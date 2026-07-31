"""
Agent Payment Attestation middleware (rubric/apa-v1).

Wraps a payment callable: attest the decision, wait for server
acknowledgement, execute the payment, attest the receipt.

Conformance note: this module deliberately does NOT use RubricClient.attest(),
which queues by default and returns a client-minted id on failure. Profile
section 8 requires a server-assigned id before the payment executes.
"""
import hashlib
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from autogen_rubric._canonical import canonicalize

_METADATA_EXCLUDE = {"params"}

DEFAULT_BASE_URL = "https://rubric-protocol.com/verify"
COMMIT_DOMAIN = ":rubric-commit-v1"


class AttestationGateError(Exception):
    """Raised in enforce mode when the decision could not be attested."""


def _prune(d):
    return {k: v for k, v in d.items() if v is not None}


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def verify_spend_commitment(record, payload_key, expected_commitment):
    """Recompute the server's salted commitment from a retained record."""
    salt = hashlib.sha256((payload_key + COMMIT_DOMAIN).encode()).hexdigest()
    computed = hashlib.sha256((salt + canonicalize(record)).encode()).hexdigest()
    return computed == expected_commitment


def _post_attestation(api_key, base_url, agent_id, source_id, decision,
                      leaf_type, record, timeout=15):
    url = base_url.rstrip("/") + "/v1/tiered-attest"
    body = {
        "agentId": agent_id,
        "sourceId": source_id,
        "decision": decision,
        "data": record,
        "output": canonicalize(record),
        "leafType": leaf_type,
        # Metadata is indexed in cleartext; params rides the encrypted payload
        # instead. paramsHash carries the commitment for disclosure-free proof.
        "metadata": {k: str(v) for k, v in record.items()
                     if k not in _METADATA_EXCLUDE and not isinstance(v, (dict, list))},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "x-api-key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            parsed = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:200]
        raise AttestationGateError("tiered-attest %s: %s" % (e.code, detail))
    except Exception as e:
        raise AttestationGateError("tiered-attest transport failure: %s" % e)

    att_id = parsed.get("attestationId") or parsed.get("id")
    if not att_id:
        raise AttestationGateError("no server attestation ID in response")
    return {
        "id": att_id,
        "payload_key": parsed.get("payloadKey"),
        "payload_commitment": parsed.get("payloadCommitment"),
    }


def attest_before_spend(payment_fn, api_key, agent_id, mandate_ref=None,
                        rail="unspecified", base_url=DEFAULT_BASE_URL,
                        mode="enforce", attest_receipt=True, timeout=15):
    """
    Wrap a payment callable with APA attestation.

    payment_fn(params, ctx) -> result
      ctx = {"decision_attestation_id": str, "params_hash": str}

    Returns a callable (params, **meta) -> dict with the result, the retained
    records, and the commitment material needed for offline verification.
    """
    source_id = mandate_ref or agent_id

    def wrapped(params, intent="unspecified", payee=None, amount=None,
                currency=None, tool_name=None):
        params_hash = hashlib.sha3_256(canonicalize(params).encode()).hexdigest()
        record = _prune({
            "schema": "rubric/apa-v1",
            "agentId": agent_id,
            "mandateRef": mandate_ref,
            "intent": intent,
            "rail": rail,
            "payee": payee,
            "amount": amount,
            "currency": currency,
            "toolName": tool_name,
            "paramsHash": params_hash,
            # The parameters themselves, encrypted at rest under a per-attestation
            # key Rubric returns and does not retain. paramsHash stays the public
            # commitment for disclosure-free proof.
            "params": params,
            "timestamp": _now(),
        })

        attestation_error = None
        payload_key = None
        commitment = None
        try:
            ack = _post_attestation(api_key, base_url, agent_id, source_id,
                                    intent, "AGENT_SPEND_DECISION", record,
                                    timeout)
            decision_id = ack["id"]
            payload_key = ack["payload_key"]
            commitment = ack["payload_commitment"]
        except AttestationGateError as e:
            if mode == "enforce":
                raise AttestationGateError(
                    "spend blocked, decision attestation failed: %s" % e)
            attestation_error = str(e)
            decision_id = "unattested:" + params_hash[:16]

        ctx = {"decision_attestation_id": decision_id, "params_hash": params_hash}
        attested = not decision_id.startswith("unattested:")

        try:
            result = payment_fn(params, ctx)
        except Exception:
            if attest_receipt and attested:
                _safe_receipt(api_key, base_url, agent_id, source_id,
                              decision_id, "failed", None, timeout)
            raise

        receipt_id = None
        receipt_record = None
        if attest_receipt and attested:
            tx_ref = None
            if isinstance(result, dict):
                tx_ref = result.get("txHash") or result.get("transaction_hash") or result.get("txRef")
            receipt_id, receipt_record = _safe_receipt(
                api_key, base_url, agent_id, source_id, decision_id,
                "settled", tx_ref, timeout)

        return {
            "result": result,
            "decision_record": record,
            "decision_canonical": canonicalize(record),
            "decision_attestation_id": decision_id,
            "decision_payload_key": payload_key,
            "decision_commitment": commitment,
            "receipt_record": receipt_record,
            "receipt_attestation_id": receipt_id,
            "attestation_error": attestation_error,
        }

    return wrapped


def _safe_receipt(api_key, base_url, agent_id, source_id, decision_id,
                  status, tx_ref, timeout):
    receipt = _prune({
        "schema": "rubric/apa-receipt-v1",
        "decisionAttestationId": decision_id,
        "txRef": tx_ref,
        "status": status,
        "timestamp": _now(),
    })
    try:
        ack = _post_attestation(api_key, base_url, agent_id, source_id,
                                "agent_spend_receipt", "AGENT_SPEND_RECEIPT",
                                receipt, timeout)
        return ack["id"], receipt
    except AttestationGateError:
        return None, receipt
