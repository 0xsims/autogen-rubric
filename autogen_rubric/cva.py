"""CVA: C2PA Verdict Attestation helpers (rubric-cva/0.1, Tier B).

Run Google Credentio locally, then make the verdict durable:

    from autogen_rubric.cva import build_claim, attest_claim
    claim = build_claim(verdict, asset_bytes=data, trust_list_path="anchors.pem")
    receipt = attest_claim(claim, post=my_x402_post)   # $0.05 USDC over x402

Payment is pluggable: `post(url, json_body) -> response` must handle the x402
handshake (402 challenge -> PAYMENT-SIGNATURE retry). Any x402 client works.
Optional eip191 signing upgrades the record from recorded-not-verified to
eip191-verified; requires `pip install autogen-rubric[cva-sign]`.
"""
import hashlib
import json

CVA_URL = "https://rubric-protocol.com/v1/c2pa/verdict-attest/claim"
_CODES = ("valid", "invalid", "trusted", "untrusted", "error")


def _sha3(b: bytes) -> str:
    return hashlib.sha3_256(b).hexdigest()


def _canon(o) -> str:
    """Sorted-key compact JSON. Matches the server's cva-clientsig canon()."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def build_claim(verdict: dict, *, asset_bytes: bytes = None, asset_sha3: str = None,
                asset_size: int = None, media_type: str = "application/octet-stream",
                trust_list_path: str = None, trust_list_sha3: str = None,
                trust_list_id: str = "c2pa-official+tsa",
                engine_version: str = "unknown", engine_commit: str = None) -> dict:
    """Assemble a Tier B claim from a Credentio crjson verdict (or normalized dict).

    Accepts either raw Credentio output (with `manifests`) or a pre-normalized
    {code, statusCodes} dict. Provide the asset by bytes or by sha3 hex.
    """
    if asset_bytes is not None:
        asset_sha3, asset_size = _sha3(asset_bytes), len(asset_bytes)
    if not asset_sha3 or len(asset_sha3) != 64:
        raise ValueError("asset_bytes or 64-hex asset_sha3 required")
    if trust_list_path:
        with open(trust_list_path, "rb") as f:
            trust_list_sha3 = _sha3(f.read())
    if not trust_list_sha3 or len(trust_list_sha3) != 64:
        raise ValueError("trust_list_path or 64-hex trust_list_sha3 required")

    if "manifests" in verdict:  # raw Credentio crjson
        failures = [f for m in verdict["manifests"]
                    for f in (m.get("validationResults", {}).get("failure") or [])]
        codes = [f.get("code") for f in failures]
        code = "valid" if not failures else "invalid"
    else:
        code, codes = verdict.get("code"), list(verdict.get("statusCodes", []))
    if code not in _CODES:
        raise ValueError(f"verdict code {code!r} not in {_CODES}")

    return {
        "asset": {"sha3_256": asset_sha3, "sizeBytes": asset_size, "mediaType": media_type},
        "verdict": {"code": code, "statusCodes": codes},
        "validator": {"engineVersion": engine_version,
                      **({"engineCommit": engine_commit} if engine_commit else {})},
        "trustList": {"id": trust_list_id, "sha3_256": trust_list_sha3},
        "clientSig": {"note": "unsigned"},
    }


def sign_claim(claim: dict, private_key: str) -> dict:
    """eip191-sign the claim in place. Requires eth-account (cva-sign extra)."""
    from eth_account import Account
    from eth_account.messages import encode_defunct
    body = {k: v for k, v in claim.items() if k != "clientSig"}
    acct = Account.from_key(private_key)
    sig = Account.sign_message(encode_defunct(text=_canon(body)), private_key)
    claim["clientSig"] = {"scheme": "eip191", "address": acct.address,
                          "signature": sig.signature.hex() if sig.signature.hex().startswith("0x")
                          else "0x" + sig.signature.hex()}
    return claim


def attest_claim(claim: dict, post, url: str = CVA_URL) -> dict:
    """POST the claim through an x402-capable `post(url, json_body)`; returns the receipt."""
    r = post(url, claim)
    body = r.json() if hasattr(r, "json") else r
    if not body.get("attestationId"):
        raise RuntimeError(f"CVA attest failed: {json.dumps(body)[:300]}")
    return body
