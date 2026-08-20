import os, sys
sys.path.insert(0, '/root/autogen-rubric')
from autogen_rubric import attest_before_spend, verify_spend_commitment

key = os.environ.get("RUBRIC_APA_KEY", "")
if len(key) < 40:
    print("FATAL: key missing/truncated"); sys.exit(1)

def mock_pay(params, ctx):
    print("  payment executing, attestation:", ctx["decision_attestation_id"])
    return {"txHash": "0xPY" + params["amount"].replace(".", ""), "amount": params["amount"]}

pay = attest_before_spend(mock_pay, api_key=key, agent_id="apa-py-smoke-01",
                          mandate_ref="mandate-py-smoke", rail="x402", mode="enforce")

out = pay({"to": "0x08F907a3522f0b2C392176058B0Da5a7Da92fD5e", "amount": "0.001", "asset": "USDC"},
          intent="APA python parity smoke", amount="0.001", currency="USDC",
          tool_name="mock_transfer")

print("decision:", out["decision_attestation_id"])
print("receipt :", out["receipt_attestation_id"])
commit_ok = None
if out["decision_payload_key"] and out["decision_commitment"]:
    commit_ok = verify_spend_commitment(out["decision_record"],
                                        out["decision_payload_key"],
                                        out["decision_commitment"])
    print("commitment verify (offline):", "MATCH" if commit_ok else "MISMATCH")
chain = bool(out["decision_attestation_id"] and out["receipt_attestation_id"])
print("SMOKE PASS (chain + commitment)" if chain and commit_ok else "SMOKE PARTIAL/FAIL")
sys.exit(0 if chain and commit_ok else 2)
