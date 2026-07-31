import hashlib, json, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, '/root/autogen-rubric')
from autogen_rubric._canonical import canonicalize
from autogen_rubric._apa import (attest_before_spend, verify_spend_commitment,
                                 AttestationGateError)

fails = []
def ok(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond: fails.append(name)

# 1. canonicalization vectors
ok("vector sort", canonicalize({"b":1,"a":2}) == '{"a":2,"b":1}')
ok("vector unicode", canonicalize({"s":"héllo"}) == '{"s":"héllo"}')
ok("vector array order", canonicalize({"arr":[3,1,2]}) == '{"arr":[3,1,2]}')
ok("vector literals", canonicalize({"n":None,"t":True,"f":False}) == '{"f":false,"n":null,"t":true}')

# 2. commitment
key = "a"*64
rec = {"schema":"rubric/apa-v1","amount":"0.001","intent":"test"}
salt = hashlib.sha256((key+":rubric-commit-v1").encode()).hexdigest()
commit = hashlib.sha256((salt+canonicalize(rec)).encode()).hexdigest()
ok("commitment honest", verify_spend_commitment(rec, key, commit) is True)
ok("commitment tampered", verify_spend_commitment({**rec,"amount":"9"}, key, commit) is False)
ok("commitment added field", verify_spend_commitment({**rec,"x":1}, key, commit) is False)
ok("commitment wrong key", verify_spend_commitment(rec, "b"*64, commit) is False)

# 3. gate against mock servers
def serve(code, payload):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(code)
            self.send_header("Content-Type","application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())
        def log_message(self, *a): pass
    s = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, "http://127.0.0.1:%d" % s.server_address[1]

state = {"executed": False}
def payfn(p, ctx):
    state["executed"] = True
    return {"txHash":"0x1"}

s, url = serve(401, {"error":"nope"})
state["executed"] = False
try:
    attest_before_spend(payfn, api_key="k", agent_id="a", base_url=url, mode="enforce")({"x":1})
    ok("enforce blocks on 401", False)
except AttestationGateError:
    ok("enforce blocks on 401", True)
ok("payment not executed on reject", state["executed"] is False)
s.shutdown()

s, url = serve(200, {"ok":True})
state["executed"] = False
try:
    attest_before_spend(payfn, api_key="k", agent_id="a", base_url=url, mode="enforce")({"x":1})
    ok("enforce blocks when no server ID", False)
except AttestationGateError:
    ok("enforce blocks when no server ID", True)
ok("payment not executed without ID", state["executed"] is False)
s.shutdown()

s, url = serve(200, {"attestationId":"srv-123","payloadKey":key,"payloadCommitment":"x"})
state["executed"] = False
out = attest_before_spend(payfn, api_key="k", agent_id="a", base_url=url, mode="enforce")({"x":1})
ok("payment executes on accept", state["executed"] is True)
ok("server ID used, not local", out["decision_attestation_id"] == "srv-123")
ok("decision record returned", out["decision_record"]["schema"] == "rubric/apa-v1")
s.shutdown()

print("\nAPA OFFLINE CONFORMANCE (python): " + ("PASS" if not fails else "%d FAILURE(S)" % len(fails)))
sys.exit(0 if not fails else 1)
