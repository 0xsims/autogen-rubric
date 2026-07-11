"""
autogen_rubric.pydantic_ai
~~~~~~~~~~~~~~~~~~~~~~~~~~
Rubric Protocol attestation for Pydantic AI agents.
Wraps Agent.run_sync / Agent.run at class level: every agent result is attested.
"""
from __future__ import annotations
import os, threading
from datetime import datetime, timezone
from functools import wraps
from typing import Optional

try:
    import httpx
except ImportError:
    httpx = None

_FRAMEWORK = "pydantic_ai"

class _RubricHTTP:
    def __init__(self, api_key, base_url="https://rubric-protocol.com"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
    def attest(self, payload, agent_id, metadata=None):
        if httpx is None: raise ImportError("httpx required: pip install httpx")
        data = {"output": payload, "leafType": "AGENT_OUTPUT", "framework": _FRAMEWORK,
                "submittedAt": datetime.now(timezone.utc).isoformat()}
        resp = httpx.post(f"{self.base_url}/v1/tiered-attest",
            headers={"Content-Type": "application/json", "x-api-key": self.api_key},
            json={"agentId": agent_id, "sourceId": agent_id,
                  "data": data, "metadata": metadata or {}}, timeout=30)
        resp.raise_for_status()
        return resp.json()

def _extract(result) -> Optional[str]:
    if result is None: return None
    for attr in ("output", "data"):          # pydantic-ai >=0.0.x renamed data -> output
        v = getattr(result, attr, None)
        if v is not None:
            return v if isinstance(v, str) else str(v)
    return str(result)[:8000]

class RubricPydanticAIInstrumentation:
    def __init__(self, api_key=None, agent_id="pydantic-ai-agent",
                 base_url="https://rubric-protocol.com", log_attestations=True,
                 blocking=False):
        self.client = _RubricHTTP(api_key=api_key or os.environ["RUBRIC_API_KEY"], base_url=base_url)
        self.agent_id = agent_id
        self.log = log_attestations
        self.blocking = blocking

    def _attest(self, content, meta):
        def _send():
            try:
                r = self.client.attest(payload=content, agent_id=self.agent_id, metadata=meta)
                if self.log:
                    import sys; print(f"[Rubric] attested: {r.get('attestationId')}", file=sys.stderr)
            except Exception as e:
                import sys; print(f"[Rubric] attestation failed: {e}", file=sys.stderr)
        if self.blocking: _send()
        else: threading.Thread(target=_send, daemon=True).start()

    def instrument(self):
        try:
            from pydantic_ai import Agent
        except ImportError:
            import sys; print("[Rubric] pydantic_ai not installed; instrumentation skipped", file=sys.stderr)
            return False
        inst = self
        if hasattr(Agent, "run") and not getattr(Agent.run, "_rubric_patched", False):
            orig_run = Agent.run
            @wraps(orig_run)
            async def patched_run(agent_self, *a, **kw):
                result = await orig_run(agent_self, *a, **kw)
                c = _extract(result)
                if c: inst._attest(c, {"method": "Agent.run", "framework": _FRAMEWORK})
                return result
            patched_run._rubric_patched = True
            Agent.run = patched_run
        return True

def instrument_pydantic_ai(api_key=None, agent_id="pydantic-ai-agent",
                           base_url="https://rubric-protocol.com", **kw):
    inst = RubricPydanticAIInstrumentation(api_key=api_key, agent_id=agent_id, base_url=base_url, **kw)
    inst.instrument()
    return inst
