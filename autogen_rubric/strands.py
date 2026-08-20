"""
autogen_rubric.strands
~~~~~~~~~~~~~~~~~~~~~~
Rubric Protocol attestation for Strands Agents (Bedrock AgentCore).
Registers a HookProvider: every completed agent invocation is attested.
"""
from __future__ import annotations
import os, threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

def _default_agent_id(base):
    """Stable per-host default so unconfigured users don't share one global bucket."""
    import hashlib, socket
    try:
        h = hashlib.sha256(socket.gethostname().encode()).hexdigest()[:8]
    except Exception:
        h = "local"
    return f"{base}-{h}"


try:
    import httpx
except ImportError:
    httpx = None

_FRAMEWORK = "strands"

class _RubricHTTP:
    def __init__(self, api_key, base_url="https://rubric-protocol.com"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
    def attest(self, payload, agent_id, metadata=None, source_id=None):
        if httpx is None: raise ImportError("httpx required: pip install httpx")
        data = {"output": payload, "leafType": "AGENT_OUTPUT", "framework": _FRAMEWORK,
                "submittedAt": datetime.now(timezone.utc).isoformat()}
        resp = httpx.post(f"{self.base_url}/v1/tiered-attest",
            headers={"Content-Type": "application/json", "x-api-key": self.api_key},
            json={"agentId": agent_id, "sourceId": source_id or f"{agent_id}-{uuid.uuid4()}",
                  "data": data, "metadata": metadata or {}}, timeout=30)
        resp.raise_for_status()
        return resp.json()

def _agent_result_text(agent) -> Optional[str]:
    try:
        msgs = getattr(agent, "messages", None)
        if msgs:
            last = msgs[-1]
            content = last.get("content") if isinstance(last, dict) else getattr(last, "content", None)
            if isinstance(content, list):
                texts = []
                for block in content:
                    t = block.get("text") if isinstance(block, dict) else getattr(block, "text", None)
                    if t: texts.append(t)
                if texts: return " ".join(texts)[:8000]
            elif isinstance(content, str):
                return content[:8000]
        return None
    except Exception:
        return None

class RubricStrandsHooks:
    """Strands HookProvider: attests after each agent invocation completes."""
    def __init__(self, api_key=None, agent_id=None,
                 base_url="https://rubric-protocol.com", log_attestations=True, blocking=False):
        self.client = _RubricHTTP(api_key=api_key or os.environ["RUBRIC_API_KEY"], base_url=base_url)
        self.agent_id = agent_id or _default_agent_id("strands-agent")
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

    def register_hooks(self, registry, **kwargs) -> None:
        try:
            from strands.hooks import AfterInvocationEvent
        except ImportError:
            return
        registry.add_callback(AfterInvocationEvent, self._on_after_invocation)

    def _on_after_invocation(self, event) -> None:
        try:
            agent = getattr(event, "agent", None)
            text = _agent_result_text(agent) or "agent invocation complete"
            aname = getattr(agent, "name", None) or self.agent_id
            self._attest(text, {"event": "after_invocation", "agent_name": str(aname),
                                "framework": _FRAMEWORK})
        except Exception:
            pass

def instrument_strands(api_key=None, agent_id=None,
                       base_url="https://rubric-protocol.com", **kw):
    """Returns a RubricStrandsHooks provider: Agent(hooks=[provider])."""
    return RubricStrandsHooks(api_key=api_key, agent_id=agent_id, base_url=base_url, **kw)
