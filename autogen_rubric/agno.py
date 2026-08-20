"""
autogen_rubric.agno
~~~~~~~~~~~~~~~~~~
Rubric Protocol attestation for the Agno agent framework.
"""
from __future__ import annotations
import json, os, uuid
from functools import wraps
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

class _RubricHTTP:
    def __init__(self, api_key, base_url="https://rubric-protocol.com"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
    def _headers(self):
        return {"Content-Type": "application/json", "x-api-key": self.api_key}
    def attest(self, payload, agent_id, metadata=None, source_id=None):
        if httpx is None: raise ImportError("httpx required: pip install httpx")
        resp = httpx.post(f"{self.base_url}/v1/tiered-attest",
            headers=self._headers(),
            json={"agentId": agent_id, "sourceId": source_id or f"{agent_id}-{uuid.uuid4()}",
                  "data": payload, "metadata": metadata or {}}, timeout=30)
        resp.raise_for_status()
        return resp.json()

def rubric_attest_tool(api_key, agent_id=None, base_url="https://rubric-protocol.com"):
    """Returns a plain Python function Agno registers as a Tool."""
    agent_id = agent_id or _default_agent_id("agno-agent")
    client = _RubricHTTP(api_key=api_key, base_url=base_url)
    def rubric_attest(payload: str, metadata: str = "{}") -> str:
        """
        Attest an AI decision to Rubric Protocol for EU AI Act Article 12 compliance.
        Args:
            payload: The AI decision or output text to attest.
            metadata: Optional JSON string of key-value metadata.
        """
        meta = {}
        try: meta = json.loads(metadata) if metadata else {}
        except json.JSONDecodeError: meta = {"raw": metadata}
        return json.dumps(client.attest(payload=payload, agent_id=agent_id, metadata=meta), indent=2)
    return rubric_attest

class RubricAgnoInstrumentation:
    """Auto-instruments an Agno Agent to attest every response."""
    def __init__(self, api_key=None, agent_id=None,
                 base_url="https://rubric-protocol.com", log_attestations=True):
        self.client = _RubricHTTP(api_key=api_key or os.environ["RUBRIC_API_KEY"], base_url=base_url)
        self.agent_id = agent_id or _default_agent_id("agno-agent")
        self.log = log_attestations

    def instrument(self, agent):
        for method in ("run", "print_response"):
            if hasattr(agent, method):
                self._wrap(agent, method)
        return agent

    def _wrap(self, agent, method_name):
        original = getattr(agent, method_name)
        client, agent_id, log = self.client, self.agent_id, self.log
        @wraps(original)
        def patched(*args, **kwargs):
            result = original(*args, **kwargs)
            content = _extract_content(result)
            if content:
                try:
                    r = client.attest(payload=content, agent_id=agent_id,
                                      metadata={"method": method_name, "framework": "agno"})
                    if log:
                        import sys
                        print(f"[Rubric] attested: {r.get('attestationId')}", file=sys.stderr)
                except Exception as e:
                    import sys
                    print(f"[Rubric] attestation failed: {e}", file=sys.stderr)
            return result
        setattr(agent, method_name, patched)

def _extract_content(result):
    if result is None: return None
    if isinstance(result, str): return result
    if hasattr(result, "content"):
        c = result.content
        if isinstance(c, str): return c
        if isinstance(c, list):
            parts = [item.text if hasattr(item, "text") else str(item) for item in c]
            return " ".join(parts) or None
    return None
