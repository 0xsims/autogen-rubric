"""
autogen_rubric.google_adk
~~~~~~~~~~~~~~~~~~~~~~~~~
Rubric Protocol attestation for Google ADK agents.
Two surfaces: rubric_adk_callback() to attach per-agent, or
instrument_google_adk() to auto-inject into every Agent at construction.
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

_FRAMEWORK = "google_adk"

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

class _Attester:
    def __init__(self, api_key=None, agent_id=None,
                 base_url="https://rubric-protocol.com", log_attestations=True, blocking=False):
        self.client = _RubricHTTP(api_key=api_key or os.environ["RUBRIC_API_KEY"], base_url=base_url)
        self.agent_id = agent_id or _default_agent_id("google-adk-agent")
        self.log = log_attestations
        self.blocking = blocking
    def send(self, content, meta):
        def _s():
            try:
                r = self.client.attest(payload=content, agent_id=self.agent_id, metadata=meta)
                if self.log:
                    import sys; print(f"[Rubric] attested: {r.get('attestationId')}", file=sys.stderr)
            except Exception as e:
                import sys; print(f"[Rubric] attestation failed: {e}", file=sys.stderr)
        if self.blocking: _s()
        else: threading.Thread(target=_s, daemon=True).start()

def _llm_response_text(llm_response) -> Optional[str]:
    try:
        content = getattr(llm_response, "content", None)
        parts = getattr(content, "parts", None) if content is not None else None
        if parts:
            texts = [getattr(p, "text", "") or "" for p in parts]
            joined = " ".join(t for t in texts if t).strip()
            if joined: return joined[:8000]
        return None
    except Exception:
        return None

def rubric_adk_callback(api_key=None, agent_id=None,
                        base_url="https://rubric-protocol.com", **kw):
    """Returns an after_model_callback: attach to Agent(after_model_callback=...)."""
    att = _Attester(api_key=api_key, agent_id=agent_id, base_url=base_url, **kw)
    def after_model_callback(callback_context=None, llm_response=None, **_ignored):
        try:
            text = _llm_response_text(llm_response)
            if text:
                aname = getattr(callback_context, "agent_name", None) or att.agent_id
                att.send(text, {"event": "after_model", "agent_name": str(aname), "framework": _FRAMEWORK})
        except Exception: pass
        return None  # never modify the response
    return after_model_callback

def instrument_google_adk(api_key=None, agent_id=None,
                          base_url="https://rubric-protocol.com", **kw):
    """Auto-inject the Rubric callback into every ADK Agent at construction."""
    try:
        from google.adk.agents import LlmAgent
    except ImportError:
        import sys; print("[Rubric] google-adk not installed; instrumentation skipped", file=sys.stderr)
        return None
    if getattr(LlmAgent, "_rubric_patched", False): return True
    cb = rubric_adk_callback(api_key=api_key, agent_id=agent_id, base_url=base_url, **kw)
    original_init = LlmAgent.__init__
    def patched_init(agent_self, *a, **kwargs):
        existing = kwargs.get("after_model_callback")
        if existing is None:
            kwargs["after_model_callback"] = cb
        elif isinstance(existing, list):
            kwargs["after_model_callback"] = existing + [cb]
        else:
            kwargs["after_model_callback"] = [existing, cb]
        original_init(agent_self, *a, **kwargs)
    LlmAgent.__init__ = patched_init
    LlmAgent._rubric_patched = True
    return True
