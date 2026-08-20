"""
autogen_rubric.openai_agents
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rubric Protocol attestation for the OpenAI Agents SDK (`agents` package).
Registers a TracingProcessor: every completed trace (agent workflow) is attested.
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

_FRAMEWORK = "openai_agents"

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

class RubricTracingProcessor:
    """OpenAI Agents SDK TracingProcessor: attests each finished trace and
    each finished generation/agent span's terminal output."""
    def __init__(self, api_key=None, agent_id=None,
                 base_url="https://rubric-protocol.com", log_attestations=True,
                 blocking=False, span_level=False):
        self.client = _RubricHTTP(api_key=api_key or os.environ["RUBRIC_API_KEY"], base_url=base_url)
        self.agent_id = agent_id or _default_agent_id("openai-agents")
        self.log = log_attestations
        self.blocking = blocking
        self.span_level = span_level

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

    # --- TracingProcessor interface (all hooks total; never raise) ---
    def on_trace_start(self, trace) -> None: pass
    def on_span_start(self, span) -> None: pass
    def on_span_end(self, span) -> None:
        if not self.span_level: return
        try:
            sd = getattr(span, "span_data", None)
            out = getattr(sd, "output", None) if sd is not None else None
            if out:
                self._attest(str(out)[:8000], {"event": "span_end",
                    "span_type": type(sd).__name__ if sd else "unknown", "framework": _FRAMEWORK})
        except Exception: pass
    def on_trace_end(self, trace) -> None:
        try:
            name = getattr(trace, "name", "workflow")
            tid = getattr(trace, "trace_id", "")
            self._attest(f"trace complete: {name}", {"event": "trace_end",
                "trace_id": str(tid), "workflow": str(name), "framework": _FRAMEWORK})
        except Exception: pass
    def shutdown(self) -> None: pass
    def force_flush(self) -> None: pass

def instrument_openai_agents(api_key=None, agent_id=None,
                             base_url="https://rubric-protocol.com", replace=False, **kw):
    """Register the Rubric processor with the Agents SDK tracing pipeline.
    replace=False adds alongside existing processors (OpenAI's exporter stays)."""
    try:
        from agents.tracing import add_trace_processor, set_trace_processors
    except ImportError:
        import sys; print("[Rubric] openai-agents not installed; instrumentation skipped", file=sys.stderr)
        return None
    proc = RubricTracingProcessor(api_key=api_key, agent_id=agent_id, base_url=base_url, **kw)
    if replace: set_trace_processors([proc])
    else: add_trace_processor(proc)
    return proc
