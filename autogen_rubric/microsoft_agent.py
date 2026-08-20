"""
autogen_rubric.microsoft_agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rubric attestation for Azure AI Agents + Semantic Kernel.
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

def rubric_function_tool(api_key, agent_id=None, base_url="https://rubric-protocol.com"):
    """Returns an azure-ai-agents FunctionTool for Rubric attestation."""
    agent_id = agent_id or _default_agent_id("azure-agent")
    try:
        from azure.ai.agents.models import FunctionTool
    except ImportError as e:
        raise ImportError("azure-ai-agents required: pip install azure-ai-agents") from e
    client = _RubricHTTP(api_key=api_key, base_url=base_url)
    def rubric_attest(payload: str, metadata: str = "{}") -> str:
        """
        Attest an AI decision to Rubric Protocol for EU AI Act Article 12 compliance.
        :param payload: The AI decision or output text to attest.
        :param metadata: Optional JSON string of key-value metadata.
        :return: JSON with attestationId, sequenceNumber, timestamp.
        """
        meta = {}
        try: meta = json.loads(metadata) if metadata else {}
        except json.JSONDecodeError: pass
        return json.dumps(client.attest(payload=payload, agent_id=agent_id,
                                        metadata={"framework": "azure-ai-agents", **meta}))
    def rubric_verify(attestation_id: str) -> str:
        """Verify a prior Rubric attestation. :param attestation_id: The attestationId."""
        if httpx is None: raise ImportError("httpx required")
        resp = httpx.post(f"{client.base_url}/v1/verify",
            headers=client._headers(), json={"attestationId": attestation_id}, timeout=30)
        resp.raise_for_status()
        return json.dumps(resp.json())
    return FunctionTool(functions={rubric_attest, rubric_verify})

class RubricAgentRunHook:
    """Wraps AgentsClient.runs.create_and_process to auto-attest completed runs."""
    def __init__(self, api_key=None, agent_id=None,
                 base_url="https://rubric-protocol.com", log_attestations=True):
        self.rubric = _RubricHTTP(api_key=api_key or os.environ["RUBRIC_API_KEY"], base_url=base_url)
        self.agent_id = agent_id or _default_agent_id("azure-agent")
        self.log = log_attestations

    def instrument(self, client):
        runs, rubric, agent_id, log = client.runs, self.rubric, self.agent_id, self.log
        original = runs.create_and_process
        @wraps(original)
        def patched(*args, **kwargs):
            run = original(*args, **kwargs)
            try:
                msgs = client.messages.list(thread_id=run.thread_id)
                text = _last_assistant_text(msgs)
                if text:
                    r = rubric.attest(payload=text, agent_id=agent_id,
                        metadata={"runId": run.id, "framework": "azure-ai-agents",
                                  "status": str(run.status)})
                    if log:
                        import sys
                        print(f"[Rubric] attested run {run.id}: {r.get('attestationId')}", file=sys.stderr)
            except Exception as e:
                import sys
                print(f"[Rubric] attestation failed: {e}", file=sys.stderr)
            return run
        runs.create_and_process = patched
        return client

def _last_assistant_text(messages):
    try:
        for msg in list(messages):
            if getattr(msg, "role", None) == "assistant":
                content = getattr(msg, "content", None)
                if isinstance(content, list):
                    for block in content:
                        if hasattr(block, "text"):
                            t = block.text
                            return t.value if hasattr(t, "value") else str(t)
                elif isinstance(content, str):
                    return content
    except Exception:
        pass
    return None

def get_sk_rubric_plugin(api_key, agent_id="sk-agent", base_url="https://rubric-protocol.com"):
    """Returns a Semantic Kernel native plugin with RubricAttest and RubricVerify."""
    try:
        from semantic_kernel.functions import kernel_function
    except ImportError as e:
        raise ImportError("semantic-kernel required: pip install semantic-kernel") from e
    rubric = _RubricHTTP(api_key=api_key, base_url=base_url)
    class RubricPlugin:
        @kernel_function(name="RubricAttest",
            description="Attest an AI decision to Rubric Protocol for EU AI Act Article 12 compliance.")
        def attest(self, payload: str, metadata: str = "{}") -> str:
            meta = {}
            try: meta = json.loads(metadata) if metadata else {}
            except json.JSONDecodeError: pass
            return json.dumps(rubric.attest(payload=payload, agent_id=agent_id,
                                            metadata={"framework": "semantic-kernel", **meta}))
        @kernel_function(name="RubricVerify", description="Verify a Rubric attestation by ID.")
        def verify(self, attestation_id: str) -> str:
            if httpx is None: raise ImportError("httpx required")
            resp = httpx.post(f"{rubric.base_url}/v1/verify",
                headers=rubric._headers(), json={"attestationId": attestation_id}, timeout=30)
            resp.raise_for_status()
            return json.dumps(resp.json())
    return RubricPlugin()
