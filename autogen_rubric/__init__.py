import json
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from urllib import request

logger = logging.getLogger("rubric")

NODES = {
    "us": "https://rubric-protocol.com/verify",
    "sg": "https://sg.rubric-protocol.com/verify",
    "jp": "https://jp.rubric-protocol.com/verify",
    "ca": "https://ca.rubric-protocol.com/verify",
    "eu": "https://eu.rubric-protocol.com/verify",
}

@dataclass
class AttestationRequest:
    agent_id: str
    output: str
    leaf_type: str = "AGENT_OUTPUT"
    metadata: Optional[Dict[str, Any]] = None
    pipeline_id: Optional[str] = None
    confidence: Optional[float] = None
    risk: str = "normal"

@dataclass
class AttestationResult:
    attestation_id: str
    agent_id: str
    stage: str
    signed_at: str
    node: str
    hcs_topic: Optional[str] = None
    hcs_sequence: Optional[int] = None
    merkle_root: Optional[str] = None
    error: Optional[str] = None
    def __repr__(self):
        return f"<AttestationResult id={self.attestation_id[:8]}... stage={self.stage} node={self.node}>"

class BackgroundQueue:
    def __init__(self, flush_interval=5.0, batch_size=100, max_attempts=3, on_dead_letter=None):
        self._queue = deque()
        self._lock = threading.Lock()
        self._flush_interval = flush_interval
        self._batch_size = batch_size
        self._max_attempts = max_attempts
        self._on_dead_letter = on_dead_letter
        self._running = False
        self._thread = None
    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
    def stop(self): self._running = False
    def enqueue(self, url, body, headers):
        with self._lock:
            self._queue.append({"url":url,"body":body,"headers":headers,"attempts":0})
    def _worker(self):
        while self._running:
            time.sleep(self._flush_interval)
            self._flush()
    def _flush(self):
        batch = []
        with self._lock:
            while self._queue and len(batch) < self._batch_size:
                batch.append(self._queue.popleft())
        for item in batch:
            try:
                _http_post(item["url"],item["body"],item["headers"],timeout=10)
            except Exception as e:
                item["attempts"] += 1
                if item["attempts"] < self._max_attempts:
                    with self._lock: self._queue.appendleft(item)
                else:
                    logger.error(f"[RubricQueue] Dead letter: {item['body'].get('attestationId')} {e}")
                    if self._on_dead_letter: self._on_dead_letter(item)

def _http_post(url, body, headers, timeout=15):
    data = json.dumps(body).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))

class RubricClient:
    def __init__(self, api_key, node="us", enterprise=False, background_queue=False,
                 flush_interval=5.0, batch_size=100, timeout=15, on_dead_letter=None):
        if node not in NODES and node != "auto":
            raise ValueError(f"Invalid node '{node}'. Choose from: {list(NODES.keys())} or 'auto'")
        self.api_key = api_key
        self.node = node
        self.enterprise = enterprise
        self.timeout = timeout
        self._node_keys = list(NODES.keys())
        self._node_index = 0
        self._queue = None
        if background_queue:
            self._queue = BackgroundQueue(flush_interval=flush_interval,
                batch_size=batch_size, on_dead_letter=on_dead_letter)
            self._queue.start()

    def _endpoint(self):
        if self.node == "auto":
            key = self._node_keys[self._node_index % len(self._node_keys)]
            self._node_index += 1
            return NODES[key]
        return NODES[self.node]

    def _headers(self):
        return {"x-api-key": self.api_key, "Content-Type": "application/json"}

    def attest(self, agent_id, output, leaf_type="AGENT_OUTPUT", metadata=None,
               pipeline_id=None, confidence=None, risk="normal"):
        attestation_id = str(uuid.uuid4())
        submitted_at = datetime.now(timezone.utc).isoformat()
        endpoint = self._endpoint()
        path = "/v1/tiered-attest" if self.enterprise else "/v1/attest"
        url = endpoint + path
        data = {"attestationId":attestation_id,"agentId":agent_id,"output":output,
                "leafType":leaf_type,"submittedAt":submitted_at}
        if metadata: data["metadata"] = metadata
        if confidence is not None: data["confidence"] = confidence
        body = {"attestationId":attestation_id,"sourceId":agent_id,"data":data}
        if pipeline_id: body["pipelineId"] = pipeline_id
        headers = self._headers()
        if risk == "high" or self._queue is None:
            try:
                resp = _http_post(url, body, headers, timeout=self.timeout)
                return AttestationResult(attestation_id=attestation_id,agent_id=agent_id,
                    stage=resp.get("stage","pending"),signed_at=submitted_at,node=self.node,
                    hcs_topic=resp.get("hcsTopic"),hcs_sequence=resp.get("hcsSequenceNumber"),
                    merkle_root=resp.get("merkleRoot"))
            except Exception as e:
                logger.warning(f"[RubricClient] Attestation failed (non-fatal): {e}")
                return AttestationResult(attestation_id=attestation_id,agent_id=agent_id,
                    stage="local",signed_at=submitted_at,node=self.node,error=str(e))
        self._queue.enqueue(url, body, headers)
        return AttestationResult(attestation_id=attestation_id,agent_id=agent_id,
            stage="queued",signed_at=submitted_at,node=self.node)

    def attest_request(self, req):
        return self.attest(agent_id=req.agent_id,output=req.output,leaf_type=req.leaf_type,
            metadata=req.metadata,pipeline_id=req.pipeline_id,
            confidence=req.confidence,risk=req.risk)

    def shutdown(self):
        if self._queue: self._queue.stop()

try:
    from autogen import ConversableAgent
    class RubricAutoGenHook:
        def __init__(self, client, pipeline_id=None, events=None):
            self.client = client
            self.pipeline_id = pipeline_id
            self.events = set(events or ["message","tool"])
        def register(self, agent):
            original_receive = agent.receive
            client = self.client
            pipeline_id = self.pipeline_id
            events = self.events
            def attested_receive(message, sender, request_reply=None, silent=False):
                if "message" in events:
                    content = message if isinstance(message,str) else json.dumps(message)
                    client.attest(agent_id=f"autogen:{agent.name}",output=content[:2000],
                        leaf_type="AGENT_OUTPUT",
                        metadata={"sender":str(getattr(sender,"name","unknown")),"event":"receive"},
                        pipeline_id=pipeline_id)
                return original_receive(message,sender,request_reply,silent)
            agent.receive = attested_receive
            if hasattr(agent,"register_hook"):
                agent.register_hook("process_message_before_send",self._attest_outbound)
        def _attest_outbound(self, sender, message, recipient, silent):
            if "message" in self.events:
                content = message if isinstance(message,str) else json.dumps(message)
                self.client.attest(agent_id=f"autogen:{getattr(sender,'name','unknown')}",
                    output=content[:2000],leaf_type="AGENT_OUTPUT",
                    metadata={"recipient":str(getattr(recipient,"name","unknown")),"event":"send"},
                    pipeline_id=self.pipeline_id)
            return message
except ImportError:
    class RubricAutoGenHook:
        def __init__(self,*a,**kw):
            raise ImportError("AutoGen not installed. pip install pyautogen")

try:
    from llama_index.core.callbacks.base_handler import BaseCallbackHandler as LlamaBase
    from llama_index.core.callbacks.schema import CBEventType, EventPayload
    class RubricLlamaIndexHandler(LlamaBase):
        event_starts_to_ignore=[]
        event_ends_to_ignore=[]
        def __init__(self,client,pipeline_id=None,events=None):
            self.client=client
            self.pipeline_id=pipeline_id
            self._events=set(events or ["llm","query","agent_step"])
        def on_event_start(self,event_type,payload=None,event_id="",**kw): pass
        def on_event_end(self,event_type,payload=None,event_id="",**kw):
            if payload is None: return
            if event_type==CBEventType.LLM and "llm" in self._events:
                r=payload.get(EventPayload.RESPONSE,"")
                self.client.attest(agent_id=f"llamaindex-llm:{event_id[:8]}",
                    output=str(r)[:2000],leaf_type="AGENT_OUTPUT",
                    metadata={"event":"llm_end","event_id":event_id},pipeline_id=self.pipeline_id)
            elif event_type==CBEventType.QUERY and "query" in self._events:
                r=payload.get(EventPayload.RESPONSE,"")
                self.client.attest(agent_id=f"llamaindex-query:{event_id[:8]}",
                    output=str(r)[:2000],leaf_type="AGENT_OUTPUT",
                    metadata={"event":"query_end","event_id":event_id},pipeline_id=self.pipeline_id)
            elif event_type==CBEventType.AGENT_STEP and "agent_step" in self._events:
                self.client.attest(agent_id=f"llamaindex-agent:{event_id[:8]}",
                    output=str(payload)[:2000],leaf_type="RULE_APPLIED",
                    metadata={"event":"agent_step","event_id":event_id},pipeline_id=self.pipeline_id)
        def start_trace(self,trace_id=None): pass
        def end_trace(self,trace_id=None,trace_map=None): pass
except ImportError:
    class RubricLlamaIndexHandler:
        def __init__(self,*a,**kw):
            raise ImportError("LlamaIndex not installed. pip install llama-index")

def attest_function(client, agent_id=None, leaf_type="AGENT_OUTPUT", pipeline_id=None):
    def decorator(func):
        import functools
        @functools.wraps(func)
        def wrapper(*args,**kwargs):
            result = func(*args,**kwargs)
            output = result if isinstance(result,str) else json.dumps(result)
            client.attest(agent_id=agent_id or f"fn:{func.__name__}",
                output=output[:2000],leaf_type=leaf_type,pipeline_id=pipeline_id,
                metadata={"function":func.__name__})
            return result
        return wrapper
    return decorator



# CrewAI integration
try:
    from crewai.events import (BaseEventListener,
        AgentExecutionCompletedEvent,AgentExecutionErrorEvent,
        TaskCompletedEvent,TaskFailedEvent,
        ToolUsageFinishedEvent,ToolUsageErrorEvent,
        CrewKickoffCompletedEvent)
    class RubricCrewAIListener(BaseEventListener):
        def __init__(self,client,pipeline_id=None,events=None):
            super().__init__()
            self.client=client;self.pipeline_id=pipeline_id
            self._events=set(events or ["agent","task","tool","crew"])
        def setup_listeners(self,bus):
            c=self.client;p=self.pipeline_id;ev=self._events
            if "agent" in ev:
                @bus.on(AgentExecutionCompletedEvent)
                def _a(src,event):
                    try: c.attest(agent_id="crewai:"+str(getattr(getattr(event,"agent",None),"role","agent")),output=str(getattr(event,"output",""))[:2000],leaf_type="AGENT_OUTPUT",metadata={"event":"agent_execution_completed"},pipeline_id=p)
                    except Exception as e: logger.warning("[RubricCrewAI] "+str(e))
                @bus.on(AgentExecutionErrorEvent)
                def _ae(src,event):
                    try: c.attest(agent_id="crewai:"+str(getattr(getattr(event,"agent",None),"role","agent")),output="AGENT_ERROR:"+str(getattr(event,"error","")),leaf_type="AGENT_OUTPUT",metadata={"event":"agent_execution_error"},pipeline_id=p)
                    except Exception as e: logger.warning("[RubricCrewAI] "+str(e))
            if "task" in ev:
                @bus.on(TaskCompletedEvent)
                def _t(src,event):
                    try:
                        out=getattr(event,"output",None);raw=getattr(out,"raw",str(out)) if out else ""
                        c.attest(agent_id="crewai-task:"+str(getattr(event,"task_id","unknown")),output=str(raw)[:2000],leaf_type="AGENT_OUTPUT",metadata={"event":"task_completed"},pipeline_id=p)
                    except Exception as e: logger.warning("[RubricCrewAI] "+str(e))
                @bus.on(TaskFailedEvent)
                def _tf(src,event):
                    try: c.attest(agent_id="crewai-task:"+str(getattr(event,"task_id","unknown")),output="TASK_FAILED:"+str(getattr(event,"error","")),leaf_type="AGENT_OUTPUT",metadata={"event":"task_failed"},pipeline_id=p)
                    except Exception as e: logger.warning("[RubricCrewAI] "+str(e))
            if "tool" in ev:
                @bus.on(ToolUsageFinishedEvent)
                def _to(src,event):
                    try: c.attest(agent_id="crewai-tool:"+str(getattr(event,"tool_name","unknown")),output=str(getattr(event,"output",""))[:2000],leaf_type="EXTERNAL_ORACLE",metadata={"event":"tool_usage_finished","tool":str(getattr(event,"tool_name","unknown"))},pipeline_id=p)
                    except Exception as e: logger.warning("[RubricCrewAI] "+str(e))
                @bus.on(ToolUsageErrorEvent)
                def _toe(src,event):
                    try: c.attest(agent_id="crewai-tool:"+str(getattr(event,"tool_name","unknown")),output="TOOL_ERROR:"+str(getattr(event,"error","")),leaf_type="EXTERNAL_ORACLE",metadata={"event":"tool_usage_error"},pipeline_id=p)
                    except Exception as e: logger.warning("[RubricCrewAI] "+str(e))
            if "crew" in ev:
                @bus.on(CrewKickoffCompletedEvent)
                def _cr(src,event):
                    try: c.attest(agent_id="crewai-crew:"+str(getattr(event,"crew_name","crew")),output=str(getattr(event,"output",""))[:2000],leaf_type="PIPELINE_COMPLETE",metadata={"event":"crew_kickoff_completed"},pipeline_id=p)
                    except Exception as e: logger.warning("[RubricCrewAI] "+str(e))
except ImportError:
    class RubricCrewAIListener:
        def __init__(self,*a,**k): raise ImportError("crewai not installed. pip install crewai")

# Haystack integration
try:
    from haystack import component as _hsc
    class RubricHaystackComponent:
        def __init__(self,client,agent_id="haystack-pipeline",pipeline_id=None,leaf_type="AGENT_OUTPUT"):
            self.client=client;self.agent_id=agent_id;self.pipeline_id=pipeline_id;self.leaf_type=leaf_type
        def run(self,replies:list):
            try:
                out=str(replies[0]) if replies else ""
                self.client.attest(agent_id=self.agent_id,output=out[:2000],leaf_type=self.leaf_type,metadata={"framework":"haystack","reply_count":len(replies)},pipeline_id=self.pipeline_id)
            except Exception as e: logger.warning("[RubricHaystack] "+str(e))
            return {"replies":replies}
    RubricHaystackComponent=_hsc(_hsc.output_types(replies=list)(RubricHaystackComponent))
    def rubric_haystack_callback(client,agent_id="haystack-pipeline",pipeline_id=None):
        def cb(snapshot):
            try:
                out=json.dumps(getattr(snapshot,"pipeline_outputs",{}))[:2000]
                client.attest(agent_id=agent_id,output=out,leaf_type="AGENT_OUTPUT",metadata={"framework":"haystack","event":"pipeline_snapshot"},pipeline_id=pipeline_id)
            except Exception as e: logger.warning("[RubricHaystack] "+str(e))
            return None
        return cb
except ImportError:
    class RubricHaystackComponent:
        def __init__(self,*a,**k): raise ImportError("haystack-ai not installed. pip install haystack-ai")
    def rubric_haystack_callback(*a,**k): raise ImportError("haystack-ai not installed. pip install haystack-ai")

# Semantic Kernel integration
try:
    from semantic_kernel.filters.filter_types import FilterTypes as _SKF
    from semantic_kernel.filters.functions.function_invocation_context import FunctionInvocationContext as _SKC
    def rubric_semantic_kernel_filter(client,pipeline_id=None,events=None):
        _ev=set(events or ["function"])
        async def _f(context,next_fn):
            await next_fn(context)
            if "function" not in _ev: return
            try:
                r=context.result;out=str(getattr(r,"value",r))[:2000] if r else ""
                fn=getattr(context.function,"name","unknown");pl=getattr(context.function,"plugin_name","")
                aid=("sk:"+pl+"."+fn) if pl else ("sk:"+fn)
                client.attest(agent_id=aid,output=out,leaf_type="AGENT_OUTPUT",metadata={"framework":"semantic_kernel","function":fn,"plugin":pl},pipeline_id=pipeline_id)
            except Exception as e: logger.warning("[RubricSK] "+str(e))
        return _f
except ImportError:
    def rubric_semantic_kernel_filter(*a,**k): raise ImportError("semantic-kernel not installed. pip install semantic-kernel")

# ── Auto-Instrumentation ──────────────────────────────────────────────────────

import importlib
import functools
import os

class Instrumentation:
    def __init__(self, client, frameworks, pipeline_id=None):
        self.client = client
        self.frameworks = frameworks
        self.pipeline_id = pipeline_id
        self._patches = []

    def status(self):
        return {"instrumented": self.frameworks, "pipeline_id": self.pipeline_id}

    def shutdown(self):
        self.client.shutdown()

def instrument(
    api_key,
    pipeline_id=None,
    node="us",
    enterprise=True,
    frameworks=None,
    payload_key_dir=None,
    on_payload_key=None,
    background_queue=True,
    flush_interval=5.0,
):
    """
    Auto-instrument all detected AI frameworks with Rubric attestation.
    One line at app startup — every AI decision is attested automatically.

    Args:
        api_key: Your Rubric API key
        pipeline_id: Optional pipeline identifier for grouping decisions
        node: Rubric node to use (us, eu, sg, jp, ca, auto)
        enterprise: Use tiered enterprise path (recommended)
        frameworks: List of framework names to instrument (None = auto-detect all)
        payload_key_dir: Directory to store payload keys (default: ./rubric_keys)
        on_payload_key: Custom callback(attestation_id, payload_key) for key storage
        background_queue: Submit attestations asynchronously (recommended)
        flush_interval: Background queue flush interval in seconds
    """
    client = RubricClient(
        api_key=api_key,
        node=node,
        enterprise=enterprise,
        background_queue=background_queue,
        flush_interval=flush_interval,
    )

    # Default payload key storage to local directory
    if on_payload_key is None and enterprise:
        key_dir = payload_key_dir or os.path.join(os.getcwd(), "rubric_keys")
        os.makedirs(key_dir, exist_ok=True)
        def _default_key_store(attestation_id, payload_key):
            path = os.path.join(key_dir, f"{attestation_id}.key")
            with open(path, "w") as f:
                f.write(payload_key)
        on_payload_key = _default_key_store
        logger.info(f"[Rubric] Payload keys will be stored in: {key_dir}")

    detected = []
    to_instrument = frameworks or [
        "openai", "anthropic", "langchain", "autogen",
        "llama_index", "crewai", "haystack", "semantic_kernel",
        "google.adk", "agents", "dspy", "langgraph",
    ]

    for fw in to_instrument:
        try:
            if fw == "openai" and importlib.util.find_spec("openai"):
                _patch_openai(client, pipeline_id)
                detected.append("openai")
                logger.info("[Rubric] Instrumented: OpenAI")

            elif fw == "anthropic" and importlib.util.find_spec("anthropic"):
                _patch_anthropic(client, pipeline_id)
                detected.append("anthropic")
                logger.info("[Rubric] Instrumented: Anthropic")

            elif fw == "langchain" and importlib.util.find_spec("langchain"):
                _patch_langchain(client, pipeline_id)
                detected.append("langchain")
                logger.info("[Rubric] Instrumented: LangChain")

            elif fw == "autogen" and importlib.util.find_spec("autogen"):
                _patch_autogen(client, pipeline_id)
                detected.append("autogen")
                logger.info("[Rubric] Instrumented: AutoGen")

            elif fw == "llama_index" and importlib.util.find_spec("llama_index"):
                _patch_llamaindex(client, pipeline_id)
                detected.append("llama_index")
                logger.info("[Rubric] Instrumented: LlamaIndex")

            elif fw == "crewai" and importlib.util.find_spec("crewai"):
                _patch_crewai(client, pipeline_id)
                detected.append("crewai")
                logger.info("[Rubric] Instrumented: CrewAI")

            elif fw == "dspy" and importlib.util.find_spec("dspy"):
                _patch_dspy(client, pipeline_id)
                detected.append("dspy")
                logger.info("[Rubric] Instrumented: DSPy")

            elif fw == "langgraph" and importlib.util.find_spec("langgraph"):
                _patch_langgraph(client, pipeline_id)
                detected.append("langgraph")
                logger.info("[Rubric] Instrumented: LangGraph")

        except Exception as e:
            logger.warning(f"[Rubric] Failed to instrument {fw}: {e}")

    if not detected:
        logger.warning("[Rubric] No supported AI frameworks detected. Install one of: openai, anthropic, langchain, crewai, llama-index")

    logger.info(f"[Rubric] Auto-instrumentation complete. Frameworks: {detected}")
    return Instrumentation(client, detected, pipeline_id)


# ── Framework Patches ─────────────────────────────────────────────────────────

_patched = set()

def _patch_openai(client, pipeline_id):
    if "openai" in _patched: return
    import openai
    from openai.resources.chat.completions import Completions

    _orig_create = Completions.create

    @functools.wraps(_orig_create)
    def _patched_create(self_inner, *args, **kwargs):
        response = _orig_create(self_inner, *args, **kwargs)
        try:
            content = response.choices[0].message.content or ""
            model = getattr(response, "model", "unknown") or "unknown"
            client.attest(
                agent_id=f"openai:{model}",
                output=content[:2000],
                leaf_type="AGENT_OUTPUT",
                metadata={"framework": "openai", "model": model,
                          "usage": dict(response.usage) if response.usage else {}},
                pipeline_id=pipeline_id,
            )
        except Exception as e:
            logger.warning(f"[Rubric/OpenAI] {e}")
        return response

    Completions.create = _patched_create

    # Async patch
    try:
        from openai.resources.chat.completions import AsyncCompletions
        _orig_acreate = AsyncCompletions.create
        @functools.wraps(_orig_acreate)
        async def _patched_acreate(self_inner, *args, **kwargs):
            response = await _orig_acreate(self_inner, *args, **kwargs)
            try:
                content = response.choices[0].message.content or ""
                model = getattr(response, "model", "unknown") or "unknown"
                client.attest(agent_id=f"openai:{model}", output=content[:2000],
                    leaf_type="AGENT_OUTPUT",
                    metadata={"framework": "openai", "model": model},
                    pipeline_id=pipeline_id)
            except Exception as e:
                logger.warning(f"[Rubric/OpenAI async] {e}")
            return response
        AsyncCompletions.create = _patched_acreate
    except Exception: pass

    _patched.add("openai")


def _patch_anthropic(client, pipeline_id):
    if "anthropic" in _patched: return
    try:
        from anthropic.resources.messages import Messages
        _orig = Messages.create
        @functools.wraps(_orig)
        def _patched_create(self_inner, *args, **kwargs):
            response = _orig(self_inner, *args, **kwargs)
            try:
                text = response.content[0].text if response.content else ""
                model = getattr(response, "model", "unknown") or "unknown"
                client.attest(agent_id=f"anthropic:{model}", output=text[:2000],
                    leaf_type="AGENT_OUTPUT",
                    metadata={"framework": "anthropic", "model": model},
                    pipeline_id=pipeline_id)
            except Exception as e:
                logger.warning(f"[Rubric/Anthropic] {e}")
            return response
        Messages.create = _patched_create
        _patched.add("anthropic")
    except Exception as e:
        logger.warning(f"[Rubric/Anthropic patch] {e}")


def _patch_langchain(client, pipeline_id):
    if "langchain" in _patched: return
    try:
        from langchain.callbacks.manager import CallbackManager
        from langchain.callbacks.base import BaseCallbackHandler

        class _RubricLCHandler(BaseCallbackHandler):
            def on_llm_end(self, response, **kwargs):
                try:
                    gen = response.generations
                    text = gen[0][0].text if gen and gen[0] else ""
                    client.attest(agent_id="langchain:llm", output=text[:2000],
                        leaf_type="AGENT_OUTPUT",
                        metadata={"framework": "langchain", "event": "llm_end"},
                        pipeline_id=pipeline_id)
                except Exception as e:
                    logger.warning(f"[Rubric/LangChain] {e}")

            def on_agent_finish(self, finish, **kwargs):
                try:
                    output = finish.return_values.get("output", "") if hasattr(finish, "return_values") else str(finish)
                    client.attest(agent_id="langchain:agent", output=str(output)[:2000],
                        leaf_type="AGENT_OUTPUT",
                        metadata={"framework": "langchain", "event": "agent_finish"},
                        pipeline_id=pipeline_id)
                except Exception as e:
                    logger.warning(f"[Rubric/LangChain] {e}")

        _handler = _RubricLCHandler()
        _orig_init = CallbackManager.__init__
        @functools.wraps(_orig_init)
        def _patched_init(self_inner, *args, **kwargs):
            _orig_init(self_inner, *args, **kwargs)
            if _handler not in self_inner.handlers:
                self_inner.add_handler(_handler)
        CallbackManager.__init__ = _patched_init
        _patched.add("langchain")
    except Exception as e:
        logger.warning(f"[Rubric/LangChain patch] {e}")


def _patch_autogen(client, pipeline_id):
    if "autogen" in _patched: return
    try:
        from autogen import ConversableAgent
        _orig_receive = ConversableAgent.receive
        @functools.wraps(_orig_receive)
        def _patched_receive(self_inner, message, sender, *args, **kwargs):
            try:
                content = message if isinstance(message, str) else json.dumps(message)
                client.attest(agent_id=f"autogen:{self_inner.name}",
                    output=content[:2000], leaf_type="AGENT_OUTPUT",
                    metadata={"framework": "autogen",
                              "sender": getattr(sender, "name", "unknown")},
                    pipeline_id=pipeline_id)
            except Exception as e:
                logger.warning(f"[Rubric/AutoGen] {e}")
            return _orig_receive(self_inner, message, sender, *args, **kwargs)
        ConversableAgent.receive = _patched_receive
        _patched.add("autogen")
    except Exception as e:
        logger.warning(f"[Rubric/AutoGen patch] {e}")


def _patch_llamaindex(client, pipeline_id):
    if "llama_index" in _patched: return
    try:
        from llama_index.core import Settings
        handler = RubricLlamaIndexHandler(client=client, pipeline_id=pipeline_id)
        if not hasattr(Settings, "callback_manager") or Settings.callback_manager is None:
            from llama_index.core.callbacks import CallbackManager
            Settings.callback_manager = CallbackManager([handler])
        else:
            Settings.callback_manager.add_handler(handler)
        _patched.add("llama_index")
    except Exception as e:
        logger.warning(f"[Rubric/LlamaIndex patch] {e}")


def _patch_crewai(client, pipeline_id):
    if "crewai" in _patched: return
    try:
        listener = RubricCrewAIListener(client=client, pipeline_id=pipeline_id)
        listener.activate()
        _patched.add("crewai")
    except Exception as e:
        logger.warning(f"[Rubric/CrewAI patch] {e}")


def _patch_dspy(client, pipeline_id):
    if "dspy" in _patched: return
    try:
        import dspy
        _orig_forward = dspy.Predict.forward if hasattr(dspy, "Predict") else None
        if not _orig_forward: return
        @functools.wraps(_orig_forward)
        def _patched_forward(self_inner, *args, **kwargs):
            result = _orig_forward(self_inner, *args, **kwargs)
            try:
                output = str(result)[:2000]
                client.attest(agent_id=f"dspy:{self_inner.__class__.__name__}",
                    output=output, leaf_type="AGENT_OUTPUT",
                    metadata={"framework": "dspy"}, pipeline_id=pipeline_id)
            except Exception as e:
                logger.warning(f"[Rubric/DSPy] {e}")
            return result
        dspy.Predict.forward = _patched_forward
        _patched.add("dspy")
    except Exception as e:
        logger.warning(f"[Rubric/DSPy patch] {e}")


def _patch_langgraph(client, pipeline_id):
    if "langgraph" in _patched: return
    try:
        from langgraph.graph import StateGraph
        _orig_compile = StateGraph.compile
        @functools.wraps(_orig_compile)
        def _patched_compile(self_inner, *args, **kwargs):
            graph = _orig_compile(self_inner, *args, **kwargs)
            _orig_invoke = graph.invoke
            @functools.wraps(_orig_invoke)
            def _patched_invoke(state, *a, **kw):
                result = _orig_invoke(state, *a, **kw)
                try:
                    client.attest(agent_id="langgraph:graph",
                        output=str(result)[:2000], leaf_type="AGENT_OUTPUT",
                        metadata={"framework": "langgraph", "event": "graph_invoke"},
                        pipeline_id=pipeline_id)
                except Exception as e:
                    logger.warning(f"[Rubric/LangGraph] {e}")
                return result
            graph.invoke = _patched_invoke
            return graph
        StateGraph.compile = _patched_compile
        _patched.add("langgraph")
    except Exception as e:
        logger.warning(f"[Rubric/LangGraph patch] {e}")

__all__ = [
    "RubricClient","AttestationRequest","AttestationResult",
    "RubricAutoGenHook","RubricLlamaIndexHandler","RubricCrewAIListener",
    "RubricHaystackComponent","rubric_haystack_callback",
    "rubric_semantic_kernel_filter","attest_function",
    "instrument","Instrumentation",
]
__version__ = "1.5.2"
