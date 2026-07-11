"""Live smoke tests: drive each framework's real dispatch and attest against
production's tiered lane. Gated on RUBRIC_CI_KEY — skipped entirely without it,
so forks and keyless local runs stay green. No paid LLM calls."""
import importlib.util, os, sys
import pytest

KEY = os.environ.get("RUBRIC_CI_KEY")
pytestmark = pytest.mark.skipif(not KEY, reason="RUBRIC_CI_KEY not set")

def _has(mod): return importlib.util.find_spec(mod) is not None

def _assert_attested(capfd):
    err = capfd.readouterr().err
    assert "[Rubric] attested:" in err, f"no attestation in stderr: {err[-300:]}"

@pytest.mark.skipif(not _has("pydantic_ai"), reason="pydantic_ai not installed")
def test_pydantic_ai_live(capfd):
    from autogen_rubric.pydantic_ai import instrument_pydantic_ai
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel
    instrument_pydantic_ai(api_key=KEY, blocking=True, agent_id="ci-pydantic-ai")
    Agent(TestModel()).run_sync("ci live smoke")
    _assert_attested(capfd)

@pytest.mark.skipif(not _has("agents"), reason="openai-agents not installed")
def test_openai_agents_live(capfd):
    from autogen_rubric.openai_agents import instrument_openai_agents
    instrument_openai_agents(api_key=KEY, blocking=True, agent_id="ci-openai-agents", replace=True)
    from agents.tracing import trace
    with trace("ci-live-smoke"):
        pass
    _assert_attested(capfd)

@pytest.mark.skipif(not _has("google.adk"), reason="google-adk not installed")
def test_google_adk_live(capfd):
    from autogen_rubric.google_adk import rubric_adk_callback
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types
    cb = rubric_adk_callback(api_key=KEY, blocking=True, agent_id="ci-google-adk")
    cb(callback_context=None, llm_response=LlmResponse(content=types.Content(
        role="model", parts=[types.Part(text="ci live smoke output")])))
    _assert_attested(capfd)

@pytest.mark.skipif(not _has("strands"), reason="strands-agents not installed")
def test_strands_live(capfd):
    from strands.hooks import HookRegistry, AfterInvocationEvent
    from autogen_rubric.strands import instrument_strands
    class A:
        name = "ci-strands"
        messages = [{"role": "assistant", "content": [{"text": "ci live smoke"}]}]
    reg = HookRegistry()
    reg.add_hook(instrument_strands(api_key=KEY, blocking=True, agent_id="ci-strands"))
    reg.invoke_callbacks(AfterInvocationEvent(agent=A()))
    _assert_attested(capfd)

@pytest.mark.skipif(not _has("haystack"), reason="haystack-ai not installed")
def test_haystack_live(caplog):
    import logging
    import autogen_rubric as rubric
    from haystack import Pipeline, component
    @component
    class Upper:
        @component.output_types(text=str)
        def run(self, text: str):
            return {"text": text.upper()}
    client = rubric.RubricClient(api_key=KEY, enterprise=False, background_queue=False)
    p = Pipeline()
    p.add_component("u", Upper())
    p.add_component("rubric", rubric.RubricHaystackComponent(client, agent_id="ci-haystack"))
    with caplog.at_level(logging.WARNING):
        out = p.run({"u": {"text": "x"}, "rubric": {"replies": ["ci live smoke"]}})
    assert out["u"]["text"] == "X"
    assert not any("RubricHaystack" in r.message for r in caplog.records), caplog.text

@pytest.mark.skipif(not _has("semantic_kernel"), reason="semantic-kernel not installed")
def test_semantic_kernel_live(caplog):
    import asyncio, logging
    import autogen_rubric as rubric
    from semantic_kernel import Kernel
    from semantic_kernel.functions import kernel_function
    from semantic_kernel.filters.filter_types import FilterTypes
    class M:
        @kernel_function(name="double", description="doubles")
        def double(self, n: str) -> str:
            return str(int(n) * 2)
    async def main():
        client = rubric.RubricClient(api_key=KEY, enterprise=False, background_queue=False)
        k = Kernel()
        k.add_filter(FilterTypes.FUNCTION_INVOCATION, rubric.rubric_semantic_kernel_filter(client))
        k.add_plugin(M(), plugin_name="m")
        return await k.invoke(plugin_name="m", function_name="double", n="21")
    with caplog.at_level(logging.WARNING):
        result = asyncio.run(main())
    assert str(result) == "42"
    assert not any("RubricSK" in r.message for r in caplog.records), caplog.text
