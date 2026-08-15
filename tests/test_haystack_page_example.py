"""
Reproduce the code published on haystack.deepset.ai/integrations/rubric-protocol
verbatim, and assert it still works.

That page is a standing promise that a specific snippet runs. It breaks silently
the first time haystack-ai ships an incompatible change, and the failure surfaces
as OUR integration being broken, on deepset's site, found by a stranger.

Hermetic: RubricClient's constructor only stores config, and the component is
never run, so nothing is transmitted and no API key is needed.

Works two ways — under pytest, and standalone:
    pytest tests/test_haystack_page_example.py
    python tests/test_haystack_page_example.py
"""
import importlib.util
import sys

def _has_haystack():
    # Mirrors _has() in test_live_smoke.py: a mocked or partially-imported
    # module raises ValueError("haystack.__spec__ is None") rather than
    # returning None, and the suite injects one. Treat it as unavailable.
    try:
        return importlib.util.find_spec("haystack") is not None
    except (ValueError, ModuleNotFoundError, ImportError):
        return False


HAS_HAYSTACK = _has_haystack()

try:
    import pytest
    skipif = pytest.mark.skipif
except ImportError:                                    # standalone, no pytest
    def skipif(cond, reason=""):
        def deco(fn):
            return fn
        return deco


# ---- block 1, exactly as published ---------------------------------------
def block_one():
    from haystack import Pipeline, component
    from autogen_rubric import RubricClient, RubricHaystackComponent

    client = RubricClient(api_key="ci-smoke-not-a-real-key")

    # Stand-in for "your generator" so the published connect() line can be
    # exercised. The page says "... add your generator, retriever, etc. ..."
    @component
    class _StubLLM:
        @component.output_types(replies=list)
        def run(self, prompt: str = ""):
            return {"replies": ["stub"]}

    pipeline = Pipeline()
    pipeline.add_component("llm", _StubLLM())
    pipeline.add_component("rubric", RubricHaystackComponent(
        client,
        agent_id="support-rag",
        pipeline_id="prod-v3",
    ))
    pipeline.connect("llm.replies", "rubric.replies")

    # The component contract Haystack enforces — this is what an upgrade breaks.
    got = pipeline.get_component("rubric")
    assert hasattr(got, "run"), "component has no run()"
    assert hasattr(got, "__haystack_output__"), "run() is missing @component.output_types"
    assert hasattr(got, "__haystack_input__"), "component declares no inputs"
    names = {s.name for s in got.__haystack_input__._sockets_dict.values()}
    assert "replies" in names, f"expected a 'replies' input socket, got {names}"


# ---- block 2, exactly as published ---------------------------------------
def block_two():
    import autogen_rubric as _ar
    from autogen_rubric import RubricClient, rubric_haystack_callback

    sent = []
    real_post = _ar._http_post

    def capture(url, body, headers, timeout=15):
        sent.append(body)
        return {"stage": "pending", "payloadHash": "ci-stub"}

    _ar._http_post = capture          # stubbed: no attestation leaves CI
    try:
        client = RubricClient(api_key="ci-smoke-not-a-real-key")
        attest = rubric_haystack_callback(client, agent_id="support-rag")
        assert callable(attest), "rubric_haystack_callback did not return a callable"

        # The published example passes the result of Pipeline.run().
        result = {"llm": {"replies": ["the published example output"]}}
        attest(result)

        assert sent, "callback produced no attestation at all"
        out = sent[-1]["data"].get("output")
        assert out != "{}", "callback anchored an empty payload"
        assert "published example" in out, "unexpected payload: %r" % (out,)
    finally:
        _ar._http_post = real_post


@skipif(not HAS_HAYSTACK, reason="haystack-ai not installed")
def test_published_block_one():
    block_one()


@skipif(not HAS_HAYSTACK, reason="haystack-ai not installed")
def test_published_block_two():
    block_two()


def _versions():
    import importlib.metadata as md
    for p in ("autogen-rubric", "haystack-ai"):
        try:
            print(f"      {p}=={md.version(p)}")
        except Exception:
            print(f"      {p}==NOT INSTALLED")


if __name__ == "__main__":
    print("installed:")
    _versions()
    if not HAS_HAYSTACK:
        print("SKIP: haystack-ai not installed")
        sys.exit(0)
    failures = []
    for name, fn in (("published block 1 — component + pipeline.connect", block_one),
                     ("published block 2 — callback factory", block_two)):
        try:
            fn()
            print(f"ok    {name}")
        except Exception as e:
            failures.append(name)
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
    print()
    if failures:
        print(f"{len(failures)} FAILURE(S) — the published integration page is now wrong.")
        print("Fix the package or open a PR against deepset-ai/haystack-integrations.")
        sys.exit(1)
    print("published example still works")
