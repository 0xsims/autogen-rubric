"""
Reproduce the code published on haystack.deepset.ai/integrations/rubric-protocol
verbatim, and assert it still works.

That page is a standing promise that a specific snippet runs. It will break
silently the first time haystack-ai ships an incompatible change, and the
failure will surface as OUR integration being broken, on deepset's site,
discovered by a stranger. This test is what makes that promise checkable.

Hermetic: RubricClient's constructor only stores config (no network), and the
component is never run, so nothing is transmitted and no API key is needed.

Run directly:  python tests/test_haystack_page_example.py
"""
import sys

FAILURES = []

def check(name, fn):
    try:
        fn()
        print(f"ok    {name}")
    except Exception as e:
        FAILURES.append((name, e))
        print(f"FAIL  {name}: {type(e).__name__}: {e}")


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
    from autogen_rubric import RubricClient, rubric_haystack_callback
    client = RubricClient(api_key="ci-smoke-not-a-real-key")
    attest = rubric_haystack_callback(client, agent_id="support-rag")
    # Deliberately NOT called: attest(result) would POST a real attestation.
    assert callable(attest), "rubric_haystack_callback did not return a callable"


def versions():
    import importlib.metadata as md
    for p in ("autogen-rubric", "haystack-ai"):
        try:
            print(f"      {p}=={md.version(p)}")
        except Exception:
            print(f"      {p}==NOT INSTALLED")


if __name__ == "__main__":
    print("installed:")
    versions()
    check("published block 1 — component + pipeline.connect", block_one)
    check("published block 2 — callback factory", block_two)
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILURE(S) — the published integration page is now wrong.")
        print("Fix the package or open a PR against deepset-ai/haystack-integrations.")
        sys.exit(1)
    print("published example still works")
