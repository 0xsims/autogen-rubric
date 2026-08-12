"""
Without haystack-ai installed, the Haystack symbols must still import and must
fail with a message naming the fix. A bare NameError or AttributeError would
leave an AutoGen user staring at an unexplained error.

Import-safe: no module-level exit. An earlier version called sys.exit() at
import, which aborts pytest collection for the whole session — the same defect
this suite already had in test_apa_offline.py.

    pytest tests/test_haystack_absent.py
    python tests/test_haystack_absent.py
"""
import importlib.util
import sys

HAS_HAYSTACK = importlib.util.find_spec("haystack") is not None

try:
    import pytest
    skipif = pytest.mark.skipif
except ImportError:
    def skipif(cond, reason=""):
        def deco(fn):
            return fn
        return deco


def _expect_importerror(fn):
    """Return None if fn() raised ImportError naming haystack, else a reason."""
    try:
        fn()
    except ImportError as e:
        if "haystack" in str(e).lower():
            return None
        return f"ImportError without a usable message: {e}"
    except Exception as e:
        return f"{type(e).__name__} instead of ImportError: {e}"
    return "no error raised — a broken component was returned"


def _client():
    from autogen_rubric import RubricClient
    return RubricClient(api_key="ci-smoke-not-a-real-key")


@skipif(HAS_HAYSTACK, reason="haystack-ai IS installed; this covers the absent case")
def test_component_fails_usefully_without_haystack():
    from autogen_rubric import RubricHaystackComponent
    c = _client()
    reason = _expect_importerror(lambda: RubricHaystackComponent(c, agent_id="x"))
    assert reason is None, f"RubricHaystackComponent: {reason}"


@skipif(HAS_HAYSTACK, reason="haystack-ai IS installed; this covers the absent case")
def test_callback_fails_usefully_without_haystack():
    from autogen_rubric import rubric_haystack_callback
    c = _client()
    reason = _expect_importerror(lambda: rubric_haystack_callback(c, agent_id="x"))
    assert reason is None, f"rubric_haystack_callback: {reason}"


if __name__ == "__main__":
    if HAS_HAYSTACK:
        print("SKIP: haystack-ai is installed; this test covers the absent case")
        sys.exit(0)
    from autogen_rubric import RubricHaystackComponent, rubric_haystack_callback
    c = _client()
    bad = []
    for name, fn in (("RubricHaystackComponent", lambda: RubricHaystackComponent(c, agent_id="x")),
                     ("rubric_haystack_callback", lambda: rubric_haystack_callback(c, agent_id="x"))):
        r = _expect_importerror(fn)
        if r:
            bad.append((name, r)); print(f"FAIL  {name}: {r}")
        else:
            print(f"ok    {name} -> ImportError naming haystack")
    sys.exit(1 if bad else 0)
