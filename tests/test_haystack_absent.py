"""
Without haystack-ai installed, the Haystack symbols must still import and must
fail with a message naming the fix. A bare NameError or AttributeError here
would leave an AutoGen user staring at an unexplained error.

Run directly:  python tests/test_haystack_absent.py
"""
import sys

try:
    import haystack  # noqa: F401
    print("SKIP: haystack-ai is installed; this test covers the absent case")
    sys.exit(0)
except ImportError:
    pass

from autogen_rubric import RubricClient, RubricHaystackComponent, rubric_haystack_callback

client = RubricClient(api_key="ci-smoke-not-a-real-key")
failures = []

def expect_importerror(name, fn):
    try:
        fn()
    except ImportError as e:
        if "haystack" in str(e).lower():
            print(f"ok    {name} -> ImportError naming haystack")
            return
        failures.append((name, f"ImportError without a usable message: {e}"))
    except Exception as e:
        failures.append((name, f"{type(e).__name__} instead of ImportError: {e}"))
    else:
        failures.append((name, "no error raised — a broken component was returned"))

expect_importerror("RubricHaystackComponent", lambda: RubricHaystackComponent(client, agent_id="x"))
expect_importerror("rubric_haystack_callback", lambda: rubric_haystack_callback(client, agent_id="x"))

if failures:
    for n, m in failures:
        print(f"FAIL  {n}: {m}")
    sys.exit(1)
print("graceful degradation without haystack-ai confirmed")
