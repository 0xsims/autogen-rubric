"""Core smoke tests — no real API calls, no framework installs required."""
import importlib.util, sys, types, unittest
from unittest.mock import patch, MagicMock

def _installed(mod):
    """True only if `mod` can really be imported from site-packages.

    `mod not in sys.modules` is not the same question: nothing has imported
    haystack yet at this point in the session even when haystack-ai IS
    installed, so the old check stubbed it anyway. autogen_rubric binds its
    integration symbols at import time, so that stub permanently replaced
    RubricHaystackComponent with the ImportError placeholder for every later
    test in the same process — the poisoning compat.yml works around by
    running test_live_smoke.py in its own process.
    """
    try:
        return importlib.util.find_spec(mod) is not None
    except (ValueError, ModuleNotFoundError, ImportError):
        return False

# ── stub heavy frameworks so tests run without them installed ──────────────
# Only the genuinely-absent ones: a stub over an installed framework hides the
# real integration from the very jobs that exist to exercise it.
for mod in ["openai","anthropic","langchain","autogen","llama_index",
            "crewai","haystack","semantic_kernel","google.adk","agents",
            "dspy","langgraph","pydantic_ai","strands"]:
    if mod not in sys.modules and not _installed(mod):
        sys.modules[mod] = types.ModuleType(mod)

import autogen_rubric as ar

class TestDataclasses(unittest.TestCase):
    def test_request_defaults(self):
        r = ar.AttestationRequest(agent_id="a1", output="hello")
        self.assertEqual(r.leaf_type, "AGENT_OUTPUT")
        self.assertEqual(r.risk, "normal")

    def test_result_repr(self):
        r = ar.AttestationResult(
            attestation_id="abc123xyz", agent_id="a1",
            stage="confirmed", signed_at="2026-01-01T00:00:00Z", node="us"
        )
        self.assertIn("abc123x", repr(r))

class TestClient(unittest.TestCase):
    def test_init_no_network(self):
        c = ar.RubricClient(api_key="test-key", node="us",
                            enterprise=False, background_queue=False)
        self.assertEqual(c.node, "us")

    def test_invalid_node_raises(self):
        with self.assertRaises(ValueError):
            ar.RubricClient(api_key="test-key", node="invalid",
                            enterprise=False, background_queue=False)

class TestInstrument(unittest.TestCase):
    def test_no_frameworks_no_crash(self):
        """instrument() with empty list should return client without error."""
        result = ar.instrument("test-key", frameworks=[], background_queue=False)
        self.assertIsNotNone(result)

    def test_auto_detect_returns_client(self):
        """Auto-detect with all stubs returns without raising."""
        result = ar.instrument("test-key", background_queue=False)
        self.assertIsNotNone(result)

class TestPatchFunctions(unittest.TestCase):
    """Verify each _patch_ function exists — catches renames/deletions."""
    def _check(self, name):
        self.assertTrue(callable(getattr(ar, name, None)),
                        f"Missing or not callable: {name}")
    def test_patch_openai(self):       self._check("_patch_openai")
    def test_patch_anthropic(self):    self._check("_patch_anthropic")
    def test_patch_langchain(self):    self._check("_patch_langchain")
    def test_patch_autogen(self):      self._check("_patch_autogen")
    def test_patch_llama_index(self):  self._check("_patch_llamaindex")
    def test_patch_crewai(self):       self._check("_patch_crewai")
    def test_patch_dspy(self):         self._check("_patch_dspy")
    def test_patch_langgraph(self):    self._check("_patch_langgraph")

if __name__ == "__main__":
    unittest.main()

