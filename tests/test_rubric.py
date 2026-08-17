"""Haystack callback + provenance regression tests.

The callback cases need a REAL haystack-ai: without it autogen_rubric binds
rubric_haystack_callback to the ImportError placeholder, so they error rather
than test anything. They skip when it is absent, except where
RUBRIC_REQUIRE_HAYSTACK is set (the haystack-ai compat job) — there a skip
would be the silent rot this file exists to prevent, so it fails instead.
"""
import importlib.util, os, unittest
import autogen_rubric as ar


def _has_haystack():
    # `import haystack` is not enough: test_core.py may have put a bare
    # ModuleType in sys.modules, and that import would succeed against the
    # stub. A stub has __spec__ is None, so find_spec raises ValueError.
    try:
        return importlib.util.find_spec("haystack") is not None
    except (ValueError, ModuleNotFoundError, ImportError):
        return False


HAVE = _has_haystack()
REQUIRE = os.environ.get("RUBRIC_REQUIRE_HAYSTACK") not in (None, "", "0")

OUT = {"llm": {"replies": ["The deductible is $500."]}}


class Base(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self._real = ar._http_post

        def fake(url, body, headers, timeout=15):
            self.sent.append(body)
            return {"stage": "pending",
                    "payloadHash": "HASH_" + body.get("attestationId", "?")[:8]}

        ar._http_post = fake
        self.c = ar.RubricClient(api_key="TEST-NOT-REAL")

    def tearDown(self):
        ar._http_post = self._real

    def out(self):
        return self.sent[-1]["data"].get("output") if self.sent else None


class TestEnv(unittest.TestCase):
    def test_haystack_installed(self):
        if not HAVE and not REQUIRE:
            raise unittest.SkipTest(
                "haystack-ai not installed; the callback cases below would only "
                "exercise the ImportError stub, so they are skipped too")
        self.assertTrue(HAVE, "RUBRIC_REQUIRE_HAYSTACK is set but haystack-ai "
                              "is missing: these tests would only exercise the "
                              "ImportError stub")


@unittest.skipUnless(HAVE, "haystack-ai not installed")
class TestCallback(Base):
    def test_dict_attests_real_content(self):
        ar.rubric_haystack_callback(self.c, agent_id="t")(OUT)
        o = self.out()
        self.assertIsNotNone(o, "nothing was sent")
        self.assertNotEqual(o, "{}", "regression: empty payload anchored")
        self.assertIn("deductible", o)

    def test_refuses_unresolvable_input(self):
        for label, arg in [("None", None), ("empty dict", {}), ("object", object())]:
            with self.subTest(arg=label):
                self.sent.clear()
                ar.rubric_haystack_callback(self.c, agent_id="t")(arg)
                self.assertEqual(self.sent, [], label + " anchored an attestation")


class TestProvenance(Base):
    def test_sync_link_is_consistent(self):
        self.c.attest(agent_id="t", output="one")
        a, h = self.c._last_attestation_id, self.c._last_payload_hash
        self.assertTrue(a and h)
        self.assertTrue(h.endswith(a[:8]), a + " paired with " + str(h))

    def test_queued_leaves_no_stale_hash(self):
        q = ar.RubricClient(api_key="TEST-NOT-REAL", background_queue=True)
        q.attest(agent_id="t", output="one", risk="high")
        self.assertIsNotNone(q._last_payload_hash)
        q.attest(agent_id="t", output="two")
        a, h = q._last_attestation_id, q._last_payload_hash
        if a and h:
            self.assertTrue(h.endswith(a[:8]),
                            "regression: " + a + " paired with " + h)


class TestMeta(unittest.TestCase):
    def test_version_matches_wheel(self):
        """__version__ must agree with the installed distribution's metadata.

        Caught 1.8.1-in-module vs 1.10.2-on-the-wheel. Only meaningful against
        an installed distribution: a bare `pytest tests/` in a checkout has no
        metadata to compare, which raised PackageNotFoundError and failed the
        compat core job. CI installs the working tree, so this runs there.
        """
        from importlib.metadata import version, PackageNotFoundError
        try:
            installed = version("autogen-rubric")
        except PackageNotFoundError:
            raise unittest.SkipTest(
                "autogen-rubric is not installed in this environment "
                "(run `pip install .` to exercise this check)")
        self.assertEqual(ar.__version__, installed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
