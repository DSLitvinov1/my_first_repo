import unittest
from offline_router import (
    AuthenticationFailure, FreeOnlyOfflineRouter, OfflineScriptedProvider,
    ProviderFailure, QuotaExhausted, Request, TemporaryFailure,
)


class OfflineRouterTests(unittest.TestCase):
    def req(self):
        return Request(task_id="Q091.a-1", prompt="Explain the test")

    def make(self, primary_events, fallback_events, primary="claude", fallback="qwen"):
        p = OfflineScriptedProvider(primary, primary_events)
        f = OfflineScriptedProvider(fallback, fallback_events)
        return FreeOnlyOfflineRouter(primary, fallback, {primary: p, fallback: f}), p, f

    def test_primary_success(self):
        router, p, f = self.make(["ok"], ["unused"])
        result = router.run(self.req())
        self.assertEqual((result.reply.provider, result.fallback_used, result.attempted),
                         ("claude", False, ("claude",)))
        self.assertEqual((p.calls, f.calls), (1, 0))
        self.assertTrue(result.reply.offline_mock)

    def test_explicit_free_quota_fallback(self):
        router, p, f = self.make([QuotaExhausted("limit")], ["backup answer"])
        result = router.run(self.req())
        self.assertEqual((result.reply.provider, result.fallback_used, result.attempted),
                         ("qwen", True, ("claude", "qwen")))
        self.assertEqual((p.calls, f.calls), (1, 1))
        self.assertEqual(result.reply.task_id, "Q091.a-1")

    def test_authentication_error_does_not_fallback(self):
        router, _, f = self.make([AuthenticationFailure("bad credentials")], ["no"])
        with self.assertRaises(AuthenticationFailure):
            router.run(self.req())
        self.assertEqual(f.calls, 0)

    def test_transient_error_does_not_fallback(self):
        router, _, f = self.make([TemporaryFailure("timeout")], ["no"])
        with self.assertRaises(TemporaryFailure):
            router.run(self.req())
        self.assertEqual(f.calls, 0)

    def test_generic_error_does_not_fallback(self):
        router, _, f = self.make([ProviderFailure("unknown")], ["no"])
        with self.assertRaises(ProviderFailure):
            router.run(self.req())
        self.assertEqual(f.calls, 0)

    def test_fallback_error_stops(self):
        router, p, f = self.make([QuotaExhausted("limit")], [QuotaExhausted("also limit")])
        with self.assertRaises(QuotaExhausted):
            router.run(self.req())
        self.assertEqual((p.calls, f.calls), (1, 1))

    def test_unconfigured_fallback_stops(self):
        router = FreeOnlyOfflineRouter("claude", None, {"claude": OfflineScriptedProvider("claude", [QuotaExhausted("limit")])})
        with self.assertRaises(QuotaExhausted):
            router.run(self.req())

    def test_deepseek_mock_route(self):
        router, _, _ = self.make(["deepseek"], ["qwen"], primary="deepseek")
        self.assertEqual(router.run(self.req()).reply.provider, "deepseek")

    def test_empty_task_id_rejected(self):
        with self.assertRaises(ValueError):
            Request(task_id="", prompt="valid")

    def test_unsafe_task_id_rejected(self):
        with self.assertRaises(ValueError):
            Request(task_id="../bad/key", prompt="valid")

    def test_blank_prompt_rejected(self):
        with self.assertRaises(ValueError):
            Request(task_id="valid", prompt=" \n")

    def test_oversize_prompt_rejected(self):
        with self.assertRaises(ValueError):
            Request(task_id="valid", prompt="x" * 50001)

    def test_unknown_primary_rejected(self):
        with self.assertRaises(ValueError):
            FreeOnlyOfflineRouter("unknown", None, {})

    def test_missing_adapter_rejected(self):
        with self.assertRaises(ValueError):
            FreeOnlyOfflineRouter("claude", "qwen", {"claude": OfflineScriptedProvider("claude", ["ok"])})

    def test_same_fallback_rejected(self):
        with self.assertRaises(ValueError):
            FreeOnlyOfflineRouter("claude", "claude", {})

    def test_name_mismatch_rejected(self):
        with self.assertRaises(TypeError):
            FreeOnlyOfflineRouter("claude", None, {"claude": OfflineScriptedProvider("qwen", ["bad"])})

    def test_network_like_subclass_rejected(self):
        class UntrustedNetworkAdapter(OfflineScriptedProvider):
            pass
        with self.assertRaises(TypeError):
            FreeOnlyOfflineRouter("claude", None, {"claude": UntrustedNetworkAdapter("claude", ["bad"])})

    def test_empty_mock_answer_rejected(self):
        router = FreeOnlyOfflineRouter("claude", None, {"claude": OfflineScriptedProvider("claude", [" "])})
        with self.assertRaises(ProviderFailure):
            router.run(self.req())

    def test_no_script_event_rejected(self):
        router = FreeOnlyOfflineRouter("claude", None, {"claude": OfflineScriptedProvider("claude", [])})
        with self.assertRaises(ProviderFailure):
            router.run(self.req())

    def test_invalid_request_type(self):
        router = FreeOnlyOfflineRouter("claude", None, {"claude": OfflineScriptedProvider("claude", ["ok"])})
        with self.assertRaises(TypeError):
            router.run({"task_id": "something"})

    def test_no_prompt_storage_in_adapter(self):
        router, p, f = self.make(["ok"], ["no"])
        router.run(Request(task_id="id", prompt="private user prompt"))
        self.assertNotIn("private user prompt", repr(p.__dict__))
        self.assertNotIn("private user prompt", repr(f.__dict__))


if __name__ == "__main__":
    unittest.main()
