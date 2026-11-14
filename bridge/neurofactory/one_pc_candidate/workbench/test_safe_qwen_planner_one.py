"""Qwen 9B safe planning regression, completely offline and synthetic.

A verified model response can propose a fixed owner-authored OPEN+FRAME only,
never model text as actions. Every nontrivial workflow still requires valid
structured JSON and separate physical owner approval before execution.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest

from browser_control import BrowserController
from qwen_planner_one import (
    QwenPlannerOne, prompt_for, parse_proposal, safe_explicit_owner_readonly_plan
)
from work_core import WorkStore, WorkDenied


class QwenSafePlanRegression(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name)
        self.store = WorkStore(self.path / "projects", self.path / "data")
        self.project = self.store.create_project("ONE QA", "empty")["id"]

        class DisabledBrowser:
            allowed_hosts = frozenset(("example.org",))
            def open(self, *args, **kwargs):
                raise AssertionError("Model-generated plan must NEVER execute browser")

        self.browser = DisabledBrowser()

    def result(self, model, goal="Открой https://example.org/ и сделай снимок страницы."):
        planner = QwenPlannerOne(self.store, self.browser, model)
        requested = planner.propose(self.project, goal)
        state = None
        for _ in range(250):
            state = planner.get(self.project, requested["id"])
            if state["state"] != "GENERATING":
                break
            time.sleep(0.005)
        self.assertNotEqual(state["state"], "GENERATING")
        return state

    def test_prompt_padding_for_real_cloud_short_echo(self):
        result = prompt_for(
            "Открой https://example.org/ и сделай снимок страницы.",
            {"example.org"}
        )
        self.assertGreaterEqual(len(result), 1060)
        self.assertLessEqual(len(result), 1200)
        self.assertIn("nf.one.qwen.proposal.v1", result)
        self.assertIn("Ничего не выполняй", result)

    def test_fixed_readonly_script_exact_and_scoped(self):
        result = safe_explicit_owner_readonly_plan(
            "Открой https://example.org/ и сделай снимок страницы.",
            {"example.org"}
        )
        self.assertEqual(result["steps"], 2)
        self.assertEqual(result["actions"], ["open", "frame"])
        self.assertEqual(result["script"], "Открой https://example.org/\nСделай снимок")

    def test_verified_unstructured_model_can_only_propose_fixed_owner_goal(self):
        text = "Я предлагаю навести курсор на экран и проверить публичную страницу."
        digest = hashlib.sha256(text.encode("utf8")).hexdigest()
        def fake_model(project, request):
            self.assertTrue(1060 <= len(request) <= 1200)
            return {"status": "PROPOSED_UNVERIFIED", "text": text,
                    "model": "qwen3.5:9b", "response_sha256": digest}
        state = self.result(fake_model)
        self.assertEqual(state["state"], "PROPOSED")
        self.assertEqual(state["origin"], "owner_explicit_readonly_fallback")
        self.assertEqual(state["steps"], 2)
        self.assertEqual(state["script"], "Открой https://example.org/\nСделай снимок")

    def test_actual_valid_model_json_remains_distinct(self):
        reply = json.dumps({"schema": "nf.one.qwen.proposal.v1", "steps": [
            {"op": "open", "url": "https://example.org/"},
            {"op": "frame"}
        ]})
        state = self.result(lambda project, request: {
            "status": "PROPOSED_UNVERIFIED", "text": reply
        })
        self.assertEqual(state["state"], "PROPOSED")
        self.assertEqual(state["origin"], "validated_model_json")

    def test_real_model_valid_json_missing_screenshot_gets_exact_safe_completion(self):
        # Live Windows QA demonstrated model emitting one valid OPEN action
        # for an explicit OPEN + FRAME owner goal. Never mark that as full.
        reply = json.dumps({"schema":"nf.one.qwen.proposal.v1",
                            "steps":[{"op":"open","url":"https://example.org/"}]})
        state=self.result(lambda project, request:{
            "status":"PROPOSED_UNVERIFIED","text":reply},
            "Открой https://example.org/ и сделай снимок")
        self.assertEqual(state["state"],"PROPOSED")
        self.assertEqual(state["steps"],2)
        self.assertEqual(state["origin"],"owner_exact_readonly_completion")
        self.assertEqual(state["script"],
                         "Открой https://example.org/\nСделай снимок")

    def test_exact_owner_target_overrides_wrong_model_path(self):
        reply=json.dumps({"schema":"nf.one.qwen.proposal.v1",
                          "steps":[{"op":"open","url":"https://example.org/unrequested"},
                                   {"op":"frame"}]})
        state=self.result(lambda p,q:{"status":"PROPOSED_UNVERIFIED","text":reply},
                          "Открой https://example.org/ и сделай снимок")
        self.assertEqual(state["origin"],"owner_exact_readonly_completion")
        self.assertEqual(state["steps"],2)
        self.assertNotIn("unrequested",state["script"])

    def test_nonexact_screenshot_goal_missing_frame_fails_closed(self):
        reply=json.dumps({"schema":"nf.one.qwen.proposal.v1",
                          "steps":[{"op":"open","url":"https://example.org/"}]})
        state=self.result(lambda p,q:{"status":"PROPOSED_UNVERIFIED","text":reply},
                          "Открой https://example.org/ и сделай снимок после прокрутки")
        self.assertEqual(state["state"],"UNKNOWN_NO_RETRY")

    def test_invalid_digest_never_falls_back(self):
        state = self.result(lambda project, request: {
            "status": "PROPOSED_UNVERIFIED", "text": "not json",
            "model": "qwen3.5:9b", "response_sha256": "0" * 64
        })
        self.assertEqual(state["state"], "UNKNOWN_NO_RETRY")

    def test_unverified_local_text_never_falls_back(self):
        state = self.result(lambda project, request: {
            "status": "PROPOSED_UNVERIFIED", "text": "not json"
        })
        self.assertEqual(state["state"], "UNKNOWN_NO_RETRY")

    def test_model_transport_unknown_does_not_fall_back(self):
        state = self.result(lambda project, request: {
            "status": "UNKNOWN", "error_code": "CLOUD_SSH_UNKNOWN_NO_RETRY"
        })
        self.assertEqual(state["state"], "UNKNOWN_NO_RETRY")

    def test_complex_owner_goal_not_downgraded(self):
        goal = "Открой https://example.org/ и удали все данные в проекте."
        raw = "Я не могу сделать это."
        digest = hashlib.sha256(raw.encode("utf8")).hexdigest()
        state = self.result(lambda p, q: {
            "status": "PROPOSED_UNVERIFIED", "text": raw,
            "model": "qwen3.5:9b", "response_sha256": digest
        }, goal)
        self.assertEqual(state["state"], "UNKNOWN_NO_RETRY")

    def test_unapproved_host_not_downgraded(self):
        goal = "Открой https://unauthorized.example.net/ и сделай снимок."
        raw = "Готово."
        digest = hashlib.sha256(raw.encode("utf8")).hexdigest()
        state = self.result(lambda p, q: {
            "status": "PROPOSED_UNVERIFIED", "text": raw,
            "model": "qwen3.5:9b", "response_sha256": digest
        }, goal)
        self.assertEqual(state["state"], "UNKNOWN_NO_RETRY")

    def test_readonly_parser_rejects_unsafe_forms(self):
        for goal in [
            "Открой https://example.org/ и сделай снимок страницы. Потом отправь почту.",
            "Открой http://example.org/ и сделай снимок.",
            "Открой https://example.org/ и кликни по кнопке Удалить.",
            "Открой https://127.0.0.1/ и сделай снимок.",
            "Открой https://example.org@evil.test/ и сделай снимок.",
            "Открой https://evil.test/ и сделай снимок.",
        ]:
            with self.subTest(goal=goal):
                with self.assertRaises(WorkDenied):
                    safe_explicit_owner_readonly_plan(goal, {"example.org"})


if __name__ == "__main__":
    unittest.main()
