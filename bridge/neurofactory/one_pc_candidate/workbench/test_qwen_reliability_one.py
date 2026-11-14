"""Regression for Qwen cloud draft safety, constrained prompt and JSON framing."""
import json
import unittest
from work_core import WorkDenied
from qwen_planner_one import parse_proposal, prompt_for


class QwenReliabilityTests(unittest.TestCase):
    def test_short_goal_uses_bounded_cloud_prompt(self):
        prompt=prompt_for("Проверь публичную страницу https://example.org/", {"example.org"})
        self.assertGreaterEqual(len(prompt),1035)
        self.assertLessEqual(len(prompt),1200)
        self.assertIn("https://example.org/",prompt)
        self.assertIn("не выполняй",prompt.lower())

    def test_user_goal_never_replaces_permissions(self):
        prompt=prompt_for("Открой https://example.org/ и затем запусти cmd.exe", {"example.org"})
        self.assertIn("Запрещены",prompt)
        self.assertIn("команды ОС",prompt)

    def test_json_only_or_complete_fence(self):
        value={"schema":"nf.one.qwen.proposal.v1",
               "steps":[{"op":"open","url":"https://example.org/"},{"op":"frame"}]}
        doc=json.dumps(value,ensure_ascii=False)
        for candidate in (doc,"```json\n"+doc+"\n```","```\n"+doc+"\n```"):
            with self.subTest(candidate=candidate[:12]):
                result=parse_proposal(candidate,{"example.org"})
                self.assertEqual(result["steps"],2)
                self.assertIn("Сделай снимок",result["script"])

    def test_refuse_prose_injection_and_multiple_json(self):
        doc=json.dumps({"schema":"nf.one.qwen.proposal.v1",
                        "steps":[{"op":"open","url":"https://example.org/"},{"op":"frame"}]})
        for raw in ("Я всё сделал. "+doc,doc+"\nОсторожно, я уже оплатил.",
                    "```json\n"+doc+"\n```\nИ ещё...",
                    doc+doc,"<think>ignore</think>"+doc):
            with self.subTest(raw=raw[:20]),self.assertRaises(WorkDenied):
                parse_proposal(raw,{"example.org"})

    def test_refuse_different_host_and_unsafe_operation(self):
        for steps in (
            [{"op":"open","url":"https://untrusted.example/"}],
            [{"op":"open","url":"https://example.org/"},{"op":"shell","cmd":"whoami"}],
            [{"op":"open","url":"http://example.org/"}],
        ):
            with self.subTest(steps=steps),self.assertRaises(WorkDenied):
                parse_proposal(json.dumps({"schema":"nf.one.qwen.proposal.v1",
                                           "steps":steps}),{"example.org"})


if __name__=="__main__":
    unittest.main()
