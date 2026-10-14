"""Offline schema and safety regressions for the source-only Qwen3 review."""
import hashlib
import json
import unittest
from model_handoff_owned import live_qwen3_remediation_review as audit

SOURCE = b"def safe_func(value):\n    return str(value)\n"
HASH = hashlib.sha256(SOURCE).hexdigest()

class Qwen3AuditTests(unittest.TestCase):
    def test_request_exact_source_and_frozen_schema(self):
        req = audit.build_request(SOURCE, HASH)
        prompt = json.loads(req["prompt"])
        self.assertEqual(prompt["source_sha256"], HASH)
        self.assertEqual(prompt["full_python_module"], SOURCE.decode())
        self.assertEqual(req["model"], "qwen3:4b")
        self.assertFalse(req["stream"])
        self.assertFalse(req["think"])
        self.assertEqual(req["format"]["properties"]["candidate_sha256"]["enum"], [HASH])

    def reply(self, verdict="APPROVE", sha=HASH, findings=None):
        return {"model": "qwen3:4b", "response": json.dumps({
            "verdict": verdict, "candidate_sha256": sha,
            "findings": [] if findings is None else findings})}

    def test_approval_is_model_opinion_only(self):
        self.assertEqual(audit.validate_result(self.reply(), HASH)["verdict"], "APPROVE")

    def test_valid_rejection_is_preserved(self):
        self.assertEqual(audit.validate_result(self.reply("REJECT", findings=["Unsafe"]), HASH)["verdict"], "REJECT")

    def test_other_model_and_wrong_source_are_rejected(self):
        for response in ({**self.reply(), "model": "qwen2.5-coder:7b"}, self.reply(sha="0"*64)):
            with self.subTest(response=response), self.assertRaises(audit.AuditError):
                audit.validate_result(response, HASH)

    def test_duplicate_keys_malformed_and_partial_are_rejected(self):
        for response in ("{", '{"verdict":"APPROVE","verdict":"REJECT"}',
                         '{"verdict":"APPROVE"}'):
            with self.subTest(response=response), self.assertRaises(audit.AuditError):
                audit.validate_result({"model": "qwen3:4b", "response": response}, HASH)

    def test_unexplained_reject_and_invalid_findings_are_rejected(self):
        for response in (self.reply("REJECT"), self.reply(findings=[""]), self.reply(findings=[1])):
            with self.subTest(response=response), self.assertRaises(audit.AuditError):
                audit.validate_result(response, HASH)

    def test_model_request_does_not_authorize_publisher(self):
        req = audit.build_request(SOURCE, HASH)
        self.assertNotIn("GITHUB_TOKEN", req["prompt"])
        self.assertNotIn("publish", req["format"])

if __name__ == "__main__":
    unittest.main()
