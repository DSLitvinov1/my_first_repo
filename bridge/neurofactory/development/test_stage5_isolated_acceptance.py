"""Deterministic offline safety checks; never call Ollama or GitHub."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import stage5_isolated_acceptance as gate

CANDIDATE = 'import hashlib\ndef fingerprint(items):\n    return hashlib.sha256(str(items).encode()).hexdigest()'


class Stage5IsolatedAcceptanceTests(unittest.TestCase):
    def test_reviewer_receives_actual_writer_output_not_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            transcript = []
            def fake_model(model, prompt):
                transcript.append((model, prompt))
                if model == gate.WRITER:
                    return CANDIDATE, {"model": model, "eval_count": 12}
                self.assertIn(CANDIDATE, prompt)
                self.assertIn(gate.sha(CANDIDATE), prompt)
                return json.dumps({"verdict": "APPROVE", "candidate_sha256": gate.sha(CANDIDATE), "findings": []}), {"model": model, "eval_count": 12}
            with patch.object(gate, "OUT", Path(temp)), patch.object(gate, "request_json", return_value={"models": [{"name":gate.WRITER}, {"name":gate.REVIEWER}]}), patch.object(gate, "model_call", side_effect=fake_model):
                gate.generate()
                self.assertEqual(gate.validate()["candidate_sha256"], gate.sha(CANDIDATE))
                self.assertEqual([r[0] for r in transcript], [gate.WRITER, gate.REVIEWER])

    def test_mismatched_reviewer_digest_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(gate, "OUT", Path(temp)), patch.object(gate, "request_json", return_value={"models": [{"name":gate.WRITER}, {"name":gate.REVIEWER}]}), patch.object(gate, "model_call", side_effect=[(CANDIDATE, {"model":gate.WRITER}), (json.dumps({"verdict":"APPROVE", "candidate_sha256":"0"*64, "findings":[]}), {"model":gate.REVIEWER})]):
                with self.assertRaises(gate.GateError):
                    gate.generate()

    def test_unsafe_writer_import_never_reaches_reviewer(self):
        with self.assertRaises(gate.GateError):
            gate.clean_candidate("import os\ndef trouble():\n    os.system('echo no')")

    def test_replay_never_writes_and_conflict_stops(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            record = {
                "schema": 1, "task_id": gate.TASK,
                "source": "isolated_two_model_evidence_not_production",
                "candidate": CANDIDATE, "candidate_sha256": gate.sha(CANDIDATE),
                "independent_review": {"verdict":"APPROVE","candidate_sha256":gate.sha(CANDIDATE),"findings":[]},
                "writer": {"model": gate.WRITER}, "reviewer":{"model":gate.REVIEWER}
            }
            (path / "evidence.json").write_text(json.dumps(record), encoding="utf-8")
            with patch.object(gate, "OUT", path), patch.dict(os.environ, {"GITHUB_TOKEN":"test-not-a-real-token"}), patch.object(gate,"github_read",return_value=(record, "old-blob")), patch.object(gate,"request_json") as put:
                gate.publish()
                put.assert_not_called()
            with patch.object(gate, "OUT", path), patch.dict(os.environ, {"GITHUB_TOKEN":"test-not-a-real-token"}), patch.object(gate,"github_read",return_value=({"task_id":"other"}, "old-blob")), patch.object(gate,"request_json") as put:
                with self.assertRaises(gate.GateError):
                    gate.publish()
                put.assert_not_called()


if __name__ == "__main__":
    unittest.main()
