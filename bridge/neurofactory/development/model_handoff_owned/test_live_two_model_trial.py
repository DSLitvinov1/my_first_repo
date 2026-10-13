"""Offline, no-network tests of the independent live HANDOFF adapter."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from model_handoff_owned import handoff_gate as gate
from model_handoff_owned import live_two_model_trial as trial

MODULE = "def demo(value):\n    return value\n"
SOURCE = "def normalize_label(value):\n    if not isinstance(value, str):\n        raise ValueError('invalid')\n    return ' '.join(value.split()).lower()\n"

class LiveHandoffOfflineTests(unittest.TestCase):
    def test_source_no_fenced_code(self):
        a = trial.prepare_candidate(SOURCE)
        self.assertEqual(a["candidate"], SOURCE.strip())
        self.assertFalse(a["publisher_enabled"])

    def test_closed_fences_do_not_change_candidate_body(self):
        original = trial.prepare_candidate(SOURCE)
        fenced = trial.prepare_candidate(chr(96)*3 + "python\n" + SOURCE + chr(96)*3)
        self.assertEqual(fenced["candidate_sha256"], original["candidate_sha256"])

    def test_unclosed_fence_rejected(self):
        with self.assertRaises(trial.LiveError):
            trial.prepare_candidate(chr(96)*3 + "python\n" + SOURCE)

    def test_module_review_binds_exact_source_digest(self):
        response = json.dumps({"verdict":"APPROVE", "candidate_sha256":gate.digest(MODULE.encode()),
                               "findings":["Only static inspection performed"]})
        packet = trial.review_module(MODULE, response)
        self.assertEqual(packet["source_sha256"], gate.digest(MODULE.encode()))
        self.assertFalse(packet["release_authorized"])
        self.assertTrue(packet["independent_review_owner_pending"])

    def test_module_review_changed_digest_does_not_count(self):
        response = json.dumps({"verdict":"APPROVE", "candidate_sha256":"0"*64, "findings":[]})
        with self.assertRaises(trial.LiveError):
            trial.review_module(MODULE, response)

    def test_module_review_requires_valid_json(self):
        with self.assertRaises(gate.HandoffError):
            trial.review_module(MODULE, "APPROVE")

    def test_module_review_requires_explicit_verdict(self):
        response = json.dumps({"verdict":"maybe", "candidate_sha256":gate.digest(MODULE.encode()),
                               "findings":[]})
        with self.assertRaises(trial.LiveError):
            trial.review_module(MODULE, response)

    def test_transient_model_failure_retries_exactly_twice(self):
        with tempfile.TemporaryDirectory() as folder:
            calls = []
            def always_fail(model,prompt,*,formatted=False):
                calls.append(model)
                raise trial.LiveError("model timed out")
            with patch.object(trial,"OUT",Path(folder)), patch.object(trial,"local_model",side_effect=always_fail):
                with self.assertRaises(trial.LiveError):
                    trial.call_bounded(gate.WRITER,"test",phase="writer")
                checkpoint = json.loads((Path(folder)/"checkpoint.json").read_text())
                self.assertEqual(checkpoint["stage"],"writer_failed")
                self.assertEqual(checkpoint["attempts"],2)
                self.assertEqual(len(calls),2)

    def test_success_does_not_repeat_model(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(trial,"OUT",Path(folder)), patch.object(trial,"local_model",return_value=("x",{"model":gate.WRITER})) as run:
                self.assertEqual(trial.call_bounded(gate.WRITER,"test",phase="writer")[0],"x")
                self.assertEqual(run.call_count,1)

    def test_local_model_wrong_identity_rejected(self):
        with patch.object(trial.urllib.request,"urlopen") as transport:
            transport.return_value.__enter__.return_value.read.return_value=json.dumps(
                {"model":gate.REVIEWER,"response":"a valid candidate"}).encode()
            with self.assertRaises(trial.LiveError):
                trial.local_model(gate.WRITER,"test")

    def test_per_run_checkpoint_is_fail_closed_if_write_interrupted(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(trial,"OUT",Path(folder)):
                trial.checkpoint("started")
                (Path(folder)/"checkpoint.json.pending").write_text("incomplete")
                with self.assertRaises(trial.LiveError):
                    trial.checkpoint("writer_done")

if __name__ == "__main__":
    unittest.main()
