"""Targeted OPS MVP status and secure-input tests, no real queues or bridges."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from diagnose import SnapshotError
from secure_input import SafeInputError, read_snapshot
from status_adapter import snapshot_to_status, concise_text, main

SHA = "a" * 40
DIGEST = "b" * 64

def sample():
    return {
        "schema": 1, "scope": "neurofactory-ops-status",
        "observed_at": "2026-10-15T01:00:00Z",
        "project": {"id": "NF-OPS-SANDBOX",
                    "repository": "DSLitvinov1/my_first_repo",
                    "branch": "neurofactory-ops-completion-20261015",
                    "head_sha": SHA},
        "bridge": {"state": "RUNNING", "heartbeat_at": "2026-10-15T00:59:00Z"},
        "workers": [{"id": "WIN-RUNNER", "role": "worker",
                     "state": "RUNNING", "heartbeat_at": "2026-10-15T00:59:00Z",
                     "run_id": 101}],
        "queue": [{"task_id": "NF-OPS-EXAMPLE-1",
                   "state": "RUNNING", "worker_id": "WIN-RUNNER",
                   "attempt": 1, "last_progress_at": "2026-10-15T00:40:00Z",
                   "checkpoint": {"state": "PARTIAL", "sha256": None,
                                  "durable_readback": False},
                   "run_id": 101}],
        "runs": [{"id": 101, "state": "COMPLETED", "conclusion": "FAILURE",
                  "head_sha": SHA}],
        "problems": [{"code": "RUNNER_LOST",
                      "task_id": "NF-OPS-EXAMPLE-1", "run_id": 101}]
    }

class StatusAdapterTests(unittest.TestCase):
    def test_realistic_status_and_stuck_task(self):
        d = sample()
        v = snapshot_to_status(d)
        self.assertEqual(v["bridge"]["display_state"], "UNKNOWN")
        self.assertEqual(v["workers"][0]["display_state"], "UNKNOWN")
        self.assertEqual(v["queue"][0]["display_state"], "BLOCKED")
        self.assertTrue(v["queue"][0]["possibly_stalled"])
        self.assertEqual(v["checkpoint_counts"], {"PARTIAL": 1})
        self.assertIn("CHECKPOINT_PARTIAL", [x["code"] for x in v["problems"]])
        self.assertIn("POSSIBLY_STALLED", [x["code"] for x in v["problems"]])
        self.assertFalse(any(v["actions_allowed"].values()))
        self.assertFalse(v["source"]["verified"])

    def test_no_evidence_must_be_unknown(self):
        d = sample()
        d["bridge"] = {"state": "RUNNING", "heartbeat_at": None}
        d["workers"][0]["heartbeat_at"] = None
        d["queue"][0]["state"] = "RUNNING"
        d["queue"][0]["checkpoint"] = {"state": "UNKNOWN", "sha256": None,
                                        "durable_readback": False}
        d["queue"][0]["last_progress_at"] = None
        v = snapshot_to_status(d)
        self.assertEqual(v["bridge"]["display_state"], "UNKNOWN")
        self.assertEqual(v["workers"][0]["display_state"], "UNKNOWN")
        self.assertEqual(v["queue"][0]["display_state"], "UNKNOWN")
        self.assertTrue(v["queue"][0]["possibly_stalled"])

    def test_stale_heartbeat_does_not_claim_live(self):
        d = sample()
        d["bridge"]["heartbeat_at"] = "2026-10-15T00:00:00Z"
        d["workers"][0]["heartbeat_at"] = "2026-10-15T00:00:00Z"
        v = snapshot_to_status(d)
        self.assertEqual(v["bridge"]["display_state"], "UNKNOWN")
        self.assertEqual(v["workers"][0]["display_state"], "UNKNOWN")

    def test_valid_checkpoint_still_is_not_attested(self):
        d = sample()
        d["queue"][0]["checkpoint"] = {
            "state": "VERIFIED", "sha256": DIGEST, "durable_readback": True}
        d["queue"][0]["last_progress_at"] = "2026-10-15T00:59:00Z"
        v = snapshot_to_status(d)
        self.assertFalse(v["queue"][0]["checkpoint"]["externally_verified"])
        self.assertEqual(v["queue"][0]["display_state"], "UNKNOWN")

    def test_forged_checkpoint_verification_rejected_if_incomplete(self):
        d = sample()
        d["queue"][0]["checkpoint"]["state"] = "VERIFIED"
        with self.assertRaises(SnapshotError):
            snapshot_to_status(d)

    def test_repeated_problem_run_ids_deduplicated(self):
        d = sample()
        d["problems"].append(copy.deepcopy(d["problems"][0]))
        d["problems"].append({"code": "RUNNER_LOST", "task_id": "NF-OPS-EXAMPLE-1",
                              "run_id": 102})
        v = snapshot_to_status(d)
        p = next(p for p in v["problems"] if p["code"] == "RUNNER_LOST")
        self.assertEqual(p["distinct_reported_runs"], 2)
        self.assertTrue(p["recurrent_in_snapshot"])

    def test_wrong_head_is_not_mislabeled_current(self):
        d = sample()
        d["runs"][0]["head_sha"] = "c" * 40
        self.assertFalse(snapshot_to_status(d)["runs"][0]["matches_project_head"])

    def test_suspicious_extra_credential_fields_refused(self):
        d = sample()
        d["project"]["token"] = "PRIVATE_SECRET"
        with self.assertRaises(SnapshotError):
            snapshot_to_status(d)

    def test_duplicate_workers_rejected(self):
        d = sample()
        d["workers"].append(copy.deepcopy(d["workers"][0]))
        with self.assertRaises(SnapshotError):
            snapshot_to_status(d)

    def test_duplicate_tasks_rejected(self):
        d = sample()
        d["queue"].append(copy.deepcopy(d["queue"][0]))
        with self.assertRaises(SnapshotError):
            snapshot_to_status(d)

    def test_duplicate_runs_rejected(self):
        d = sample()
        d["runs"].append(copy.deepcopy(d["runs"][0]))
        with self.assertRaises(SnapshotError):
            snapshot_to_status(d)

    def test_future_heartbeat_rejected(self):
        d = sample()
        d["bridge"]["heartbeat_at"] = "2026-10-15T01:01:00Z"
        with self.assertRaises(SnapshotError):
            snapshot_to_status(d)

    def test_offline_heartbeat_is_not_live_confirmation(self):
        d = sample()
        d["bridge"]["state"] = "OFFLINE"
        v = snapshot_to_status(d)
        self.assertEqual(v["bridge"]["display_state"], "UNKNOWN")

    def test_no_workers_means_no_false_success(self):
        d = sample()
        d["workers"] = []
        d["queue"] = []
        d["problems"] = []
        v = snapshot_to_status(d)
        self.assertEqual(v["workers"], [])
        self.assertEqual(v["queue"], [])
        self.assertFalse(v["integrity"]["snapshot_authenticated"])

    def test_no_tasks_outside_schema(self):
        d = sample()
        d["queue"][0]["state"] = "PUBLISHED"
        with self.assertRaises(SnapshotError):
            snapshot_to_status(d)

    def test_windows_and_linux_secure_reader_plain_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "snapshot.json"
            path.write_text(json.dumps(sample()), encoding="utf-8")
            self.assertEqual(json.loads(read_snapshot(path))["schema"], 1)

    def test_symlink_file_never_read(self):
        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "real.json"
            real.write_text(json.dumps(sample()), encoding="utf-8")
            alias = Path(td) / "alias.json"
            try:
                alias.symlink_to(real)
            except (OSError, NotImplementedError):
                self.skipTest("Windows runner does not permit symlinks")
            with self.assertRaises(SafeInputError):
                read_snapshot(alias)

    @unittest.skipUnless(os.name == "posix", "FIFO supported on POSIX")
    def test_fifo_nonblocking_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "fifo"
            os.mkfifo(p)
            with self.assertRaises(SafeInputError):
                read_snapshot(p)

    def test_invalid_utf8_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad"
            p.write_bytes(b"\xff")
            with self.assertRaises(SafeInputError):
                read_snapshot(p)

    def test_text_discloses_untrusted(self):
        s = concise_text(snapshot_to_status(sample()))
        self.assertIn("непроверенный", s.lower())
        self.assertIn("возможное зависание", s)
        self.assertIn("ЗАПРЕЩЕНЫ", s)

    def test_cli_accepts_fixture_without_writes(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "fixture.json"
            p.write_text(json.dumps(sample()), encoding="utf-8")
            from contextlib import redirect_stdout
            from io import StringIO
            out = StringIO()
            with redirect_stdout(out):
                self.assertEqual(main([str(p)]), 0)
            val = json.loads(out.getvalue())
            self.assertEqual(val["type"], "neurofactory.ops.status_view")
            self.assertEqual(set(Path(td).iterdir()), {p})


if __name__ == "__main__":
    unittest.main()
