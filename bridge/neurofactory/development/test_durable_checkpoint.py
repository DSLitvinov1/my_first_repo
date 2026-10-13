"""Real process termination, persisted recovery and duplicate-publication protection."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import durable_checkpoint as store


class DurableCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="neurofactory-crash-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "job-state.json"
        self.task = dict(id="NF-DEV-04-production", state="queued", attempts=0, lease_until=None)
        store.initialize(self.path, self.task)

    def test_atomic_checkpoint_survives_actual_subprocess_termination(self):
        command = """
import os,sys
from pathlib import Path
import durable_checkpoint as store
store.transition(Path(sys.argv[1]),'queued','running',lease_until=120)
os._exit(73)
"""
        cp = subprocess.run([sys.executable, "-c", command, str(self.path)],
                            env=os.environ.copy(), timeout=12)
        self.assertEqual(cp.returncode, 73)
        live = store.load(self.path)
        self.assertEqual((live["state"], live["attempts"]), ("running", 1))
        self.assertEqual(store.recover(self.path, 150, 3)["state"], "queued")
        self.assertEqual(store.recover(self.path, 150, 3)["attempts"], 1)
        self.assertEqual(store.transition(self.path, "queued", "running", lease_until=170)["attempts"], 2)

    def test_interruption_before_atomic_replace_preserves_old_checkpoint(self):
        command = """
import os,sys
from pathlib import Path
import durable_checkpoint as store
store.os.replace=lambda *args: os._exit(74)
store.transition(Path(sys.argv[1]),'queued','running',lease_until=120)
"""
        cp = subprocess.run([sys.executable, "-c", command, str(self.path)],
                            env=os.environ.copy(), timeout=12)
        self.assertEqual(cp.returncode, 74)
        original = store.load(self.path)
        self.assertEqual(original["state"], "queued")
        self.assertEqual(original["attempts"], 0)

    def test_windows_replace_failure_preserves_old_checkpoint(self):
        from unittest import mock
        with mock.patch.object(store.os, "replace", side_effect=PermissionError("file in use")):
            with self.assertRaises(PermissionError):
                store.transition(self.path, "queued", "running", lease_until=120)
        old = store.load(self.path)
        self.assertEqual((old["state"], old["attempts"]), ("queued", 0))

    def test_publishing_interruption_never_resubmits(self):
        store.transition(self.path, "queued", "running", lease_until=100)
        store.transition(self.path, "running", "publishing")
        self.assertEqual(store.recover(self.path, 101, 3)["state"], "needs_receipt_check")
        with self.assertRaises(store.CheckpointError):
            store.transition(self.path, "queued", "running", lease_until=130)
        with self.assertRaises(store.CheckpointError):
            store.transition(self.path, "needs_receipt_check", "verified_done", commit="bad")
        accepted = store.transition(self.path, "needs_receipt_check", "verified_done", commit="a" * 40)
        self.assertEqual(accepted["publication_sha"], "a" * 40)
        self.assertEqual(store.recover(self.path, 10000, 3)["state"], "verified_done")
        with self.assertRaises(store.CheckpointError):
            store.transition(self.path, "verified_done", "running", lease_until=20000)

    def test_duplicate_claim_and_checkpoint_reinitialization_refused(self):
        store.transition(self.path, "queued", "running", lease_until=50)
        with self.assertRaises(store.CheckpointError):
            store.transition(self.path, "queued", "running", lease_until=60)
        with self.assertRaises(store.CheckpointError):
            store.initialize(self.path, self.task)

    def test_max_attempts_exhausted_remains_terminal(self):
        for i in range(3):
            store.transition(self.path, "queued", "running", lease_until=i + 1)
            self.assertEqual(store.recover(self.path, i + 1, 3)["state"],
                             "retry_exhausted" if i == 2 else "queued")
        with self.assertRaises(store.CheckpointError):
            store.transition(self.path, "queued", "running", lease_until=44)

    def test_modified_persisted_data_denied(self):
        data = json.loads(self.path.read_text("utf-8"))
        data["data"]["state"] = "verified_done"
        self.path.write_text(json.dumps(data), "utf-8")
        with self.assertRaises(store.CheckpointError):
            store.load(self.path)

    def test_stale_lease_never_replays_already_verified(self):
        store.transition(self.path, "queued", "running", lease_until=10)
        store.transition(self.path, "running", "publishing")
        store.recover(self.path, 11, 2)
        store.transition(self.path, "needs_receipt_check", "verified_done", commit="b" * 40)
        original = self.path.read_bytes()
        self.assertEqual(store.recover(self.path, 10**9, 2)["state"], "verified_done")
        self.assertEqual(self.path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
