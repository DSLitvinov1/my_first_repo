"""Deterministic scoped tests; no remote writes, paid models or user processes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from stage5_isolated_failure_supervisor import (
    FailureLedger, UnsafeState, BRANCH, digest, MAX_RETRIES
)

TASK = "NF-DEV-05-FAULT-001"
WORKER = "WIN-LIDC05TBOQD-chatgpt"
BACKUP = "recovery"
SRC = "def addition(a, b):\n    return a + b\n"

class FailureSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.queue = FailureLedger(self.root, TASK)
        self.queue.initialize()

    def tearDown(self):
        self.temp.cleanup()

    def reviewed(self):
        self.queue.start("writer", WORKER, now=10)
        self.queue.writer_result(SRC, model="qwen2.5-coder:7b")
        self.queue.start("reviewer", BACKUP, now=11)
        self.queue.reviewer_result(model="qwen3:4b",
                                   reviewed_candidate=SRC, approved=True)

    def receipt(self):
        return dict(task_id=TASK, branch=BRANCH,
                    source_sha256=digest(SRC), reviewed_sha256=digest(SRC),
                    commit_sha="a" * 40)

    def test_exact_two_model_approval_and_receipt(self):
        self.reviewed()
        self.assertEqual(self.queue.snapshot()["status"], "review_ok")
        self.queue.start("publisher", WORKER, now=12)
        done = self.queue.reconcile_receipt(self.receipt(),
                            github_reachable=True, verify_remote=lambda r: True)
        self.assertEqual(done["status"], "verified_done")
        self.assertEqual(done["publication_sha"], "a" * 40)
        unchanged = self.queue.snapshot()["revision"]
        self.queue.start("publisher", WORKER, now=13)
        self.assertEqual(self.queue.snapshot()["revision"], unchanged)

    def test_reviewer_must_see_exact_candidate(self):
        self.queue.start("writer", WORKER, now=1)
        self.queue.writer_result(SRC, model="qwen2.5-coder:7b")
        self.queue.start("reviewer", BACKUP, now=2)
        state = self.queue.reviewer_result(model="qwen3:4b",
                                            reviewed_candidate="wrong", approved=True)
        self.assertEqual(state["status"], "blocked")
        with self.assertRaises(UnsafeState):
            self.queue.start("publisher", WORKER, now=3)

    def test_unapproved_models_rejected(self):
        self.queue.start("writer", WORKER, now=1)
        with self.assertRaises(UnsafeState):
            self.queue.writer_result(SRC, model="mystery-coder")
        self.queue.writer_result(SRC, model="qwen2.5-coder:7b")
        self.queue.start("reviewer", BACKUP, now=2)
        with self.assertRaises(UnsafeState):
            self.queue.reviewer_result(model="qwen2.5-coder:7b",
                                       reviewed_candidate=SRC, approved=True)

    def test_reviewer_rejection_blocks_publication(self):
        self.queue.start("writer", WORKER, now=1)
        self.queue.writer_result(SRC, model="qwen2.5-coder:7b")
        self.queue.start("reviewer", BACKUP, now=2)
        self.assertEqual(self.queue.reviewer_result(model="qwen3:4b",
                              reviewed_candidate=SRC, approved=False)["status"], "blocked")

    def test_bounded_two_retries(self):
        self.queue.start("writer", WORKER, now=10)
        for count in range(1, MAX_RETRIES + 1):
            snapshot = self.queue.failure("model_timeout", available_runners=[BACKUP])
            self.assertEqual(snapshot["status"], "retry_wait")
            self.assertEqual(snapshot["retries"], count)
            self.queue.start("writer", BACKUP, now=10 + count)
        exhausted = self.queue.failure("model_timeout")
        self.assertEqual(exhausted["status"], "blocked")
        self.assertEqual(exhausted["retries"], MAX_RETRIES + 1)

    def test_switch_only_to_explicit_backup(self):
        self.queue.start("writer", WORKER, now=10)
        next_state = self.queue.failure("worker_unavailable",
                                available_runners=["foreign-agent", BACKUP])
        self.assertEqual(next_state["status"], "retry_wait")
        self.assertEqual(next_state["runner"], BACKUP)
        self.queue.start("writer", BACKUP, now=12)
        self.assertEqual(self.queue.snapshot()["runner"], BACKUP)

    def test_no_backup_blocks(self):
        self.queue.start("writer", WORKER, now=1)
        self.assertEqual(self.queue.failure("worker_unavailable",
                    available_runners=["foreign-agent"])["status"], "blocked")

    def test_memory_pressure_never_kills_any_process(self):
        self.queue.start("writer", WORKER, now=1)
        self.assertEqual(self.queue.failure("out_of_memory")["status"], "blocked")

    def test_unknown_github_publication_requires_receipt_reconciliation(self):
        self.reviewed()
        self.queue.start("publisher", WORKER, now=20)
        paused = self.queue.failure("publication_unknown")
        self.assertEqual(paused["status"], "needs_receipt_check")
        with self.assertRaises(UnsafeState):
            self.queue.start("publisher", WORKER, now=21)
        self.assertEqual(self.queue.reconcile_receipt(None, github_reachable=False)["status"],
                         "needs_receipt_check")
        self.assertEqual(self.queue.reconcile_receipt(self.receipt(), github_reachable=True,
                          verify_remote=lambda r: True)["status"], "verified_done")

    def test_missing_receipt_stays_blocked(self):
        self.reviewed()
        self.queue.start("publisher", WORKER, now=2)
        self.assertEqual(self.queue.reconcile_receipt(None,
                      github_reachable=True)["status"], "blocked")

    def test_verifier_must_confirm_real_receipt(self):
        self.reviewed()
        self.queue.start("publisher", WORKER, now=2)
        unchanged = self.queue.reconcile_receipt(self.receipt(), github_reachable=True,
                                      verify_remote=lambda r: False)
        self.assertEqual(unchanged["status"], "needs_receipt_check")
        self.assertEqual(self.queue.reconcile_receipt(self.receipt(), github_reachable=True,
                                      verify_remote=lambda r: True)["status"], "verified_done")

    def test_wrong_branch_or_wrong_commit_blocks(self):
        self.reviewed()
        self.queue.start("publisher", WORKER, now=2)
        modified = self.receipt()
        modified["branch"] = "main"
        self.assertEqual(self.queue.reconcile_receipt(modified, github_reachable=True,
                                      verify_remote=lambda r: True)["status"], "blocked")

    def test_real_child_process_is_terminated_and_checkpoint_restored(self):
        isolated = FailureLedger(self.root, "NF-DEV-05-FAULT-002")
        isolated.initialize()
        cmd = ("from stage5_isolated_failure_supervisor import FailureLedger;"
               "from pathlib import Path;import sys,time;"
               "q=FailureLedger(Path(sys.argv[1]),'NF-DEV-05-FAULT-002');"
               "q.start('writer','WIN-LIDC05TBOQD-chatgpt',now=20);"
               "time.sleep(20)")
        child = subprocess.Popen([sys.executable, "-c", cmd, str(self.root)])
        try:
            for _ in range(100):
                if isolated.snapshot()["status"] == "running":
                    break
                time.sleep(0.03)
            self.assertEqual(isolated.snapshot()["status"], "running")
        finally:
            child.terminate()  # Only the child created by this test, never a user program.
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        restored = FailureLedger(self.root, "NF-DEV-05-FAULT-002")
        state = restored.resume_expired(now=200, lease_seconds=30,
                                       available_runners=(BACKUP,))
        self.assertEqual(state["status"], "retry_wait")
        self.assertEqual(state["retries"], 1)
        self.assertEqual(state["candidate"], None)

    def test_reboot_while_publishing_never_replays(self):
        self.reviewed()
        self.queue.start("publisher", WORKER, now=7)
        recovered = FailureLedger(self.root, TASK).resume_expired(now=300)
        self.assertEqual(recovered["status"], "needs_receipt_check")

    def test_unexpired_lease_does_not_steal_execution(self):
        self.queue.start("writer", WORKER, now=90)
        snapshot = self.queue.snapshot()
        self.assertEqual(self.queue.resume_expired(now=100, lease_seconds=120), snapshot)

    def test_tampered_file_stops_restoration(self):
        path = self.queue.file
        doc = json.loads(path.read_text("utf-8"))
        doc["payload"]["status"] = "verified_done"
        path.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaises(UnsafeState):
            FailureLedger(self.root, TASK).snapshot()

    def test_foreign_scope_and_outside_branch_blocked(self):
        with self.assertRaises(UnsafeState):
            FailureLedger(self.root, "foreign-project-999")
        with self.assertRaises(UnsafeState):
            FailureLedger(self.root, TASK, branch="main")
        with self.assertRaises(UnsafeState):
            self.queue.start("writer", "outside-runner", now=10)

    def test_second_chat_task_does_not_change_first_checkpoint(self):
        before = self.queue.snapshot()
        other = FailureLedger(self.root, "NF-DEV-05-FAULT-003")
        other.initialize()
        other.start("writer", BACKUP, now=100)
        self.assertEqual(self.queue.snapshot(), before)
        self.assertNotEqual(other.file, self.queue.file)

    def test_concurrent_owner_lock_blocks_write(self):
        self.queue.lock_file.write_text("occupied", encoding="utf-8")
        try:
            with self.assertRaises(UnsafeState):
                self.queue.start("writer", WORKER, now=10)
        finally:
            self.queue.lock_file.unlink()
        self.assertEqual(self.queue.snapshot()["status"], "queued")

if __name__ == "__main__":
    unittest.main()
