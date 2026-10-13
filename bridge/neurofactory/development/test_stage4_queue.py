"""Isolated Stage 4 queue integration tests; no external requests or user processes."""
import copy
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import stage4_queue as st

HERE = pathlib.Path(__file__).resolve().parent
PLAN = json.loads((HERE / "roadmap.json").read_text("utf-8"))


class Stage4QueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nf-stage4-roles-")
        self.addCleanup(self.tmp.cleanup)
        self.queue = st.Stage4Queue(self.tmp.name, copy.deepcopy(PLAN))
        self.queue.prepare()

    def complete(self, role, sha, **kwargs):
        self.queue.claim(role, 100, 10)
        self.queue.before_external_effect(role, **kwargs)
        return self.queue.acknowledge(role, sha, remote_verified=True)

    def test_prepare_twice_keeps_identity(self):
        before = self.queue.prepare()
        self.assertEqual(set(before), {"writer", "reviewer", "publisher"})
        self.assertEqual(before["writer"]["attempts"], 0)
        self.assertEqual(self.queue.prepare(), before)

    def test_reviewer_and_publisher_cannot_claim_early(self):
        with self.assertRaises(st.Stage4Error):
            self.queue.claim("reviewer", 100)
        with self.assertRaises(st.Stage4Error):
            self.queue.claim("publisher", 100)

    def test_claim_durable_before_execution_and_duplicate_denied(self):
        self.queue.claim("writer", 100, 10)
        self.assertEqual(self.queue.prepare()["writer"]["state"], "running")
        with self.assertRaises(st.Stage4Error):
            self.queue.claim("writer", 101, 10)
        self.assertEqual(self.queue.recover(105)["writer"]["state"], "running")

    def test_real_process_death_replays_only_expired_unpublished_work(self):
        child = """
import os,sys,json
import stage4_queue as st
from pathlib import Path
plan=json.loads((Path(st.__file__).parent/'roadmap.json').read_text('utf-8'))
queue=st.Stage4Queue(sys.argv[1],plan)
queue.claim('writer',100,10)
os._exit(73)
"""
        done = subprocess.run([sys.executable, "-c", child, self.tmp.name],
                              env=os.environ.copy(), timeout=12)
        self.assertEqual(done.returncode, 73)
        self.assertEqual(self.queue.prepare()["writer"]["attempts"], 1)
        self.assertEqual(self.queue.recover(120)["writer"]["state"], "queued")
        self.assertEqual(self.queue.claim("writer", 121, 10)["attempts"], 2)

    def test_real_process_death_during_publication_never_resends(self):
        child = """
import os,sys,json
import stage4_queue as st
from pathlib import Path
plan=json.loads((Path(st.__file__).parent/'roadmap.json').read_text('utf-8'))
queue=st.Stage4Queue(sys.argv[1],plan)
queue.claim('writer',100,10)
queue.before_external_effect('writer',source_sha256='f'*64)
os._exit(74)
"""
        result = subprocess.run([sys.executable, "-c", child, self.tmp.name],
                                env=os.environ.copy(), timeout=12)
        self.assertEqual(result.returncode, 74)
        self.assertEqual(self.queue.recover(120)["writer"]["state"], "needs_receipt_check")
        with self.assertRaises(st.Stage4Error):
            self.queue.claim("writer", 200)
        with self.assertRaises(st.Stage4Error):
            self.queue.acknowledge("writer", "b"*40, remote_verified=False)
        self.assertEqual(self.queue.acknowledge("writer", "b"*40, remote_verified=True)["state"], "verified_done")
        with self.assertRaises(st.Stage4Error):
            self.queue.acknowledge("writer", "b"*40, remote_verified=True)

    def test_exact_writer_and_independent_reviewer_then_publisher(self):
        self.complete("writer", "a"*40, source_sha256="f"*64)
        with self.assertRaises(st.Stage4Error):
            self.queue.claim("writer", 160)
        self.queue.claim("reviewer", 100, 10)
        with self.assertRaises(st.Stage4Error):
            self.queue.before_external_effect("reviewer", source_sha256="e"*64, verdict="REVIEW_OK")
        with self.assertRaises(st.Stage4Error):
            self.queue.before_external_effect("reviewer", source_sha256="f"*64, verdict="REVIEW_BAD")
        self.queue.before_external_effect("reviewer", source_sha256="f"*64, verdict="REVIEW_OK")
        with self.assertRaises(st.Stage4Error):
            self.queue.claim("publisher", 105)
        self.queue.acknowledge("reviewer", "b"*40, remote_verified=True)
        self.complete("publisher", "c"*40)
        self.assertEqual(set(t["state"] for t in self.queue.recover(10**6).values()), {"verified_done"})

    def test_retry_cap_without_repeat(self):
        self.queue.claim("writer", 100, 10)
        self.assertEqual(self.queue.recover(120)["writer"]["state"], "queued")
        self.queue.claim("writer", 121, 10)
        self.assertEqual(self.queue.recover(140)["writer"]["state"], "retry_exhausted")
        with self.assertRaises(st.Stage4Error):
            self.queue.claim("writer", 150, 10)

    def test_modified_checkpoint_denied(self):
        p = self.queue.paths["writer"]
        raw = json.loads(p.read_text("utf-8"))
        raw["data"]["actor"] = "qwen3:4b"
        p.write_text(json.dumps(raw), "utf-8")
        with self.assertRaises(st.checkpoint.CheckpointError):
            self.queue.prepare()

    def test_publisher_write_ahead_intent_is_not_a_completion_receipt(self):
        self.complete("writer", "a"*40, source_sha256="f"*64)
        self.complete("reviewer", "b"*40, source_sha256="f"*64, verdict="REVIEW_OK")
        self.queue.claim("publisher", 100, 10)
        state = self.queue.before_external_effect("publisher")
        self.assertEqual(state["state"], "publishing")
        self.assertNotIn("publication_sha", state)
        with self.assertRaises(st.Stage4Error):
            self.queue.acknowledge("publisher", "c"*40, remote_verified=False)
        self.assertEqual(self.queue.recover(999)["publisher"]["state"], "needs_receipt_check")
        with self.assertRaises(st.Stage4Error):
            self.queue.claim("publisher", 1000, 10)
        self.assertEqual(self.queue.acknowledge("publisher", "c"*40,
                                               remote_verified=True)["state"], "verified_done")
        with self.assertRaises(st.Stage4Error):
            self.queue.acknowledge("publisher", "c"*40, remote_verified=True)

    def test_forbids_resuming_chat_delivery(self):
        unsafe = copy.deepcopy(PLAN)
        unsafe["chat_delivery_paused"] = False
        with self.assertRaises(Exception):
            st.Stage4Queue(self.tmp.name, unsafe)

    def test_writer_must_save_digest_before_remote_side_effect(self):
        self.queue.claim("writer", 100, 10)
        with self.assertRaises(st.Stage4Error):
            self.queue.before_external_effect("writer")
        with self.assertRaises(st.Stage4Error):
            self.queue.before_external_effect("writer",source_sha256="bad")
        self.assertEqual(self.queue.prepare()["writer"]["state"], "running")
        self.assertEqual(self.queue.before_external_effect("writer",source_sha256="f"*64)["state"], "publishing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
