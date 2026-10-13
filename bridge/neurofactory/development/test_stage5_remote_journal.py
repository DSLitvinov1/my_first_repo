"""Trusted GitHub journal transport is tested without network access or credentials."""
import base64
import copy
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import stage5_development_queue as tasks
import stage5_remote_journal as journal

ROOT=pathlib.Path(__file__).resolve().parent
PLAN=json.loads((ROOT/"roadmap.json").read_text("utf-8"))
JOBS=[
 {"id":"NF-DEV-05-Q001","target":"bridge/neurofactory/development/stage5_development_queue.py",
  "objective":"Guarantee serial task allocation with durable per-task state and no replay"},
 {"id":"NF-DEV-05-Q002","target":"bridge/neurofactory/development/stage5_remote_journal.py",
  "objective":"Synchronize approved task checkpoints to GitHub before external work"},
]

class FakeGitHub:
    def __init__(self):
        self.blob=None
        self.version=0
        self.writes=0
        self.fail=False
    def request(self,method,data=None):
        if method=="GET":
            if self.blob is None:return None
            return {"path":journal.FILE,"sha":str(self.version),
                    "content":base64.b64encode(self.blob).decode()}
        if method!="PUT":raise RuntimeError("Forbidden method")
        if self.fail:raise journal.RemoteJournalError("CAS conflict or transport failure")
        expected=str(self.version) if self.blob is not None else None
        if data.get("sha")!=expected:raise journal.RemoteJournalError("CAS mismatch")
        self.blob=base64.b64decode(data["content"])
        self.version+=1;self.writes+=1
        return {"content":{"sha":str(self.version)},"commit":{"sha":f"{self.version:040x}"}}

class JournalTests(unittest.TestCase):
    def setUp(self):
        self.remote=FakeGitHub()
        self.patcher=mock.patch.object(journal,"_request",side_effect=self.remote.request)
        self.patcher.start();self.addCleanup(self.patcher.stop)
        self.directory=tempfile.TemporaryDirectory(prefix="nf-stage5-journal-")
        self.addCleanup(self.directory.cleanup)
        self.queue=tasks.DevelopmentQueue(self.directory.name,copy.deepcopy(PLAN),JOBS)

    def test_init_claim_and_write_ahead_remote_state(self):
        coordinator=journal.DurableCoordinator(self.queue)
        coordinator.restore_if_exists()
        self.assertEqual(self.remote.writes,1)
        coordinator.claim(JOBS[0]["id"],"writer",100,10)
        self.assertEqual(self.remote.writes,2)
        checkpoint=journal.read()[0]
        doc=json.loads(checkpoint["body"]["files"]["nf-dev-05-q001-writer.json"])
        self.assertEqual(doc["data"]["state"],"running")
        coordinator.before_effect(JOBS[0]["id"],"writer",source_sha256="a"*64)
        self.assertEqual(self.remote.writes,3)
        checkpoint=journal.read()[0]
        doc=json.loads(checkpoint["body"]["files"]["nf-dev-05-q001-writer.json"])
        self.assertEqual(doc["data"]["state"],"publishing")

    def test_no_repeated_checkpoint_write_or_task_claim(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        self.assertEqual(journal.checkpoint_to_github(self.queue)["changed"],False)
        self.assertEqual(self.remote.writes,1)
        coord.claim(JOBS[0]["id"],"writer",100,10)
        with self.assertRaises(Exception):coord.claim(JOBS[0]["id"],"writer",101,10)
        self.assertEqual(self.remote.writes,2)

    def test_new_process_like_restore_matches_exact_remote_checkpoint(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        coord.claim(JOBS[0]["id"],"writer",100,10)
        with tempfile.TemporaryDirectory(prefix="nf-stage5-newrunner-") as newpath:
            recovered=tasks.DevelopmentQueue(newpath,PLAN,JOBS)
            second=journal.DurableCoordinator(recovered)
            self.assertTrue(second.restore_if_exists()["restored"])
            self.assertEqual(recovered.snapshot(),self.queue.snapshot())
            self.assertEqual(self.remote.writes,2)
            recovered.recover(120)
            journal.checkpoint_to_github(recovered)
            self.assertEqual(recovered.snapshot()[JOBS[0]["id"]]["writer"]["state"],"queued")

    def test_failed_remote_persistence_stops_prior_to_effect(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        self.remote.fail=True
        with self.assertRaises(journal.RemoteJournalError):
            coord.claim(JOBS[0]["id"],"writer",100,10)
        self.assertEqual(self.remote.writes,1)
        self.assertEqual(self.queue.snapshot()[JOBS[0]["id"]]["writer"]["state"],"running")

    def test_corrupted_remote_snapshot_rejected(self):
        coord=journal.DurableCoordinator(self.queue);coord.restore_if_exists()
        document=json.loads(self.remote.blob)
        document["body"]["chat_delivery"]="enabled"
        self.remote.blob=json.dumps(document).encode()
        with self.assertRaises(journal.RemoteJournalError):journal.read()

    def test_second_queue_identity_cannot_take_existing_journal(self):
        coord=journal.DurableCoordinator(self.queue);coord.restore_if_exists()
        diff=copy.deepcopy(JOBS);diff[1]["objective"]="Use a different approved source and do not silently overwrite queue identity"
        with tempfile.TemporaryDirectory() as p:
            another=tasks.DevelopmentQueue(p,PLAN,diff)
            another.prepare()
            with self.assertRaises(journal.RemoteJournalError):
                journal.checkpoint_to_github(another)

    def test_stale_queue_cannot_rewind_verified_remote_checkpoint(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        with tempfile.TemporaryDirectory(prefix="nf-stage5-old-state-") as dir_old:
            stale=tasks.DevelopmentQueue(dir_old,PLAN,JOBS)
            stale.restore_snapshot(self.queue.sealed_snapshot())
            coord.claim(JOBS[0]["id"],"writer",100,10)
            coord.before_effect(JOBS[0]["id"],"writer",source_sha256="a"*64)
            self.queue.acknowledge(JOBS[0]["id"],"writer","1"*40,
                                   verify_remote=lambda *args:True)
            journal.checkpoint_to_github(self.queue)
            old_count=self.remote.writes
            with self.assertRaises(journal.RemoteJournalError):
                journal.checkpoint_to_github(stale)
            self.assertEqual(self.remote.writes,old_count)

    def test_old_running_snapshot_cannot_undo_publishing_intent(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        coord.claim(JOBS[0]["id"],"writer",100,10)
        with tempfile.TemporaryDirectory(prefix="nf-stage5-unresolved-") as earlier_dir:
            earlier=tasks.DevelopmentQueue(earlier_dir,PLAN,JOBS)
            earlier.restore_snapshot(self.queue.sealed_snapshot())
            coord.before_effect(JOBS[0]["id"],"writer",source_sha256="a"*64)
            with self.assertRaises(journal.RemoteJournalError):
                journal.checkpoint_to_github(earlier)

    def test_recover_commits_remote_checkpoint_before_new_task(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        coord.claim(JOBS[0]["id"],"writer",100,10)
        remote_before=self.remote.writes
        recovered=coord.recover(120)
        self.assertGreater(self.remote.writes,remote_before)
        self.assertEqual(self.queue.snapshot()[JOBS[0]["id"]]["writer"]["state"],"queued")
        with tempfile.TemporaryDirectory(prefix="nf-stage5-following-run-") as next_dir:
            another=tasks.DevelopmentQueue(next_dir,PLAN,JOBS)
            journal.DurableCoordinator(another).restore_if_exists()
            self.assertEqual(another.snapshot(),self.queue.snapshot())
        before_repeat=self.remote.writes
        coord.recover(121)
        self.assertEqual(self.remote.writes,before_repeat)

    def test_old_runner_cannot_recover_over_newer_remote_state(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        with tempfile.TemporaryDirectory(prefix="nf-stage5-stale-runner-") as other_dir:
            stale=tasks.DevelopmentQueue(other_dir,PLAN,JOBS)
            journal.DurableCoordinator(stale).restore_if_exists()
            coord.claim(JOBS[0]["id"],"writer",100,10)
            count=self.remote.writes
            with self.assertRaises(journal.RemoteJournalError):
                journal.DurableCoordinator(stale).recover(120)
            self.assertEqual(self.remote.writes,count)

    def test_recovery_fails_closed_when_remote_commit_unavailable(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        coord.claim(JOBS[0]["id"],"writer",100,10)
        self.remote.fail=True
        with self.assertRaises(journal.RemoteJournalError):
            coord.recover(120)
        self.assertEqual(self.remote.writes,2)

    def test_independent_reviewer_alleged_attempt_rewind_is_rejected(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        stale=self.queue.sealed_snapshot()
        coord.claim(JOBS[0]["id"],"writer",100,10)
        newer=journal.read()[0]
        with self.assertRaises(journal.RemoteJournalError):
            journal._no_rewind(newer,stale)
        self.assertEqual(self.remote.writes,2)

    def test_independent_reviewer_alleged_renamed_task_is_rejected(self):
        coord=journal.DurableCoordinator(self.queue)
        coord.restore_if_exists()
        before=self.queue.sealed_snapshot()
        altered=copy.deepcopy(before)
        key="nf-dev-05-q001-writer.json"
        entry=json.loads(altered["body"]["files"][key])
        entry["data"]["id"]="NF-DEV-05-Q999-writer"
        altered["body"]["files"][key]=json.dumps(entry)
        with self.assertRaises(journal.RemoteJournalError):
            journal._no_rewind(before,altered)

    def test_invented_top_level_attempts_not_valid_remote_checkpoint(self):
        invented={"body":{"schema":1,"identity_sha256":"a1b2c3",
                 "attempts":3,"scope":"neurofactory_only",
                 "chat_delivery":"paused_by_user"},"sha256":"bad"}
        with self.assertRaises(journal.RemoteJournalError):
            journal._validate(invented)

    def test_external_write_requires_trusted_publisher_token(self):
        self.patcher.stop()
        try:
            with mock.patch.dict(os.environ,{},clear=True):
                with self.assertRaises(journal.RemoteJournalError):
                    journal._request("PUT",{"content":"not used"})
        finally:
            self.patcher.start()

if __name__=="__main__":
    unittest.main(verbosity=2)
