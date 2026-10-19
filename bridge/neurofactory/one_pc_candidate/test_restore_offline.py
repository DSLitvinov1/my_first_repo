"""Actual draft SQLite backup restoration, corruption and overwrite rejection."""
from __future__ import annotations
import shutil
from hashlib import sha256
from contextlib import closing
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from local_workspace import WorkspaceStore
from restore_offline import RestoreDenied,restore

class OfflineRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory(prefix="nf-onepc-restore-test-")
        self.root=Path(self.tmp.name)
        self.store=WorkspaceStore(self.root/"original")
        self.project=self.store.create_project({
            "name":"Stored project","description":"persisted"})
        self.task=self.store.create_task({
            "project_id":self.project["id"],
            "objective":"Create harmless explanatory text only, without file operations.",
            "model_preference":"auto"})
        info=self.store.backup()
        self.backup=self.store.directory/"backups"/info["filename"]
    def tearDown(self):self.tmp.cleanup()

    def test_backup_restores_data_draft_only_and_survives_reopen(self):
        path=self.root/"recovered-new"
        result=restore(self.backup,path)
        self.assertEqual(result["state"],"RESTORED_DRAFT_DATA_ONLY")
        self.assertIs(result["live_execution_allowed"],False)
        restored=WorkspaceStore(path)
        self.assertEqual(restored.list_projects()[0]["id"],self.project["id"])
        self.assertEqual(restored.list_tasks()[0]["id"],self.task["id"])
        self.assertEqual(restored.list_tasks()[0]["state"],"DRAFT_PENDING_OWNER_AUTH")
        self.assertFalse(restored.diag()["real_core_dispatch_enabled"])
        with self.assertRaises(RestoreDenied):
            restore(self.backup,path)
        print("NF_ONEPC_SQLITE_RESTORE_NEW_DIRECTORY=PASS_DRAFT_ONLY")

    def test_corrupted_and_future_schema_fail_without_creating_destination(self):
        damaged=self.root/"invalid.sqlite3"
        damaged.write_bytes(b"not a valid SQLite database")
        with self.assertRaises((RestoreDenied,sqlite3.DatabaseError)):
            restore(damaged,self.root/"invalid-destination")
        self.assertFalse((self.root/"invalid-destination").exists())
        future=self.root/"future.sqlite3"
        shutil.copyfile(self.backup,future)
        with closing(sqlite3.connect(future)) as con:
            con.execute("PRAGMA user_version=999")
        with self.assertRaises(RestoreDenied):
            restore(future,self.root/"future-destination")
        self.assertFalse((self.root/"future-destination").exists())

    def test_missing_table_and_spoofed_task_state_fail_closed(self):
        bad=self.root/"missing.sqlite3"
        shutil.copyfile(self.backup,bad)
        with closing(sqlite3.connect(bad)) as con:
            con.execute("DROP TABLE model_checks")
        with self.assertRaises(RestoreDenied):
            restore(bad,self.root/"missing-destination")
        self.assertFalse((self.root/"missing-destination").exists())

    def test_never_overwrite_existing_workspace_or_linked_backup(self):
        with self.assertRaises(RestoreDenied):
            restore(self.backup,self.store.directory)
        self.assertEqual(self.store.list_tasks()[0]["id"],self.task["id"])
        linked=self.root/"linked.sqlite3"
        try:
            linked.symlink_to(self.backup)
        except (OSError,NotImplementedError):
            return
        with self.assertRaises(RestoreDenied):
            restore(linked,self.root/"linked-destination")
        self.assertFalse((self.root/"linked-destination").exists())

    def test_draft_qwen_proposal_recovery_checks_original_content_hash(self):
        self.store.reserve_task_proposal(self.task["id"],"qwen3:0.6b")
        text="Only an untrusted model text proposal. TEST FIXTURE."
        self.store.finalize_task_proposal(self.task["id"],{
            "status":"PROPOSED_UNVERIFIED","model":"qwen3:0.6b","text":text,
            "content_sha256":sha256(text.encode()).hexdigest(),
            "response_sha256":"a"*64})
        info=self.store.backup()
        real_backup=self.store.directory/"backups"/info["filename"]
        destination=self.root/"recovered-with-text-proposal"
        restore(real_backup,destination)
        reopened=WorkspaceStore(destination)
        proposals=reopened.list_task_proposals()
        self.assertEqual(len(proposals),1)
        self.assertEqual(proposals[0]["text"],text)
        self.assertEqual(reopened.list_tasks()[0]["state"],"DRAFT_PENDING_OWNER_AUTH")
        self.assertFalse(reopened.diag()["real_core_dispatch_enabled"])
        tampered=self.root/"tampered-proposal.sqlite3"
        shutil.copyfile(real_backup,tampered)
        with closing(sqlite3.connect(tampered)) as con:
            con.execute("UPDATE task_proposals SET proposal_text='forged' WHERE task_id=?",
                        (self.task["id"],))
            con.commit()
        with self.assertRaises(RestoreDenied):
            restore(tampered,self.root/"tampered-proposal-destination")
        self.assertFalse((self.root/"tampered-proposal-destination").exists())

    def test_restore_older_v2_draft_backup_and_migrate_safely(self):
        old=self.root/"legacy-v2.sqlite3"
        shutil.copyfile(self.backup,old)
        with closing(sqlite3.connect(old)) as con:
            con.execute("DROP TABLE task_proposals")
            con.execute("PRAGMA user_version=2")
        destination=self.root/"legacy-restored-new"
        restore(old,destination)
        reopened=WorkspaceStore(destination)
        self.assertEqual(reopened.list_tasks()[0]["id"],self.task["id"])
        self.assertEqual(reopened.list_task_proposals(),[])
        with reopened.connect() as con:
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0],3)

    def test_interrupted_proposal_backup_never_retries_model(self):
        self.store.reserve_task_proposal(self.task["id"],"qwen3:0.6b")
        info=self.store.backup()
        backed=self.store.directory/"backups"/info["filename"]
        dest=self.root/"inflight-restored"
        restore(backed,dest)
        reopened=WorkspaceStore(dest)
        self.assertEqual(reopened.recover_unknown_proposals(),1)
        self.assertEqual(reopened.list_task_proposals()[0]["status"],"UNKNOWN")
        from local_workspace import WorkspaceDenied
        with self.assertRaises(WorkspaceDenied):
            reopened.reserve_task_proposal(self.task["id"],"qwen3:0.6b")
        self.assertFalse(reopened.diag()["real_core_dispatch_enabled"])

if __name__=="__main__":unittest.main()
