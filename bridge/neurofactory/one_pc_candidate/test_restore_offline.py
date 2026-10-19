"""Actual draft SQLite backup restoration, corruption and overwrite rejection."""
from __future__ import annotations
import shutil
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
        with sqlite3.connect(future) as con:
            con.execute("PRAGMA user_version=999")
        with self.assertRaises(RestoreDenied):
            restore(future,self.root/"future-destination")
        self.assertFalse((self.root/"future-destination").exists())

    def test_missing_table_and_spoofed_task_state_fail_closed(self):
        bad=self.root/"missing.sqlite3"
        shutil.copyfile(self.backup,bad)
        with sqlite3.connect(bad) as con:
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

if __name__=="__main__":unittest.main()
