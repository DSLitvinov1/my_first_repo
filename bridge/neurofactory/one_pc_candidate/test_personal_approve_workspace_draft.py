"""Single focused Windows regression: Qwen draft -> OWNER review, never auto-sign."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import sqlite3
import tempfile
import unittest

from personal_approve_workspace_draft import (
    DraftOwnerApprovalDenied, owner_approvable_saved_draft,
    approve_interactively,
)

class PersonalDraftReadOnlyAcceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nf-owner-draft-ci-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "workspace.sqlite3"
        self.task_id = "a" * 32
        self.project_id = "b" * 32
        self.text = "Предложение: разработать сайт, форму заявок и подключить CRM."
        self.digest = sha256(self.text.encode("utf-8")).hexdigest()
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE projects(id TEXT PRIMARY KEY,name TEXT NOT NULL)")
            conn.execute("CREATE TABLE tasks("
                         "id TEXT PRIMARY KEY,project_id TEXT,"
                         "objective TEXT,state TEXT)")
            conn.execute("CREATE TABLE task_proposals("
                         "task_id TEXT PRIMARY KEY,model TEXT,status TEXT,"
                         "proposal_text TEXT,content_sha256 TEXT)")
            conn.execute("INSERT INTO projects VALUES(?,?)",
                         (self.project_id, "НЕЙРОЗАВОД"))
            conn.execute("INSERT INTO tasks VALUES(?,?,?,?)",
                         (self.task_id,self.project_id,
                          "Напиши краткое деловое коммерческое предложение.",
                          "DRAFT_PENDING_OWNER_AUTH"))
            conn.execute("INSERT INTO task_proposals VALUES(?,?,?,?,?)",
                         (self.task_id,"qwen2.5-coder:1.5b",
                          "PROPOSED_UNVERIFIED",self.text,self.digest))
            conn.commit()

    def alter(self,sql,value):
        with sqlite3.connect(self.db) as conn:
            conn.execute(sql,(value,))
            conn.commit()

    def test_recovered_qwen_draft_has_exact_project_and_sha256(self):
        draft = owner_approvable_saved_draft(self.root,self.task_id)
        self.assertEqual(draft["task_id"],self.task_id)
        self.assertEqual(draft["project_id"],self.project_id)
        self.assertEqual(draft["text"],self.text)
        self.assertEqual(draft["text_sha256"],self.digest)

    def test_corrupt_model_content_hash_denied_without_signing(self):
        self.alter("UPDATE task_proposals SET content_sha256=?","0"*64)
        with self.assertRaises(DraftOwnerApprovalDenied):
            owner_approvable_saved_draft(self.root,self.task_id)

    def test_non_qwen_or_unknown_denied(self):
        self.alter("UPDATE task_proposals SET model=?","another-model")
        with self.assertRaises(DraftOwnerApprovalDenied):
            owner_approvable_saved_draft(self.root,self.task_id)

    def test_non_interactive_owner_approval_not_possible(self):
        # GitHub Actions is never a substitute for a real human's input.
        with self.assertRaises(DraftOwnerApprovalDenied):
            approve_interactively(self.root,self.root,self.task_id,1)
        self.assertFalse((self.root / "personal-owner-private.key").exists())
        self.assertFalse((self.root / "inbox").exists())

if __name__ == "__main__":
    unittest.main()
