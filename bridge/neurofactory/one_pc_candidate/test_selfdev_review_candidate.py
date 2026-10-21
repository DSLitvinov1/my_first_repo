"""Only NEW review gate tests. No repeated Qwen inference, SCM, installer or old CI."""
from __future__ import annotations
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from selfdev_review_candidate import DOMAIN, SCOPE, SelfDevGateDenied, _canon, prepare_candidate

FILE = "bridge/neurofactory/one_pc_candidate/safe_increment.py"
QWEN_REPLY = "Original Qwen proposal must remain untrusted and NOT become program source."

def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          check=True, text=True, timeout=15).stdout.strip()

class SignedProposalToDraftPatch(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nf-signed-selfdev-test-")
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "NF Disposable Gate")
        git(self.repo, "config", "user.email", "ci@example.invalid")
        file = self.repo / FILE
        file.parent.mkdir(parents=True)
        self.before = b'def sample():\n    return "v1"\n'
        self.after = b'def sample():\n    return "v2"\n'
        file.write_bytes(self.before)
        git(self.repo, "add", "--", FILE)
        git(self.repo, "commit", "-qm", "pre-reviewed base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        file.write_bytes(self.after)
        git(self.repo, "add", "--", FILE)
        git(self.repo, "commit", "-qm", "separate human-reviewed change")
        self.reviewed = git(self.repo, "rev-parse", "HEAD")
        self.backup = self.root / "real-qwen-workspace.sqlite3"
        self.draft_id = "a" * 32
        self.project = "b" * 32
        with sqlite3.connect(self.backup) as db:
            db.executescript("""
                CREATE TABLE projects (id TEXT PRIMARY KEY);
                CREATE TABLE tasks (id TEXT PRIMARY KEY, project_id TEXT,
                    model_preference TEXT, state TEXT);
                CREATE TABLE task_proposals (task_id TEXT PRIMARY KEY, model TEXT,
                    status TEXT, content_sha256 TEXT, proposal_text TEXT);
                PRAGMA user_version=3;
            """)
            db.execute("INSERT INTO projects VALUES (?)", (self.project,))
            db.execute("INSERT INTO tasks VALUES (?,?,?,?)", (
                self.draft_id, self.project, "qwen2.5-coder:1.5b", "DRAFT_PENDING_OWNER_AUTH"))
            db.execute("INSERT INTO task_proposals VALUES (?,?,?,?,?)", (
                self.draft_id, "qwen2.5-coder:1.5b", "PROPOSED_UNVERIFIED",
                sha256(QWEN_REPLY.encode()).hexdigest(), QWEN_REPLY))
            db.commit()
        self.signer = Ed25519PrivateKey.generate()
        self.public = self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.now = int(time.time())
        self.descriptor = {
            "schema": "nf.selfdev.review_descriptor.v2",
            "base_sha": self.base, "reviewed_sha": self.reviewed,
            "draft_id": self.draft_id, "project_id": "p-" + self.project,
            "model": "qwen2.5-coder:1.5b",
            "proposal_sha256": sha256(QWEN_REPLY.encode()).hexdigest(),
            "changes": [{"path": FILE, "base_sha256": sha256(self.before).hexdigest(),
                         "reviewed_sha256": sha256(self.after).hexdigest()}],
        }
        self.env = patch.dict(os.environ, {
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "NF_SELFDEV_DISPOSABLE_CI": "1", "RUNNER_TEMP": str(self.root)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def permit(self, descriptor=None, signer=None, issued=None, expires=None):
        body = {
            "schema": "nf.selfdev.signed_review_candidate.v2",
            "scope": SCOPE,
            "descriptor": self.descriptor if descriptor is None else descriptor,
            "nonce": "c" * 32,
            "issued_at": self.now - 1 if issued is None else issued,
            "expires_at": self.now + 120 if expires is None else expires,
        }
        sig = (self.signer if signer is None else signer).sign(DOMAIN + _canon(body))
        return {**body, "signature": base64.b64encode(sig).decode()}

    def output(self):
        return self.root / "review"

    def test_valid_signed_patch_is_inert_and_original_clean(self):
        result = prepare_candidate(self.repo, self.backup, self.permit(),
                                   self.public, self.output(), now=self.now)
        self.assertEqual(result["status"], "SIGNED_CANDIDATE_PREPARED_NOT_TESTED_NOT_PUBLISHED")
        for flag in ("source_executed", "source_published", "production_authorized",
                     "core_queue_or_host_effect_enabled"):
            self.assertFalse(result[flag])
        exported = (self.output() / "review_only.patch").read_bytes()
        self.assertIn(b'+    return "v2"', exported)
        self.assertNotIn(QWEN_REPLY.encode(), exported)
        self.assertEqual(result["patch_sha256"], sha256(exported).hexdigest())
        self.assertEqual(json.loads((self.output() / "manifest.json").read_text()), result)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.reviewed)
        self.assertEqual(len(git(self.repo, "worktree", "list").splitlines()), 1)
        print("NF_SELFDEV_NEW_QWEN_SIGNED_REVIEW_PATCH=PASS_DRAFT_NOT_APPLIED")

    def test_fake_owner_and_changed_signed_scope_refused(self):
        with self.assertRaises(SelfDevGateDenied):
            prepare_candidate(self.repo, self.backup,
                              self.permit(signer=Ed25519PrivateKey.generate()),
                              self.public, self.output(), now=self.now)
        mutated = self.permit()
        mutated["descriptor"] = {**self.descriptor, "proposal_sha256": "0" * 64}
        with self.assertRaises(SelfDevGateDenied):
            prepare_candidate(self.repo, self.backup, mutated,
                              self.public, self.output(), now=self.now)
        self.assertFalse(self.output().exists())

    def test_expired_or_not_ephemeral_ci_refused(self):
        with self.assertRaises(SelfDevGateDenied):
            prepare_candidate(self.repo, self.backup,
                              self.permit(issued=self.now-500, expires=self.now-400),
                              self.public, self.output(), now=self.now)
        with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}):
            with self.assertRaises(SelfDevGateDenied):
                prepare_candidate(self.repo, self.backup, self.permit(),
                                  self.public, self.output(), now=self.now)
        self.assertEqual(len(git(self.repo, "worktree", "list").splitlines()), 1)

    def test_altered_model_evidence_never_becomes_code(self):
        with sqlite3.connect(self.backup) as db:
            db.execute("UPDATE task_proposals SET proposal_text=?", ("FORGED_QWEN",))
            db.commit()
        with self.assertRaises(SelfDevGateDenied):
            prepare_candidate(self.repo, self.backup, self.permit(),
                              self.public, self.output(), now=self.now)

    def test_privileged_paths_symlink_and_traversal_denied(self):
        for path in ("bridge/neurofactory/trusted_host/windows_scm_ci_worker.py",
                     "../../Windows/System32/evil.py", ".github/workflows/live.yml"):
            desc = {**self.descriptor, "changes": [{
                **self.descriptor["changes"][0], "path": path}]}
            with self.subTest(path=path), self.assertRaises(SelfDevGateDenied):
                prepare_candidate(self.repo, self.backup, self.permit(desc),
                                  self.public, self.output(), now=self.now)
        self.assertFalse(self.output().exists())

    def test_another_commit_outside_signed_scope_denied(self):
        extra = self.repo / "bridge/neurofactory/one_pc_candidate/other.py"
        extra.write_text("out_of_scope = True\n")
        git(self.repo, "add", "--", str(extra.relative_to(self.repo)))
        git(self.repo, "commit", "-qm", "unexpected separate commit")
        with self.assertRaises(SelfDevGateDenied):
            prepare_candidate(self.repo, self.backup, self.permit(),
                              self.public, self.output(), now=self.now)
        self.assertFalse(self.output().exists())

    def test_existing_review_package_must_not_be_overwritten(self):
        prepare_candidate(self.repo, self.backup, self.permit(),
                          self.public, self.output(), now=self.now)
        before = (self.output() / "review_only.patch").read_bytes()
        with self.assertRaises(SelfDevGateDenied):
            prepare_candidate(self.repo, self.backup, self.permit(),
                              self.public, self.output(), now=self.now)
        self.assertEqual((self.output() / "review_only.patch").read_bytes(), before)

if __name__ == "__main__":
    unittest.main()
