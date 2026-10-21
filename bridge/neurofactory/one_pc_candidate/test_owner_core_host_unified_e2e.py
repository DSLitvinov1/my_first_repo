"""One fixture end-to-end: persisted UI draft -> independently signed owner permit
-> real Git-validated CORE SQLite enqueue -> claim -> signed HOST test receipt
-> verified file readback and durable restart. NO SCM process or real Qwen in
this addressed test; those require their separate genuine Windows gates.
All effects are to disposable tempfile only; no model text is executed.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "development" / "core_owned"))
from one_task_core import OneTaskCore, CoreSafetyError, EMPTY_SHA
from local_workspace import WorkspaceStore, WorkspaceDenied
from signed_owner_admission import (
    prepare_draft_request, admit_signed_draft, AdmissionDenied, _canon,
)


def _git(directory, *args):
    return subprocess.run(["git", "-C", str(directory), *args],
                          check=True, text=True, capture_output=True, timeout=15).stdout.strip()


def _public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


class OneInstalledFlowContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nf-unified-trusted-cycle-")
        self.root = Path(self.tmp.name)
        self.repo = self.root / "git"
        self.repo.mkdir(mode=0o700)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.name", "NF isolated end to end")
        _git(self.repo, "config", "user.email", "test@example.invalid")
        (self.repo / "README.md").write_text("Single disposable Git commit\n", encoding="utf-8")
        _git(self.repo, "add", "README.md")
        _git(self.repo, "commit", "-qm", "isolated source")
        self.source_sha = _git(self.repo, "rev-parse", "HEAD")
        self.owner = Ed25519PrivateKey.generate()
        self.host_signer = Ed25519PrivateKey.generate()
        self.workspace = WorkspaceStore(self.root / "workspace")
        project = self.workspace.create_project({"name": "Disposable signed cycle", "description": ""})
        self.draft = self.workspace.create_task({
            "project_id": project["id"],
            "objective": "Write only a test receipt into the isolated protected output.",
            "model_preference": "qwen2.5-coder:1.5b",
        })
        self.proposal = b"Untrusted model text fixture: never execute or publish it.\n"
        self.workspace.reserve_task_proposal(self.draft["id"], "qwen2.5-coder:1.5b")
        self.workspace.finalize_task_proposal(self.draft["id"], {
            "status": "PROPOSED_UNVERIFIED",
            "model": "qwen2.5-coder:1.5b",
            "text": self.proposal.decode("utf-8"),
            "content_sha256": sha256(self.proposal).hexdigest(),
            "response_sha256": "e" * 64,
        })
        self.state = self.root / "core"
        self.state.mkdir(mode=0o700)
        self.out = self.root / "host"
        self.out.mkdir(mode=0o700)
        self.core = self._new_core()
        self.preview = prepare_draft_request(self.workspace, self.draft["id"])
        self.spec = {
            "schema": "neurofactory.core.task.v1",
            "task_id": "NF-DEV-05-Q954",
            "project_id": self.preview["core_project_id"],
            "target": "bridge/neurofactory/development/core_owned/windows_pilot.txt",
            "objective": self.draft["objective"],
            "source_sha": self.source_sha,
            "source_sha256": EMPTY_SHA,
            "approval_commit": self.source_sha,
            "model": "qwen2.5-coder:1.5b",
            "reserved_units": 10,
        }
        self.owner_now = int(time.time())
        self.host_data = b"NF_DISPOSABLE_SIGNED_HOST_FILE_TEST_ONLY\n"
        self.host_digest = sha256(self.host_data).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def _new_core(self):
        return OneTaskCore(self.state, self.repo, host_output_dir=self.out,
                           host_receipt_public_raw=_public(self.host_signer))

    def owner_permit(self):
        body = {
            "schema": "nf.onepc.owner_core_admission.v1",
            "scope": "OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION",
            "draft": self.preview,
            "spec": self.spec,
            "nonce": secrets.token_hex(16),
            "issued_at": self.owner_now - 1,
            "expires_at": self.owner_now + 180,
        }
        signature = self.owner.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00" + _canon(body))
        return {**body, "owner_signature": base64.b64encode(signature).decode("ascii")}

    def host_receipt(self, *, signer=None):
        body = {
            "schema": "neurofactory.windows.host_signed_test_receipt.v1",
            "task_id": self.spec["task_id"],
            "project_id": self.spec["project_id"],
            "source_sha40": self.spec["source_sha"],
            "target": self.spec["target"],
            "operation_id": "pilot-" + self.spec["task_id"],
            "content_sha256": self.host_digest,
            "status": "HOST_FILE_WRITTEN_TEST_ONLY",
        }
        signed = json.dumps(body, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":"), allow_nan=False).encode("utf-8")
        sig = (signer or self.host_signer).sign(b"NF_WINDOWS_HOST_RECEIPT_TEST_V1\x00" + signed)
        return {
            "schema": "neurofactory.core.host_checkpoint_test.v1",
            "signed": body,
            "signature_base64": base64.b64encode(sig).decode("ascii"),
            "host_key_sha256": sha256(_public(self.host_signer)).hexdigest(),
        }

    def admit(self):
        permit = self.owner_permit()
        observed = admit_signed_draft(
            self.workspace, self.core, permit,
            owner_public_raw=_public(self.owner), now=self.owner_now)
        self.assertEqual(observed["core_reported_state"], "QUEUED")
        self.assertFalse(observed["host_execution_allowed"])
        self.assertFalse(observed["production_release"])
        self.assertEqual(self.core.snapshot()["state"], "QUEUED")
        return permit

    def test_one_draft_signed_admission_signed_host_completion_restart(self):
        permit = self.admit()
        self.assertEqual(len(self.workspace.list_task_proposals()), 1)
        self.assertEqual(self.workspace.list_tasks()[0]["state"], "DRAFT_PENDING_OWNER_AUTH")
        claim = self.core.claim("isolated-host", now=1000, lease_seconds=100)
        with self.assertRaises(CoreSafetyError):
            self.core.claim("second-worker", now=1001)
        (self.out / "windows_pilot.txt").write_bytes(self.host_data)
        finished = self.core.finalize_signed_host_test(
            self.spec["task_id"], claim["token"], self.host_receipt(), now=1001)
        self.assertEqual(finished["state"], "HOST_CHECKPOINTED_TEST")
        self.assertEqual(finished["result_sha256"], self.host_digest)
        reopened = self._new_core()
        self.assertEqual(reopened.snapshot()["state"], "HOST_CHECKPOINTED_TEST")
        self.assertEqual(reopened.recover(now=9999)["state"], "HOST_CHECKPOINTED_TEST")
        self.assertEqual(reopened.snapshot()["attempts"], 1)
        with self.assertRaises(CoreSafetyError):
            reopened.finalize_signed_host_test(
                self.spec["task_id"], claim["token"], self.host_receipt(), now=1002)
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, reopened, permit,
                               owner_public_raw=_public(self.owner), now=self.owner_now)
        self.assertEqual(self.workspace.list_tasks()[0]["state"], "DRAFT_PENDING_OWNER_AUTH")
        self.assertEqual(self.workspace.list_task_proposals()[0]["status"], "PROPOSED_UNVERIFIED")
        print("NF_UI_DRAFT_OWNER_CORE_HOST_RESTART=PASS_DISPOSABLE_SIGNED_TEST_ONLY")

    def test_effect_without_signed_receipt_never_auto_retries(self):
        permit = self.admit()
        self.core.claim("isolated-host", now=1000, lease_seconds=20)
        (self.out / "windows_pilot.txt").write_bytes(self.host_data)
        self.assertEqual(self.core.recover(now=1021)["state"], "NEEDS_MANUAL_REVIEW")
        reopened = self._new_core()
        self.assertEqual(reopened.snapshot()["state"], "NEEDS_MANUAL_REVIEW")
        self.assertEqual(reopened.snapshot()["attempts"], 1)
        with self.assertRaises(CoreSafetyError):
            reopened.claim("replay-worker", now=1022)
        with self.assertRaises(AdmissionDenied):
            admit_signed_draft(self.workspace, reopened, permit,
                               owner_public_raw=_public(self.owner), now=self.owner_now)
        print("NF_UI_OWNER_CORE_HOST_UNKNOWN_EFFECT=NO_AUTOMATIC_RETRY")

    def test_host_signature_is_not_owner_signature_and_needs_actual_file(self):
        self.admit()
        claim = self.core.claim("isolated-host", now=1000, lease_seconds=100)
        with self.assertRaises(CoreSafetyError):
            self.core.finalize_signed_host_test(
                self.spec["task_id"], claim["token"], self.host_receipt(), now=1001)
        (self.out / "windows_pilot.txt").write_bytes(self.host_data)
        with self.assertRaises(CoreSafetyError):
            self.core.finalize_signed_host_test(
                self.spec["task_id"], claim["token"],
                self.host_receipt(signer=self.owner), now=1001)
        self.assertEqual(self.core.snapshot()["state"], "CLAIMED")
        print("NF_UI_OWNER_HOST_DISTINCT_SIGNING_KEY_AND_FILE=ENFORCED")


if __name__ == "__main__":
    unittest.main()
