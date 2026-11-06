"""Windows CI: two distinct owner Ed25519 signatures, real CORE SQLite queue,
and physical file permit bind exactly, with ZERO host execution authority.
"""
from __future__ import annotations

import base64
import copy
from hashlib import sha256
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0,str(Path(__file__).resolve().parent.parent/"development"/"core_owned"))
from one_task_core import (
    OneTaskCore, CoreSafetyError, EMPTY_SHA, provision_empty_core_queue_offline,
)
from local_workspace import WorkspaceStore
from signed_owner_admission import (
    prepare_draft_request, admit_signed_draft, _canon,
)
from personal_project_file_effect import (
    OWNER_FILE_DOMAIN, PROJECT_FILE_SCHEMA, PROJECT_FILE_ACTION,
    CORE_PERMISSION_SCHEMA, MAX_CONTENT,
)
from owner_core_qwen_claim_binding import (
    check_signed_personal_core_claim, CoreQwenBindingDenied,
)


def git(root,*args):
    return subprocess.run(["git","-C",str(root),*args],check=True,
                          capture_output=True,text=True,timeout=12).stdout.strip()


def public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)


class OwnerCoreQwenClaimBindingWindows(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="nf-owner-core-qwen-binding-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        repo=self.root/"git"
        repo.mkdir()
        git(repo,"init","-q")
        git(repo,"config","user.name","NF bounded Qwen binding CI")
        git(repo,"config","user.email","ci@example.invalid")
        (repo/"README.md").write_text("Pinned temporary source commit\n",
                                       encoding="utf-8")
        git(repo,"add","README.md")
        git(repo,"commit","-qm","bounded temporary source")
        self.source=git(repo,"rev-parse","HEAD")
        self.workspace=WorkspaceStore(self.root/"workspace")
        project=self.workspace.create_project({
            "name":"Isolated signed owner CORE gate","description":""})
        self.task=self.workspace.create_task({
            "project_id":project["id"],
            "objective":"Create one reviewed harmless Qwen text file only after verifying the actual CORE lease.",
            "model_preference":"qwen3.5:9b",
        })
        self.text="Only one harmless Qwen text file in a protected project.\n"
        self.digest=sha256(self.text.encode("utf-8")).hexdigest()
        self.workspace.reserve_task_proposal(self.task["id"],"qwen3.5:9b")
        self.workspace.finalize_task_proposal(self.task["id"],{
            "status":"PROPOSED_UNVERIFIED","model":"qwen3.5:9b",
            "text":self.text,"content_sha256":self.digest,
            "response_sha256":"f"*64,
        })
        self.owner=Ed25519PrivateKey.generate()
        self.operator={
            "source_sha40":self.source,
            "machine_sha256":"d"*64,
            "package_sha256":"e"*64,
        }
        self.core_root=self.root/"core"
        self.core_root.mkdir()
        provision_empty_core_queue_offline(self.core_root)
        self.core=OneTaskCore(self.core_root,repo)
        self.preview=prepare_draft_request(self.workspace,self.task["id"])
        self.spec={
            "schema":"neurofactory.core.task.v1",
            "task_id":"NF-DEV-05-Q956",
            "project_id":self.preview["core_project_id"],
            "target":"bridge/neurofactory/development/core_owned/windows_pilot.txt",
            "objective":self.task["objective"],
            "source_sha":self.source,"source_sha256":EMPTY_SHA,
            "approval_commit":self.source,
            "model":"qwen3.5:9b","reserved_units":10,
        }
        now=int(time.time())
        body={
            "schema":"nf.onepc.owner_core_admission.v1",
            "scope":"OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION",
            "draft":self.preview,"spec":self.spec,"nonce":secrets.token_hex(16),
            "issued_at":now-1,"expires_at":now+240,
        }
        self.permit={**body,"owner_signature":base64.b64encode(
            self.owner.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00"+_canon(body))
        ).decode("ascii")}
        file_body={
            "schema":PROJECT_FILE_SCHEMA,
            "task_id":self.task["id"],"project_id":project["id"],
            "nonce":secrets.token_hex(16),"external_epoch":2,
            "issued_unix":now-1,"expires_unix":now+75,
            "source_sha40":self.source,
            "machine_sha256":self.operator["machine_sha256"],
            "package_sha256":self.operator["package_sha256"],
            "operation":PROJECT_FILE_ACTION,
            "relative_path":"reviewed-note.md",
            "text":self.text,"content_sha256":self.digest,
            "core_permission":{
                "schema":CORE_PERMISSION_SCHEMA,
                "task_id":self.task["id"],"project_id":project["id"],
                "model":"qwen3.5:9b","draft_sha256":self.digest,
                "operation":PROJECT_FILE_ACTION,
                "relative_path":"reviewed-note.md",
                "content_sha256":self.digest,
                "max_bytes":MAX_CONTENT,"owner_reviewed":True,
            },
        }
        self.file_packet={
            **file_body,
            "owner_signature_base64":base64.b64encode(
                self.owner.sign(OWNER_FILE_DOMAIN+_canon(file_body))
            ).decode("ascii"),
        }
        self.original_repo=repo

    def verify(self,**overrides):
        params={
            "workspace_dir":self.root/"workspace",
            "protected_core_state":self.core_root/"state",
            "file_packet":self.file_packet,
            "core_owner_permit":self.permit,
            "owner_public_raw":public(self.owner),
            "expected_operator":self.operator,
            "expected_core_worker":"protected-personal-host",
        }
        params.update(overrides)
        return check_signed_personal_core_claim(**params)

    def test_bound_once_without_authorizing_host_effect(self):
        # Queue must exist and be CLAIMED; QUEUED alone is NEVER enough.
        admitted=admit_signed_draft(
            self.workspace,self.core,self.permit,
            owner_public_raw=public(self.owner))
        self.assertEqual(admitted["core_reported_state"],"QUEUED")
        with self.assertRaises(CoreQwenBindingDenied):
            self.verify()
        now=int(time.time())
        claim=self.core.claim("protected-personal-host",now=now,lease_seconds=180)
        result=self.verify()
        self.assertEqual(result["qwen_task_uuid"],self.task["id"])
        self.assertEqual(result["model"],"qwen3.5:9b")
        self.assertEqual(result["content_sha256"],self.digest)
        self.assertTrue(result["signed_owner_core_admission_verified"])
        self.assertTrue(result["signed_owner_file_permission_verified"])
        self.assertFalse(result["execution_allowed"])
        self.assertFalse(result["external_witness_reserved"])
        self.assertFalse(result["recipient_atomic_completion_proven"])
        self.assertFalse(result["automatic_retry_allowed"])
        # Tampering either of the two independently signed envelopes fails.
        changed=copy.deepcopy(self.file_packet)
        changed["text"]="MODEL TRIED TO CHANGE CONTENT"
        with self.assertRaises(CoreQwenBindingDenied):
            self.verify(file_packet=changed)
        changed=copy.deepcopy(self.permit)
        changed["spec"]["model"]="qwen2.5-coder:1.5b"
        with self.assertRaises(CoreQwenBindingDenied):
            self.verify(core_owner_permit=changed)
        with self.assertRaises(CoreQwenBindingDenied):
            self.verify(owner_public_raw=public(Ed25519PrivateKey.generate()))
        with self.assertRaises(CoreQwenBindingDenied):
            self.verify(expected_core_worker="foreign-worker")
        with self.assertRaises(CoreSafetyError):
            self.core.apply_offline_test(self.spec["task_id"],claim["token"],{})
        self.assertEqual(self.core.recover(now=now+181)["state"],
                         "NEEDS_MANUAL_REVIEW")
        with self.assertRaises(CoreQwenBindingDenied):
            self.verify()
        self.assertEqual(list((self.core_root/"sandbox").iterdir()),[])
        print("NF_PERSONAL_SIGNED_OWNER_QWEN_CORE_CLAIM_BINDING=PASS_NO_OS_EFFECT")


if __name__=="__main__":
    unittest.main()
