"""Isolated Windows installed-runtime contract for strict owner CORE9 -> HOST.

Local fixture deliberately substitutes a fake Linux reply. It tests the
CORE/owner/host file code path, never attests a physical Linux reservation,
actual Windows SCM identity or real Qwen inference.
"""
from __future__ import annotations

import base64
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/"development"/"core_owned"))
from one_task_core import (
    OneTaskCore, EMPTY_SHA, CoreSafetyError, provision_empty_core_queue_offline,
)
from local_workspace import WorkspaceStore
from signed_owner_admission import (
    prepare_draft_request,admit_signed_draft,_canon,
)
from personal_project_file_effect import (
    PROJECT_FILE_SCHEMA,PROJECT_FILE_ACTION,CORE_PERMISSION_SCHEMA,MAX_CONTENT,
    apply_approved_project_file,
)
from personal_ssh_highwater import _canon as host_canon
from personal_core9_host_bridge import (
    V2_SCHEMA,V2_DOMAIN,_verified_core9_body,CoreHostIntegrationDenied,
    CORE_TARGET,
)
from personal_windows_host_service import DDL


def git(directory,*args):
    return subprocess.run(
        ["git","-C",str(directory),*args],capture_output=True,
        check=True,text=True,timeout=12).stdout.strip()


class OwnerCore9PersonalCompletion(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-realcore9-bound-fixture-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.repo=self.root/"git"
        self.repo.mkdir()
        git(self.repo,"init","-q")
        git(self.repo,"config","user.name","NF scoped CORE9 CI")
        git(self.repo,"config","user.email","ci@example.invalid")
        (self.repo/"README.md").write_text("Pinned disposable source\n",encoding="utf-8")
        git(self.repo,"add","README.md")
        git(self.repo,"commit","-qm","pinned")
        self.source=git(self.repo,"rev-parse","HEAD")
        self.workspace=WorkspaceStore(self.root/"workspace")
        proj=self.workspace.create_project({
            "name":"Disposable Qwen CORE9 project","description":""})
        task=self.workspace.create_task({
            "project_id":proj["id"],
            "objective":"Safely save a bounded harmless Qwen text file without running any generated source.",
            "model_preference":"qwen3.5:9b",
        })
        self.uuid=task["id"]
        self.project=proj["id"]
        self.text="Qwen draft: file text ONLY, not executable.\n"
        self.digest=sha256(self.text.encode("utf-8")).hexdigest()
        self.workspace.reserve_task_proposal(self.uuid,"qwen3.5:9b")
        self.workspace.finalize_task_proposal(self.uuid,{
            "status":"PROPOSED_UNVERIFIED",
            "model":"qwen3.5:9b",
            "text":self.text,
            "content_sha256":self.digest,
            "response_sha256":"d"*64,
        })
        self.preview=prepare_draft_request(self.workspace,self.uuid)
        self.signer=Ed25519PrivateKey.generate()
        self.operator={
            "source_sha40":self.source,
            "machine_sha256":"a"*64,
            "package_sha256":"b"*64,
        }
        self.state=self.root/"core9"
        self.state.mkdir()
        provision_empty_core_queue_offline(self.state)
        self.core=OneTaskCore(self.state,self.repo)
        self.spec={
            "schema":"neurofactory.core.task.v1",
            "task_id":"NF-DEV-05-Q972",
            "project_id":self.preview["core_project_id"],
            "target":CORE_TARGET,
            "objective":task["objective"],
            "source_sha":self.source,
            "source_sha256":EMPTY_SHA,
            "model":"qwen3.5:9b",
            "reserved_units":100,
            "approval_commit":self.source,
        }
        now=int(time.time())
        core_data={
            "schema":"nf.onepc.owner_core_admission.v1",
            "scope":"OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION",
            "draft":self.preview,
            "spec":self.spec,
            "nonce":secrets.token_hex(16),
            "issued_at":now-1,
            "expires_at":now+180,
        }
        self.signed_core={
            **core_data,
            "owner_signature":base64.b64encode(
                self.signer.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00"+_canon(core_data))
            ).decode("ascii"),
        }
        permission={
            "schema":CORE_PERMISSION_SCHEMA,
            "task_id":self.uuid,"project_id":self.project,
            "model":"qwen3.5:9b","draft_sha256":self.digest,
            "operation":PROJECT_FILE_ACTION,
            "relative_path":"bounded-result.md",
            "content_sha256":self.digest,
            "max_bytes":MAX_CONTENT,"owner_reviewed":True,
        }
        original={
            "schema":PROJECT_FILE_SCHEMA,
            "task_id":self.uuid,"project_id":self.project,
            "nonce":secrets.token_hex(16),"external_epoch":3,
            "issued_unix":now,"expires_unix":now+75,
            "source_sha40":self.source,
            "machine_sha256":self.operator["machine_sha256"],
            "package_sha256":self.operator["package_sha256"],
            "operation":PROJECT_FILE_ACTION,
            "relative_path":"bounded-result.md",
            "text":self.text,
            "content_sha256":self.digest,
            "core_permission":permission,
        }
        v2={
            **original,"schema":V2_SCHEMA,
            "core_task_id":self.spec["task_id"],
            "core_spec_sha256":sha256(_canon(self.spec)).hexdigest(),
            "core_owner_permit":self.signed_core,
        }
        self.packet={
            **v2,
            "owner_signature_base64":base64.b64encode(
                self.signer.sign(V2_DOMAIN+host_canon(v2))).decode("ascii"),
        }
        self.projects=self.root/"projects"
        self.projects.mkdir()
        (self.projects/self.project).mkdir()
        self.file=self.projects/self.project/"bounded-result.md"
        self.fence=self.root/"intents.sqlite3"
        with closing(sqlite3.connect(self.fence)) as con:
            con.execute(DDL)
            con.commit()

    def test_real_sqlite_claim_and_anchored_personal_receipt(self):
        body,file_body,spec=_verified_core9_body(
            self.packet,self.operator,self.signer.public_key())
        self.assertEqual(spec,self.spec)
        self.assertEqual(file_body["text"],self.text)
        self.assertEqual(body["core_task_id"],self.spec["task_id"])
        admission=admit_signed_draft(
            self.workspace,self.core,self.signed_core,
            owner_public_raw=self.signer.public_key().public_bytes_raw())
        self.assertEqual(admission["core_reported_state"],"QUEUED")
        token=self.core.claim("personal-host-service",lease_seconds=120)
        result=apply_approved_project_file(
            signed_body=file_body,projects_root=self.projects)
        self.assertEqual(result["content_sha256"],self.digest)
        self.assertFalse(result["executed_generated_code"])
        head="e"*64
        with closing(sqlite3.connect(self.fence)) as con:
            con.execute(
                "INSERT INTO intents (task_id,nonce,external_epoch,"
                "operation_sha256,status,remote_head) "
                "VALUES(?,?,? ,?,'EXECUTED',?)",
                (self.uuid,"c"*32,3,"d"*64,head))
            con.commit()
        evidence={
            "schema":"nf.personal.core9.host_completion.v1",
            "core_task_id":self.spec["task_id"],
            "qwen_task_uuid":self.uuid,
            "project_uuid":self.project,
            "relative_path":"bounded-result.md",
            "content_sha256":self.digest,"external_epoch":3,
            "linux_ledger_head":head,"source_sha40":self.source,
            "linux_signature_checked":True,
            "generated_source_executed":False,
            "automatic_retry_allowed":False,
        }
        with self.assertRaises(CoreSafetyError):
            self.core.finalize_personal_host(
                self.spec["task_id"],token["token"],evidence,
                trusted_effect_readback=lambda x:False)
        completed=self.core.finalize_personal_host(
            self.spec["task_id"],token["token"],evidence,
            trusted_effect_readback=lambda x:(
                self.file.is_file()
                and sha256(self.file.read_bytes()).hexdigest()==self.digest))
        self.assertEqual(completed["state"],"HOST_CHECKPOINTED_PERSONAL")
        self.assertEqual(completed["attempts"],1)
        reopened=OneTaskCore(self.state,self.repo)
        self.assertTrue(reopened.verify_personal_host_result(
            protected_projects=self.projects,
            host_fence=self.fence,
            signed_remote_head={
                "epoch":3,"ledger_head":head,
                "remote_status_signature_verified":True,
            }))
        with self.assertRaises(CoreSafetyError):
            reopened.finalize_personal_host(
                self.spec["task_id"],token["token"],evidence,
                trusted_effect_readback=lambda x:True)
        with self.assertRaises(CoreSafetyError):
            reopened.claim("replay-worker")
        changed={**self.packet,"text":"attacker"}
        with self.assertRaises(CoreHostIntegrationDenied):
            _verified_core9_body(
                changed,self.operator,self.signer.public_key())
        self.assertEqual(len(list((self.projects/self.project).iterdir())),1)
        print("CORE9_QWEN_V2_PERSONAL_HOST_COMPLETED_NO_CODE_REPLAY_TEST=PASS")

    def test_missing_signed_core_or_no_queue_fails_closed(self):
        with self.assertRaises(CoreSafetyError):
            self.core.claim("worker-before-admission")
        for changed in (
            {**self.packet,"core_owner_permit":{}},
            {**self.packet,"core_task_id":"NF-DEV-05-Q100"},
            {**self.packet,"external_epoch":4},
        ):
            with self.subTest(key=changed.keys()):
                with self.assertRaises(CoreHostIntegrationDenied):
                    _verified_core9_body(changed,self.operator,
                                         self.signer.public_key())
        self.assertFalse(self.file.exists())
        print("CORE9_QWEN_NO_OWNER_OR_QUEUE_NO_EFFECT=PASS")


if __name__=="__main__":
    unittest.main()
