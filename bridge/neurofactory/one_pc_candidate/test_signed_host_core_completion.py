"""Integration-owned proof: genuine SQLite OneTaskCore closes one signed TEST HOST effect.
The host signature is generated synthetically by this test, NOT by a deployed SCM signer.
No Qwen, real user data, production queue or live authorization.
"""
from __future__ import annotations

import base64
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent / "development" / "core_owned"))
from one_task_core import OneTaskCore,CoreSafetyError,EMPTY_SHA

def git(folder,*arguments):
    r=subprocess.run(["git","-C",str(folder),*arguments],capture_output=True,
                     check=True,text=True,timeout=12)
    return r.stdout.strip()

class SignedHostCloseTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix="nf-host-core-finish-")
        root=Path(self.temporary.name)
        self.repo=root/"git"
        self.repo.mkdir()
        git(self.repo,"init","-q")
        git(self.repo,"config","user.name","NF isolated integration")
        git(self.repo,"config","user.email","test@example.invalid")
        (self.repo/"README.md").write_text("Synthetic project\n",encoding="utf-8")
        git(self.repo,"add","README.md")
        git(self.repo,"commit","-qm","synthetic source")
        commit=git(self.repo,"rev-parse","HEAD")
        self.out=root/"service-output"
        self.out.mkdir(mode=0o700)
        self.state=root/"core"
        self.state.mkdir(mode=0o700)
        self.signer=Ed25519PrivateKey.generate()
        self.pub=self.signer.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.spec={
            "schema":"neurofactory.core.task.v1",
            "task_id":"NF-DEV-05-Q951","project_id":"local-test",
            "target":"bridge/neurofactory/development/core_owned/windows_pilot.txt",
            "objective":"Create one harmless local file from approved service only.",
            "source_sha":commit,"source_sha256":EMPTY_SHA,
            "approval_commit":commit,"model":"qwen2.5-coder:1.5b",
            "reserved_units":10,
        }
        self.core=OneTaskCore(self.state,self.repo,host_output_dir=self.out,
                              host_receipt_public_raw=self.pub)
        self.core.enqueue(self.spec,trusted_approval_check=lambda x:x==self.spec)
        self.claim=self.core.claim("integration-worker",now=1000,lease_seconds=100)
        self.payload=b"NF_VERIFIED_ONE_PC_HOST_EFFECT_TEST_ONLY\n"
        self.digest=sha256(self.payload).hexdigest()

    def tearDown(self):
        self.temporary.cleanup()

    def signed(self,body=None, signer=None):
        if body is None:
            body={
                "schema":"neurofactory.windows.host_signed_test_receipt.v1",
                "task_id":self.spec["task_id"],
                "project_id":self.spec["project_id"],
                "source_sha40":self.spec["source_sha"],
                "target":self.spec["target"],
                "operation_id":"pilot-"+self.spec["task_id"],
                "content_sha256":self.digest,
                "status":"HOST_FILE_WRITTEN_TEST_ONLY",
            }
        raw=json.dumps(body,ensure_ascii=False,sort_keys=True,
                       separators=(",",":"),allow_nan=False).encode()
        sig=(signer or self.signer).sign(b"NF_WINDOWS_HOST_RECEIPT_TEST_V1\x00"+raw)
        return {
            "schema":"neurofactory.core.host_checkpoint_test.v1",
            "signed":copy.deepcopy(body),
            "signature_base64":base64.b64encode(sig).decode(),
            "host_key_sha256":sha256(self.pub).hexdigest(),
        }

    def proof(self,receipt=None,now=1001,token=None):
        return self.core.finalize_signed_host_test(
            self.spec["task_id"],self.claim["token"] if token is None else token,
            self.signed() if receipt is None else receipt,now=now)

    def test_signed_readback_finalizes_real_core_sqlite_and_restart(self):
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")
        (self.out/"windows_pilot.txt").write_bytes(self.payload)
        reply=self.proof()
        self.assertEqual(reply["state"],"HOST_CHECKPOINTED_TEST")
        self.assertEqual(reply["result_sha256"],self.digest)
        cold=OneTaskCore(self.state,self.repo,host_output_dir=self.out,
                         host_receipt_public_raw=self.pub)
        self.assertEqual(cold.snapshot()["state"],"HOST_CHECKPOINTED_TEST")
        self.assertEqual(cold.recover(now=999999)["state"],"HOST_CHECKPOINTED_TEST")
        with self.assertRaises(CoreSafetyError):
            self.proof()
        self.assertEqual(cold.snapshot()["attempts"],1)
        print("NF_ONEPC_CORE_DURABLE_HOST_CLOSE_AND_RESTART=PASS_TEST_ONLY")

    def test_forged_signature_cannot_finalize(self):
        (self.out/"windows_pilot.txt").write_bytes(self.payload)
        false=self.signed(signer=Ed25519PrivateKey.generate())
        with self.assertRaises(CoreSafetyError):
            self.proof(false)
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")

    def test_other_source_task_project_operation_and_content_denied(self):
        (self.out/"windows_pilot.txt").write_bytes(self.payload)
        body=self.signed()["signed"]
        changes={
            "source_sha40":"f"*40,
            "task_id":"NF-DEV-05-Q952",
            "project_id":"other-project",
            "operation_id":"other-operation",
            "content_sha256":"e"*64,
            "target":"bridge/neurofactory/development/core_owned/other.txt",
            "status":"LIVE_ALLOWED",
        }
        for key,value in changes.items():
            with self.subTest(key=key):
                bad=dict(body,**{key:value})
                with self.assertRaises(CoreSafetyError):
                    self.proof(self.signed(body=bad))
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")

    def test_no_completion_without_protected_file(self):
        with self.assertRaises(CoreSafetyError):
            self.proof()
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")

    def test_unchanged_signed_receipt_but_modified_output_denied(self):
        (self.out/"windows_pilot.txt").write_bytes(b"FORGED_CONTENT")
        with self.assertRaises(CoreSafetyError):
            self.proof()

    def test_expired_claim_and_wrong_token_denied(self):
        (self.out/"windows_pilot.txt").write_bytes(self.payload)
        with self.assertRaises(CoreSafetyError):
            self.proof(now=1100)
        with self.assertRaises(CoreSafetyError):
            self.proof(token="a"*64)
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")

    def test_unknown_crash_after_file_does_not_retry(self):
        (self.out/"windows_pilot.txt").write_bytes(self.payload)
        # Physical test file exists, but signed HOST receipt never arrived.
        self.assertEqual(self.core.recover(now=1100)["state"],
                         "NEEDS_MANUAL_REVIEW")
        with self.assertRaises(CoreSafetyError):
            self.proof(now=1101)
        self.assertEqual(self.core.snapshot()["attempts"],1)
        print("NF_ONEPC_UNKNOWN_EFFECT_NO_AUTOMATIC_RETRY=PASS_TEST_ONLY")

    def test_missing_externally_pinned_key_fails_closed_after_restart(self):
        (self.out/"windows_pilot.txt").write_bytes(self.payload)
        self.proof()
        unpinned=OneTaskCore(self.state,self.repo)
        with self.assertRaises(CoreSafetyError):
            unpinned.snapshot()
        badkey=Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        wrong=OneTaskCore(self.state,self.repo,host_output_dir=self.out,
                          host_receipt_public_raw=badkey)
        with self.assertRaises(CoreSafetyError):
            wrong.snapshot()

    def test_modified_completed_file_is_not_reported_success(self):
        (self.out/"windows_pilot.txt").write_bytes(self.payload)
        self.proof()
        (self.out/"windows_pilot.txt").write_bytes(b"tampered")
        with self.assertRaises(CoreSafetyError):
            self.core.snapshot()

    def test_legacy_local_token_writer_still_disabled(self):
        with self.assertRaises(CoreSafetyError):
            self.core.apply_offline_test(self.spec["task_id"],self.claim["token"],{})

if __name__=="__main__":
    unittest.main()
