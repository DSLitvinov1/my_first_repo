"""Disposable Windows-only full personal HOST/CORE9 service dispatch test.

The signed Linux reply is deliberately SIMULATED, and the paths and private
keys are generated under an ephemeral temp directory. Never production proof
of an external Linux epoch or physical restricted SCM process.
"""
from __future__ import annotations

from contextlib import closing
import secrets
import shutil
import sqlite3
import unittest
from unittest import mock

import test_personal_core9_host_contract as fixture
from signed_owner_admission import admit_signed_draft
from one_task_core import OneTaskCore
from personal_core9_host_bridge import (
    run_signed_core9_project_file,verify_protected_core9_after_scm_start,
    CoreHostIntegrationDenied,
)
import personal_windows_host_service as h


class FullCore9ServiceDispatchDisposable(unittest.TestCase):
    def setUp(self):
        self.item=fixture.OwnerCore9PersonalCompletion(
            "test_missing_signed_core_or_no_queue_fails_closed")
        self.item.setUp()
        self.addCleanup(self.item.doCleanups)
        self.root=self.item.root
        self.service_state=self.root/"service_state"
        self.service_state.mkdir()
        shutil.copytree(self.item.repo,self.item.state/"git")
        with closing(sqlite3.connect(self.item.fence)) as con:
            for epoch in (1,2):
                con.execute(
                    "INSERT INTO intents(task_id,nonce,external_epoch,"
                    "operation_sha256,status,remote_head) VALUES(?,?,?,?,?,?)",
                    (secrets.token_hex(16),secrets.token_hex(16),epoch,
                     secrets.token_hex(32),"EXECUTED",secrets.token_hex(32)))
            con.commit()
        result=admit_signed_draft(
            self.item.workspace,self.item.core,
            self.item.signed_core,
            owner_public_raw=self.item.signer.public_key().public_bytes_raw())
        self.assertEqual(result["core_reported_state"],"QUEUED")
        self.fake={"epoch":2,"head":"b"*64}
        self.witness=self.item.signer.public_key()
        def signed_head():
            return {
                "remote_status_signature_verified":True,
                "epoch":self.fake["epoch"],
                "ledger_head":self.fake["head"],
            }
        def witness_ack(*,trusted_service_root,claim,pinned_public_raw):
            self.assertEqual(claim["external_epoch"],3)
            self.assertEqual(self.fake["epoch"],2)
            self.fake={"epoch":3,"head":"e"*64}
            return {
                "status":"SIGNED_EXTERNAL_EPOCH_OBSERVED_NO_EFFECT_AUTHORITY",
                "epoch":3,"ledger_head":self.fake["head"],
                "signed_witness_verified":True,
                "automatic_retry_allowed":False,
                "os_effect_authorized_by_receipt_alone":False,
            }
        self.patches=[
            mock.patch.object(h,"ROOT",self.root),
            mock.patch.object(h,"STATE",self.service_state),
            mock.patch.object(h,"FENCE",self.item.fence),
            mock.patch.object(h,"PROJECTS",self.item.projects),
            mock.patch.object(h,"INBOX",self.root/"inbox"),
            mock.patch.object(h,"OUT",self.root/"outputs"),
            mock.patch.object(h,"_config",return_value=(
                self.item.operator,self.item.signer.public_key(),self.witness)),
            mock.patch.object(h,"assert_external_head_matches_local_fence",
                              side_effect=signed_head),
            mock.patch.object(h,"reserve_personal_epoch",side_effect=witness_ack),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_service_dispatch_existing_core_once_and_reboot_readback(self):
        self.assertFalse(self.item.file.exists())
        # Previous direct-owner note route is intentionally blocked once
        # the real OneTaskCore queue is installed.
        from personal_windows_host_service import PersonalHostDenied
        with self.assertRaises(PersonalHostDenied):
            h.perform_approved_safe_note({"schema":"nf.personal.owner_signed_note.v1"})
        result=h.perform_approved_safe_note(self.item.packet)
        self.assertEqual(result["status"],
                         "CORE9_OWNER_QWEN_PHYSICAL_HOST_FILE_EXECUTED_ONCE")
        self.assertEqual(result["external_epoch"],3)
        self.assertEqual(self.item.file.read_text("utf-8"),self.item.text)
        with closing(sqlite3.connect(self.item.fence)) as con:
            self.assertEqual(con.execute(
                "SELECT COUNT(*) FROM intents WHERE status='EXECUTED'"
            ).fetchone()[0],3)
            self.assertEqual(con.execute(
                "SELECT COUNT(*) FROM intents WHERE status='UNKNOWN_NO_AUTO_RETRY'"
            ).fetchone()[0],0)
        core=OneTaskCore(self.item.state,self.item.state/"git")
        self.assertEqual(core.snapshot()["state"],"HOST_CHECKPOINTED_PERSONAL")
        self.assertEqual(
            verify_protected_core9_after_scm_start(),
            "CORE9_COMPLETION_AND_SIGNED_LINUX_RESTORED")
        # Service reboot/repeated inbox is NEVER a second Linux reservation
        # or file effect; the physical target and CORE lease deny replay.
        with self.assertRaises(CoreHostIntegrationDenied):
            run_signed_core9_project_file(self.item.packet)
        with closing(sqlite3.connect(self.item.fence)) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM intents").fetchone()[0],3)
        self.assertEqual(core.snapshot()["attempts"],1)
        self.assertEqual(self.fake["epoch"],3)
        self.assertEqual(len(list((self.item.projects/self.item.project).iterdir())),1)
        print("NF_CORE9_SERVICE_QUEUE_CLAIM_WITNESS_FILE_COMPLETION_RESTART_PASS_SIMULATED_LINUX")

if __name__=="__main__":
    unittest.main()
