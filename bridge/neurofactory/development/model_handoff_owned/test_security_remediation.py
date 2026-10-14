"""HANDOFF-only adversarial regression: never load foreign projects or publish."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from model_handoff_owned import handoff_gate as gate

SRC = "def hello(value):\n    return value.strip()\n"
TARGET = "bridge/neurofactory/development/model_handoff_owned/isolated_proof.py"
TASK = "NF-DEV-05-Q099"

class SecuredHandoffTests(unittest.TestCase):
    def candidate(self):
        return gate.candidate_packet(TASK, TARGET, SRC)

    def review(self, candidate):
        return gate.review_packet(candidate, json.dumps({
            "verdict": "APPROVE",
            "candidate_sha256": candidate["candidate_sha256"],
            "findings": ["Read the exact source"]}))

    @unittest.skipUnless(os.name == "posix", "POSIX-only secure write checks")
    def test_directory_swap_during_file_create_cannot_write_foreign_file(self):
        """Inject an adversarial same-UID rename exactly at the leaf creation."""
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"evidence";root.mkdir()
            foreign=Path(td)/"foreign";foreign.mkdir()
            owner=root/TASK
            leaf_open=os.open
            injected=[False]
            def interrupt(path, flags, *args, **kw):
                if str(path)=="candidate.json" and flags & os.O_CREAT and not injected[0]:
                    injected[0]=True
                    owner.rename(root/"moved_task")
                    owner.symlink_to(foreign,target_is_directory=True)
                return leaf_open(path,flags,*args,**kw)
            # Patching os.open changes its identity; retain the real platform capability check.
            with mock.patch.object(gate,"_secure_storage_available",return_value=True), \
                 mock.patch.object(os,"open",side_effect=interrupt):
                with self.assertRaises(gate.HandoffError):
                    gate.store_once(root,TASK,"candidate.json",{"example":"adversarial"})
            self.assertTrue(injected[0])
            self.assertFalse((foreign/"candidate.json").exists())
            self.assertFalse((root/"moved_task"/"candidate.json").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX-only secure write checks")
    def test_preopened_symlink_swap_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"evidence";root.mkdir()
            foreign=Path(td)/"foreign";foreign.mkdir()
            owner=root/TASK;owner.mkdir(mode=0o700)
            owner.rename(root/"original")
            owner.symlink_to(foreign,target_is_directory=True)
            with self.assertRaises(gate.HandoffError):
                gate.store_once(root,TASK,"candidate.json",{"item":"x"})
            self.assertFalse((foreign/"candidate.json").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX-only secure write checks")
    def test_private_root_cannot_be_writable_by_other_users(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"evidence";root.mkdir()
            root.chmod(0o777)
            with self.assertRaises(gate.HandoffError):
                gate.store_once(root,TASK,"candidate.json",{"item":"x"})

    @unittest.skipUnless(os.name == "posix", "POSIX-only secure write checks")
    def test_partial_checkpoint_is_never_complete(self):
        with tempfile.TemporaryDirectory() as td:
            c=self.candidate();r=self.review(c)
            gate.store_once(td,TASK,"candidate.json",c)
            with self.assertRaises(gate.HandoffError):
                gate.verify_complete_handoff(td,c,r)
            # Recovery is idempotent; incomplete proof cannot be mistaken for success.
            gate.persist_handoff(td,c,r)
            self.assertTrue(gate.verify_complete_handoff(td,c,r))

    @unittest.skipUnless(os.name == "posix", "POSIX-only secure write checks")
    def test_interruption_after_one_evidence_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            c=self.candidate();r=self.review(c)
            real=gate.store_once
            called=[0]
            def interrupt(*args,**kw):
                called[0]+=1
                if called[0]==2:
                    raise gate.HandoffError("deliberate owned-process interruption")
                return real(*args,**kw)
            with mock.patch.object(gate,"store_once",side_effect=interrupt):
                with self.assertRaises(gate.HandoffError):
                    gate.persist_handoff(td,c,r)
            self.assertTrue((Path(td)/TASK/"candidate.json").exists())
            with self.assertRaises(gate.HandoffError):
                gate.verify_complete_handoff(td,c,r)
            self.assertFalse((Path(td)/TASK/"handoff.json").exists())

    def test_caller_supplied_model_claim_does_not_attest_origin(self):
        c=self.candidate(); r=self.review(c)
        with self.assertRaises(gate.HandoffError):
            gate.verify_trusted_runner_origin(c,r,{},verify_github=lambda *_:True)
        fake={"run_id":38469770594,"head_sha":"a"*40,"artifact_id":11850873678,
              "artifact_sha256":"b"*64,"candidate_sha256":c["candidate_sha256"],
              "reviewer_model":gate.REVIEWER,"raw_reply_sha256":"c"*64}
        with self.assertRaises(gate.HandoffError):
            gate.verify_trusted_runner_origin(c,r,fake,verify_github=lambda *_:False)
        with self.assertRaises(gate.HandoffError):
            gate.verify_trusted_runner_origin(c,r,fake,verify_github=None)

    def test_attestation_proves_external_check_but_cannot_grant_release(self):
        c=self.candidate();r=self.review(c)
        evidence={"run_id":38469770594,"head_sha":"a"*40,"artifact_id":11850873678,
                  "artifact_sha256":"b"*64,"candidate_sha256":c["candidate_sha256"],
                  "reviewer_model":gate.REVIEWER,"raw_reply_sha256":"c"*64}
        attestation=gate.verify_trusted_runner_origin(c,r,evidence,
            verify_github=lambda receipt,candidate,review:
                 receipt["candidate_sha256"] == candidate["candidate_sha256"])
        self.assertTrue(attestation["receipt_correlated_by_callback"])
        self.assertFalse(attestation["origin_attested_by_external_verifier"])
        self.assertFalse(attestation["release_authorized"])
        self.assertTrue(attestation["needs_independent_review_owner"])

    def test_windows_is_deliberately_fail_closed_until_native_storage_is_reviewed(self):
        with mock.patch.object(gate, "_secure_storage_available", return_value=False):
            with tempfile.TemporaryDirectory() as td:
                with self.assertRaises(gate.HandoffError):
                    gate.store_once(td,TASK,"candidate.json",{"value":"not written"})
                self.assertFalse((Path(td)/TASK/"candidate.json").exists())


    @unittest.skipUnless(os.name == "nt", "Native Windows fail-closed check")
    def test_real_windows_evidence_write_must_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(gate.HandoffError):
                gate.store_once(td,TASK,"candidate.json",{"value":"blocked on Windows"})
            self.assertFalse((Path(td)/TASK/"candidate.json").exists())

if __name__=="__main__":
    unittest.main()
