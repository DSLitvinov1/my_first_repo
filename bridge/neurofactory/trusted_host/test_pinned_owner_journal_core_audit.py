"""Targeted cross-component owner-grant + recipient highwater, NON-LIVE.

Exact HOST sources are pinned by immutable Git blob identities in CI; CORE
is pinned at its own latest known exact commit (only docs changed since its
previously tested source). This is ONE disposable Linux machine with 3 UIDs,
NOT dual physical nodes or independent owner authorization.
"""
import base64
import copy
import hashlib
import json
import subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from offline_operator_anchor import _canonical
from test_offline_os_separated_effect_receiver import (
    ProtectedReceiverThreePrincipalE2E as Prior, TARGET, CONTENT, run_uid
)

class OwnerGrantJournalPinnedIntegration(Prior):
    def test_audit_01_valid_signed_owner_and_protected_completed_survives_db_rollback(self):
        report=self.send()
        self.assertEqual(report["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        expected=hashlib.sha256(CONTENT).hexdigest()
        self.assertEqual(self.hash_file_from_recipient_uid(),expected)
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],1)
        # Adversarial DB actor resets its *own* reversible SQL journal.
        self.fx.db.execute("DELETE FROM nf_receiver_effect_journal")
        denied=self.send()  # fresh signer/recipient processes; OS journal survives
        self.assertEqual(denied["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.hash_file_from_recipient_uid(),expected)
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
        print("NF_OWNER_GRANT_RECIPIENT_PERSISTENT_ONCE_AFTER_SQL_RESTORE=PASS_TEST_ONLY")

    def test_audit_02_forged_owner_signature_rejected_without_effect_or_marker(self):
        grant=self.owner_grant()
        grant["signature_base64"]=base64.b64encode(
            Ed25519PrivateKey.generate().sign(_canonical(grant["statement"]))
        ).decode("ascii")
        self.write_request(extra={"signed_owner_grant":grant})
        got=self.send()
        self.assertEqual(got["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],"NEVER_SEEN")
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
        print("NF_FORGED_OWNER_SIGNATURE_NO_PROTECTED_INTENT=PASS")

    def test_audit_03_valid_owner_key_but_wrong_task_rejected(self):
        grant=self.owner_grant()
        statement=dict(grant["statement"],task_id="NF-DEV-05-Q999")
        grant={"statement":statement,"signature_base64":
               base64.b64encode(self.owner_private.sign(
                   _canonical(statement))).decode("ascii")}
        self.write_request(extra={"signed_owner_grant":grant})
        got=self.send()
        self.assertEqual(got["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],"NEVER_SEEN")
        print("NF_VALID_OWNER_SIGNER_WRONG_TASK_NO_EFFECT=PASS")

    def test_audit_04_absent_owner_grant_cannot_fall_back_to_test_only_legacy(self):
        self.write_request(extra={"signed_owner_grant":None})
        got=self.send()
        self.assertEqual(got["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],"NEVER_SEEN")
        print("NF_NO_OWNER_GRANT_DENIED_BEFORE_EFFECT=PASS")

    def test_audit_05_post_fsync_crash_and_db_rollback_fails_closed(self):
        denied=self.send(crash_after_fsync=True)
        self.assertEqual(denied["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.hash_file_from_recipient_uid(),
                         hashlib.sha256(CONTENT).hexdigest())
        self.assertEqual(self.protected_effect_state()["state"],
                         "UNKNOWN_MANUAL_RECONCILIATION")
        self.fx.db.execute("DELETE FROM nf_receiver_effect_journal")
        got=self.send()
        self.assertEqual(got["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],
                         "UNKNOWN_MANUAL_RECONCILIATION")
        self.assertEqual(self.hash_file_from_recipient_uid(),
                         hashlib.sha256(CONTENT).hexdigest())
        print("NF_POST_FSYNC_REBOOT_SQL_ROLLBACK_NO_DUPLICATE=PASS_TEST_ONLY")

    def test_audit_06_untrusted_worker_cannot_remove_recipient_receipt(self):
        self.assertEqual(self.send()["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        private=self.receiver_config/"nf-protected-effect-journal"
        res=run_uid("nf_db_actor","-c",
          "import pathlib,sys;[x.unlink() for x in pathlib.Path(sys.argv[1]).iterdir()]",
          private)
        self.assertNotEqual(res.returncode,0)
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        print("NF_DB_ACTOR_CANNOT_DELETE_PRIVATE_RECEIPT=PASS")

    def test_audit_07_real_CORE_claim_Qwen_bytes_with_owner_and_journal(self):
        # Reuse the exact real CORE Git/SQLite + protected 3 UID receiver path,
        # not just a fake JSON claim. It verifies prior genuine Qwen bytes hash.
        self.test_real_core_claim_to_protected_recipient_for_previous_qwen_generated_code()
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        # SQL admin rollback is not permitted to erase nf_effect marker.
        self.fx.db.execute("DELETE FROM nf_receiver_effect_journal")
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        print("NF_QWEN_CORE_OS_RECIPIENT_OWNER_AND_PROTECTED_JOURNAL=PASS_TEST_ONLY")

if __name__=="__main__":
    import unittest
    unittest.main()
