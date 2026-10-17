"""Separate REVIEW-owned hostile checks on exact pinned CORE/HOST receiver.

This is an independent TEST IMPLEMENTATION but NOT an independent,
separately authorised human or OS-identity production verdict.
"""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

root=Path(__file__).resolve().parents[4]
fixture_root=root/"_receiver_audit_source"/"coordinator"
sys.path.insert(0,str(fixture_root/"bridge/neurofactory/coordination"))
import test_pinned_core_host_real_receiver as baseline

class ReceiverBoundaryReview(baseline.PinnedCoreHostReceiver):
    def test_revocation_after_commit_before_file_op_reveals_missing_live_fence(self):
        """Host checks then commits UNKNOWN; revocation BEFORE actual open still writes.

        A real protected receiver must define authorised effect linearisation,
        bound trusted central policy/highwater and OS fence. This is a fixture
        TOCTOU diagnostic; not evidence of an exploited deployed service.
        """
        original=self.hreceiver._create_fenced_new_file
        called={"once":0}
        def revoke_then_file(*args):
            called["once"]+=1
            self.conn.execute(
                "UPDATE nf_task SET phase='UNKNOWN',"
                " lease_deadline=clock_timestamp()-interval '5 seconds'"
                " WHERE task_id=%s",(baseline.TASK,))
            return original(*args)
        with patch.object(self.hreceiver,"_create_fenced_new_file",side_effect=revoke_then_file):
            receipt=self.ask()
        self.assertEqual(called["once"],1)
        self.assertEqual(receipt["status"],"CORE_TO_HOST_ONE_EFFECT_OBSERVED_OFFLINE_ONLY")
        self.assertEqual(self.output().read_bytes(),baseline.CONTENT)
        row=self.conn.execute("SELECT phase FROM nf_task WHERE task_id=%s",(baseline.TASK,)).fetchone()
        self.assertEqual(row[0],"UNKNOWN")
        self.assertEqual(self.conn.execute(
            "SELECT status FROM nf_receiver_effect_journal").fetchone()[0],
                         "COMPLETED_TEST")
        self.assertFalse(receipt["live_execution_allowed"])
        print("NF_REVIEW_GAP_REVOCATION_AFTER_DB_CHECK_BEFORE_FILE=OBSERVED_TEST_FIXTURE")
        print("NF_REVIEW_RELEASE_VERDICT=REJECT_LIVE_NO_PROTECTED_RECEIVER")

    def test_external_db_revoke_cannot_cross_locked_effect(self):
        """Separate connection cannot alter leased task while fsync lock held.

        Same privileged process can still alter its own DB state; this is
        only PostgreSQL row-lock containment, not OS identity isolation.
        """
        import psycopg
        original=self.hreceiver._create_fenced_new_file
        observed={"blocked":False}
        def contender(root,target,content):
            with baseline.db() as other:
                other.execute("SET statement_timeout='350ms'")
                with self.assertRaises(psycopg.errors.QueryCanceled):
                    other.execute(
                        "UPDATE nf_task SET phase='UNKNOWN' WHERE task_id=%s",
                        (baseline.TASK,))
                observed["blocked"]=True
            return original(root,target,content)
        with patch.object(self.hreceiver,"_create_fenced_new_file",side_effect=contender):
            result=self.ask()
        self.assertTrue(observed["blocked"])
        self.assertEqual(self.output().read_bytes(),baseline.CONTENT)
        self.assertFalse(result["live_execution_allowed"])
        print("NF_REVIEW_REMEDIATED_CROSS_CONNECTION_REVOKE_LOCK=PASS_TEST_ONLY")

    def test_signed_scope_does_not_grant_execution_without_independent_root(self):
        result=self.ask()
        self.assertFalse(result["live_execution_allowed"])
        self.assertFalse(result["core_checkpoint_production_authorized"])
        self.assertFalse(self.receiver.pinned_key is None)
        self.assertTrue(self.output().exists())

    def test_untrusted_extra_execution_permission_not_accepted(self):
        packet=dict(self.packet,execution_allowed=True)
        with self.assertRaises(self.hreceiver.OfflineReceiverDenied):
            self.ask(packet=packet)
        self.assert_no_effect()

    def test_pin_substitution_breaks_signature_even_on_valid_request(self):
        self.receiver.pinned_key=Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(self.hreceiver.OfflineReceiverDenied):
            self.ask()
        self.assert_no_effect()

if __name__=="__main__":
    unittest.main()
