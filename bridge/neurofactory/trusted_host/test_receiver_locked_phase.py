"""HOST-owned narrow test of external DB claimant racing final OS file effect.

Only ephemeral nf_test, disposable filesystem, in-memory signature fixture.
NOT proof against DB superuser/root, OS same-UID, real remote machines.
"""
import psycopg
from unittest.mock import patch

import offline_fenced_file_receiver as module
from test_offline_fenced_file_receiver import (
    TestSignedLiveLeaseOfflineEffect as PriorHostFixture, connect, TASK, CONTENT
)

class ReceiverLockedPhaseChecks(PriorHostFixture):
    def test_separate_db_claimant_cannot_revoke_between_final_check_and_open(self):
        original=module._create_fenced_new_file
        state={"rival_rejected":False}
        def competing_revoke(root,target,content):
            other=connect()
            try:
                other.execute("SET statement_timeout='350ms'")
                try:
                    other.execute("UPDATE nf_task SET phase='UNKNOWN' WHERE task_id=%s",(TASK,))
                except psycopg.errors.QueryCanceled:
                    state["rival_rejected"]=True
            finally:
                other.close()
            return original(root,target,content)
        with patch.object(module,"_create_fenced_new_file",side_effect=competing_revoke):
            receipt=self.write()
        self.assertTrue(state["rival_rejected"])
        self.assertEqual(receipt["status"],"ONE_FILE_COMPLETED_OFFLINE_TEST_ONLY")
        self.assertEqual(self.fspath().read_bytes(),CONTENT)
        self.assertEqual(self.marker_count(),1)
        self.assertEqual(self.db.execute(
            "SELECT phase FROM nf_task WHERE task_id=%s",(TASK,)).fetchone()[0],"LEASED")
        print("NF_RECEIVER_ROW_LOCK_HELD_THROUGH_FSYNC=TEST_PASS")

    def test_expired_before_final_effect_still_refused(self):
        self.db.execute("UPDATE nf_task SET lease_deadline=clock_timestamp()-"
                        "interval '2 seconds' WHERE task_id=%s",(TASK,))
        self.expect_denied_no_effect(self.write)

    def test_crash_remains_unknown_and_unreplayable(self):
        with self.assertRaises(module.OfflineEffectUnknown):
            self.write(simulate_crash_after_fsync=True)
        self.assertEqual(self.fspath().read_bytes(),CONTENT)
        self.assertEqual(self.db.execute(
            "SELECT status FROM nf_receiver_effect_journal").fetchone()[0],
            "UNKNOWN")
        with self.assertRaises(module.OfflineReceiverDenied):
            self.write()
        self.assertEqual(self.marker_count(),1)
