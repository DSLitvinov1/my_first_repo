"""Only new local HOST journal boundary; no model, Windows SCM or cloud API."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from resident_host_audit_journal import (
    append_after_core_checkpoint,inspect,LocalAuditDenied
)

def event(n=951):
    tid=f"NF-DEV-05-Q{n}"
    return {
      "schema":"nf.onepc.local_host_checkpoint.v1",
      "task_id":tid,
      "source_sha40":"a"*40,
      "proposal_sha256":"b"*64,
      "result_sha256":"c"*64,
      "receipt_sha256":"d"*64,
      "operation_id":"pilot-"+tid,
      "checkpoint_state":"HOST_CHECKPOINTED_TEST",
    }

class ResidentSignedResultJournalTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name).resolve()/"receipt-audit.sqlite3"
    def tearDown(self):
        self.temp.cleanup()
    def test_complete_signed_host_receipt_only_once_and_reopen(self):
        with self.assertRaises(LocalAuditDenied):
            append_after_core_checkpoint(self.path,event(),
                                        actual_core_state="CLAIMED")
        self.assertFalse(self.path.exists())
        first=append_after_core_checkpoint(self.path,event(),
                                           actual_core_state="HOST_CHECKPOINTED_TEST")
        self.assertEqual(first["entries"],1)
        self.assertFalse(first["external_highwater_attested"])
        second=inspect(self.path)
        self.assertEqual(first,second)
        with self.assertRaises(LocalAuditDenied):
            append_after_core_checkpoint(self.path,event(),
                                        actual_core_state="HOST_CHECKPOINTED_TEST")
        self.assertEqual(inspect(self.path)["entries"],1)
        step=append_after_core_checkpoint(self.path,event(952),
                                          actual_core_state="HOST_CHECKPOINTED_TEST")
        self.assertEqual(step["entries"],2)
        self.assertNotEqual(step["head_sha256"],first["head_sha256"])
    def test_read_only_missing_file_cannot_regenerate_forged_audit(self):
        with self.assertRaises(LocalAuditDenied):
            inspect(self.path)
        self.assertFalse(self.path.exists())
    def test_reject_model_text_and_arbitrary_states(self):
        altered=event()
        altered["untrusted_model_text"]="write arbitrary files"
        with self.assertRaises(LocalAuditDenied):
            append_after_core_checkpoint(self.path,altered,
                                         actual_core_state="HOST_CHECKPOINTED_TEST")
        altered=event()
        altered["checkpoint_state"]="PRODUCTION_SUCCEEDED"
        with self.assertRaises(LocalAuditDenied):
            append_after_core_checkpoint(self.path,altered,
                                         actual_core_state="HOST_CHECKPOINTED_TEST")
    def test_detect_receipt_mutation_and_stop_further_appends(self):
        append_after_core_checkpoint(self.path,event(),
                                     actual_core_state="HOST_CHECKPOINTED_TEST")
        db=sqlite3.connect(self.path)
        db.execute("UPDATE checkpoints SET record_sha256=? WHERE seq=1",("0"*64,))
        db.commit()
        db.close()
        with self.assertRaises(LocalAuditDenied):
            inspect(self.path)
        with self.assertRaises(LocalAuditDenied):
            append_after_core_checkpoint(self.path,event(952),
                                         actual_core_state="HOST_CHECKPOINTED_TEST")
    def test_detect_missing_table(self):
        append_after_core_checkpoint(self.path,event(),actual_core_state="HOST_CHECKPOINTED_TEST")
        db=sqlite3.connect(self.path)
        db.execute("DROP TABLE checkpoints")
        db.commit()
        db.close()
        with self.assertRaises(LocalAuditDenied):
            inspect(self.path)
    def test_detect_corrupted_prev_chain(self):
        append_after_core_checkpoint(self.path,event(),actual_core_state="HOST_CHECKPOINTED_TEST")
        append_after_core_checkpoint(self.path,event(952),actual_core_state="HOST_CHECKPOINTED_TEST")
        db=sqlite3.connect(self.path)
        db.execute("UPDATE checkpoints SET previous_sha256=? WHERE seq=2",("9"*64,))
        db.commit()
        db.close()
        with self.assertRaises(LocalAuditDenied):
            inspect(self.path)

if __name__=="__main__":
    unittest.main()
