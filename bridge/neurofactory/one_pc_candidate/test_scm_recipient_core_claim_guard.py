"""Targeted negative checks for recipient-side CORE scope, no Windows SCM install."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from scm_recipient_core_claim_guard import (
    assert_recipient_core_claim, ScmRecipientScopeDenied,
)


class RecipientClaimGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nf-recipient-claim-")
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.db = self.state / "queue.sqlite3"
        self.now = int(time.time())
        self.spec = {
            "schema":"neurofactory.core.task.v1",
            "task_id":"NF-DEV-05-Q941", "project_id":"test-project",
            "target":"bridge/neurofactory/development/core_owned/windows_pilot.txt",
            "objective":"Write one harmless sealed output in a disposable Windows CI workspace.",
            "source_sha":"a"*40, "source_sha256":"b"*64,
            "model":"qwen2.5-coder:1.5b", "reserved_units":10,
            "approval_commit":"a"*40,
        }
        raw=json.dumps(self.spec,sort_keys=True,ensure_ascii=False,
                       separators=(",",":"),allow_nan=False)
        self.digest=hashlib.sha256(raw.encode("utf8")).hexdigest()
        self.body={
            "task_id":self.spec["task_id"],
            "project_id":self.spec["project_id"],
            "source_sha40":self.spec["source_sha"],
            "operation_id":"pilot-"+self.spec["task_id"],
            "target":self.spec["target"],
            "content_sha256":"c"*64,
        }
        with sqlite3.connect(self.db) as con:
            con.execute("""CREATE TABLE single_job(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                task_id TEXT, spec TEXT, spec_sha256 TEXT, state TEXT,
                owner TEXT, token_sha256 TEXT, attempts INTEGER,
                lease_until INTEGER, result_sha256 TEXT, receipt TEXT)""")
            con.execute("INSERT INTO single_job VALUES (1,?,?,?,?,?,?,?,?,?,?)",
                (self.spec["task_id"],raw,self.digest,"CLAIMED","worker-one",
                 "d"*64,1,self.now+120,None,None))
        if os.name != "nt":
            os.chmod(self.db,0o600)
            os.chmod(self.state,0o700)
            self.previous=os.environ.get("NF_RECIPIENT_CORE_GUARD_UNIT_TEST")
            os.environ["NF_RECIPIENT_CORE_GUARD_UNIT_TEST"]="1"

    def tearDown(self):
        if os.name != "nt":
            if self.previous is None:
                os.environ.pop("NF_RECIPIENT_CORE_GUARD_UNIT_TEST",None)
            else:
                os.environ["NF_RECIPIENT_CORE_GUARD_UNIT_TEST"]=self.previous
        self.temp.cleanup()

    def check(self,body=None,**kwargs):
        return assert_recipient_core_claim(
            core_state=self.state,
            body=self.body if body is None else body,
            expected_spec_sha256=kwargs.pop("spec_sha",self.digest),
            expected_payload_sha256=kwargs.pop("payload_sha","c"*64),
            expected_owner=kwargs.pop("owner","worker-one"),
            now_unix=kwargs.pop("now",self.now),**kwargs)

    def update(self,sql,params=()):
        with sqlite3.connect(self.db) as con:
            con.execute(sql,params)

    def test_real_claimed_queue_matches_only_ci(self):
        out=self.check()
        self.assertEqual(out["status"],"SCM_CORE_SCOPE_MATCHES_ADMIN_PIN_TEST_ONLY")
        self.assertIs(out["production_execution_allowed"],False)
        self.assertIs(out["recipient_effect_transaction_attested"],False)

    def test_wrong_signed_payload_pin_denied(self):
        with self.assertRaises(ScmRecipientScopeDenied):
            self.check(payload_sha="d"*64)

    def test_wrong_full_task_spec_pin_denied(self):
        with self.assertRaises(ScmRecipientScopeDenied):
            self.check(spec_sha="e"*64)

    def test_wrong_worker_owner_denied(self):
        with self.assertRaises(ScmRecipientScopeDenied):
            self.check(owner="other-worker")

    def test_expired_claim_denied(self):
        self.update("UPDATE single_job SET lease_until=? WHERE singleton=1",
                    (self.now-1,))
        with self.assertRaises(ScmRecipientScopeDenied):
            self.check()

    def test_wrong_task_or_project_denied(self):
        for field,new in (("task_id","NF-DEV-05-Q942"),
                          ("project_id","other-project"),
                          ("source_sha40","f"*40)):
            with self.subTest(field=field):
                with self.assertRaises(ScmRecipientScopeDenied):
                    self.check(body={**self.body,field:new})

    def test_queue_state_must_be_claimed_and_receipt_absent(self):
        self.update("UPDATE single_job SET state='NEEDS_MANUAL_REVIEW' WHERE singleton=1")
        with self.assertRaises(ScmRecipientScopeDenied):
            self.check()

    def test_lost_db_refuses_no_recreation(self):
        self.db.unlink()
        with self.assertRaises(ScmRecipientScopeDenied):
            self.check()
        self.assertFalse(self.db.exists())

    def test_corrupt_spec_hash_refuses(self):
        self.update("UPDATE single_job SET spec_sha256=? WHERE singleton=1",("f"*64,))
        with self.assertRaises(ScmRecipientScopeDenied):
            self.check()

    def test_forged_caller_clock_refuses(self):
        with self.assertRaises(ScmRecipientScopeDenied):
            self.check(now=self.now+3600)


if __name__=="__main__":
    unittest.main(verbosity=2)
