"""Real disposable PostgreSQL16 + filesystem effect with cryptographic scope.

No production OS principal, no real owner permit, no private persistent key.
Run ONLY Github-hosted Linux with NF_HOST_RECEIVER_FIXTURE_ONLY=1.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import unittest

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from offline_cas import OfflineCAS
from offline_effect_reservation import OfflineEffectReservation
from offline_fenced_file_receiver import (
    OfflineFencedFileReceiver,OfflineReceiverDenied,OfflineEffectUnknown
)

DSN="postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"
TARGET="bridge/neurofactory/development/core_owned/offline_receiver_once.txt"
TASK="NF-DEV-05-Q973"
PROJECT="nf-sandbox"
WORKER="worker-sandbox-01"
CONTENT=b"NF irreversible only test content\\n".replace(b"\\\\n",b"\\n")
EMPTY=hashlib.sha256(b"").hexdigest()
def hexsha(x):
    return hashlib.sha256(x).hexdigest()
def connect():
    c=psycopg.connect(DSN,autocommit=True,connect_timeout=3)
    c.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    return c

class TestSignedLiveLeaseOfflineEffect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name!="posix" or os.environ.get("NF_HOST_RECEIVER_FIXTURE_ONLY")!="1":
            raise RuntimeError("missing ephemeral Linux test gate")
        cls.db=connect()
        cls.addClassCleanup(cls.db.close)
        root=Path(__file__).resolve().parent
        cls.db.execute((root/"schema_v1.sql").read_text(encoding="utf8"))
        cls.db.execute((root/"offline_effect_reservation_schema.sql").read_text(encoding="utf8"))
        OfflineFencedFileReceiver.install_fixture_schema(cls.db)
        cls.source_sha=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()
        assert len(cls.source_sha)==40
    def setUp(self):
        # Each case owns its own DB connection; outage test must not close
        # the class-level setup connection used by later independent cases.
        self.db=connect()
        self.addCleanup(self.db.close)
        self.db.execute("""TRUNCATE nf_receiver_effect_journal,
            nf_receiver_scope_fixture,nf_effect_intent,nf_effect_scope_fixture,
            nf_claim_request,nf_task""")
        temp=tempfile.TemporaryDirectory(prefix="nf-receiver-test-")
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)/"nf-receiver-work-001"
        self.root.mkdir(mode=0o700)
        self.private=Ed25519PrivateKey.generate()
        self.public=self.private.public_key()
        self.claim=self._seed()
        self.receiver=OfflineFencedFileReceiver(self.db,self.root,pinned_public_key=self.public)
        self.packet=self._sign(self.payload)
    def _seed(self):
        task_sha=hexsha(b"real test task snapshot")
        policy_sha=hexsha(b"bounded fixture policy")
        self.db.execute("""INSERT INTO nf_task
            (task_id,project_id,input_core_sha40,source_file_sha256,
             input_task_sha256,fixture_authorized) VALUES (%s,%s,%s,%s,%s,TRUE)""",
             (TASK,PROJECT,self.source_sha,EMPTY,task_sha))
        self.db.execute("""INSERT INTO nf_effect_scope_fixture
            (task_id,project_id,input_core_sha40,source_file_sha256,
             input_task_sha256,target,policy_sha256,fixture_authorized)
             VALUES(%s,%s,%s,%s,%s,%s,%s,TRUE)""",
             (TASK,PROJECT,self.source_sha,EMPTY,task_sha,TARGET,policy_sha))
        claim=OfflineCAS(self.db).claim(TASK,WORKER,secrets.token_hex(16),lease_seconds=120)
        self.assertEqual(claim["status"],"CLAIMED")
        token_digest=hexsha(claim["fencing_token"].encode())
        idem=secrets.token_hex(32)
        reserved=OfflineEffectReservation(self.db).reserve_once(
            task_id=TASK,project_id=PROJECT,source_sha40=self.source_sha,
            source_file_sha256=EMPTY,input_task_sha256=task_sha,
            target=TARGET,policy_sha256=policy_sha,worker_id=WORKER,
            lease_epoch=claim["lease_epoch"],fencing_token=claim["fencing_token"],
            idempotency_key=idem)
        self.assertEqual(reserved["status"],"RESERVED_OFFLINE_TEST_ONLY")
        self.db.execute("""INSERT INTO nf_receiver_scope_fixture
             (task_id,issuer_id,key_id,owner_id,repository,operation_id,
              proposed_content_sha256) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
             (TASK,"offline-issuer","ephemeral-key","sandbox-owner",
              "DSLitvinov1/my_first_repo","operation-one",hexsha(CONTENT)))
        now=int(time.time())
        self.payload={
            "schema":"neurofactory.trusted_host.signed_effect_permit.v1",
            "purpose":"EFFECT_RESERVATION_SCOPE_ONLY",
            "issuer_id":"offline-issuer","key_id":"ephemeral-key",
            "owner_id":"sandbox-owner","repository":"DSLitvinov1/my_first_repo",
            "project_id":PROJECT,"task_id":TASK,"worker_id":WORKER,
            "source_sha40":self.source_sha,"source_file_sha256":EMPTY,
            "input_task_sha256":task_sha,"policy_sha256":policy_sha,
            "target":TARGET,"proposed_content_sha256":hexsha(CONTENT),
            "fencing_token_sha256":token_digest,
            "lease_epoch":claim["lease_epoch"],"issued_unix":now-5,
            "expires_unix":now+90,"idempotency_key":idem,
            "operation_id":"operation-one"}
        return claim
    def _sign(self,payload):
        raw=json.dumps(payload,sort_keys=True,separators=(",",":"),
                       ensure_ascii=True,allow_nan=False).encode("ascii")
        return {"payload":dict(payload),
                "signature_base64":base64.b64encode(self.private.sign(raw)).decode("ascii")}
    def write(self,packet=None,content=CONTENT,**extra):
        return self.receiver.write_fixture_once(
            signed_packet=self.packet if packet is None else packet,
            content=content,**extra)
    def fspath(self):
        return self.root/TARGET
    def marker_count(self):
        return self.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0]
    def expect_denied_no_effect(self,fn):
        with self.assertRaises(OfflineReceiverDenied):fn()
        self.assertFalse(self.fspath().exists())
        self.assertEqual(self.marker_count(),0)
    def test_actual_one_file_written_and_fsynced_with_no_live_permit(self):
        result=self.write()
        self.assertEqual(result["status"],"ONE_FILE_COMPLETED_OFFLINE_TEST_ONLY")
        self.assertEqual(self.fspath().read_bytes(),CONTENT)
        self.assertEqual(result["content_sha256"],hexsha(self.fspath().read_bytes()))
        self.assertFalse(result["live_execution_allowed"])
        self.assertFalse(result["protected_signer_custody_attested"])
        self.assertFalse(result["true_independent_recipient_fencing"])
        self.assertEqual(self.marker_count(),1)
        row=self.db.execute("SELECT status FROM nf_receiver_effect_journal").fetchone()
        self.assertEqual(row[0],"COMPLETED_TEST")
        print("NF_SIGNED_FENCED_FIXTURE=ONE_PHYSICAL_FILE_ONCE",flush=True)
    def test_duplicate_delivery_never_rewrites_file(self):
        self.write()
        before=self.fspath().stat()
        with self.assertRaises(OfflineReceiverDenied):self.write()
        self.assertEqual(self.fspath().stat().st_ino,before.st_ino)
        self.assertEqual(self.fspath().read_bytes(),CONTENT)
        self.assertEqual(self.marker_count(),1)
    def test_forged_signature_fails_before_unknown_journal(self):
        foreign=Ed25519PrivateKey.generate()
        raw=json.dumps(self.payload,sort_keys=True,separators=(",",":"),
                       ensure_ascii=True).encode("ascii")
        wrong={"payload":dict(self.payload),
               "signature_base64":base64.b64encode(foreign.sign(raw)).decode("ascii")}
        self.expect_denied_no_effect(lambda:self.write(wrong))
    def test_valid_signer_wrong_owner_source_or_worker_fails(self):
        for name,value in (("owner_id","another-owner"),("worker_id","other-worker"),
            ("repository","AnotherOrg/foreign"),("project_id","other-project"),
            ("source_sha40","f"*40),("target","bridge/neurofactory/development/core_owned/other.txt"),
            ("lease_epoch",2),("operation_id","other-operation"),
            ("idempotency_key","f"*64),("proposed_content_sha256","f"*64)):
            p=dict(self.payload);p[name]=value
            with self.subTest(field=name):
                self.expect_denied_no_effect(lambda:self.write(self._sign(p)))
    def test_expired_signed_permit_denies_without_effect(self):
        p=dict(self.payload)
        p["issued_unix"]=int(time.time())-100
        p["expires_unix"]=int(time.time())-1
        self.expect_denied_no_effect(lambda:self.write(self._sign(p)))
    def test_expired_real_postgres_lease_denies_even_with_valid_signature(self):
        self.db.execute("""UPDATE nf_task SET lease_deadline=clock_timestamp()-interval '1 second'
                          WHERE task_id=%s""",(TASK,))
        self.expect_denied_no_effect(self.write)
    def test_losing_or_stale_worker_in_central_db_denied(self):
        self.db.execute("UPDATE nf_task SET holder_id='stale-worker' WHERE task_id=%s",(TASK,))
        self.expect_denied_no_effect(self.write)
    def test_unknown_host_state_denies(self):
        self.db.execute("UPDATE nf_task SET phase='UNKNOWN' WHERE task_id=%s",(TASK,))
        self.expect_denied_no_effect(self.write)
    def test_central_host_unavailable_never_writes(self):
        self.db.close()
        with self.assertRaises(Exception):self.write()
        self.assertFalse(self.fspath().exists())
    def test_bytes_hash_tamper_rejected_before_intent(self):
        self.expect_denied_no_effect(lambda:self.write(content=b"wrong content"))
    def test_existing_file_cannot_be_overwritten_even_valid_permit(self):
        self.fspath().parent.mkdir(parents=True,exist_ok=True)
        self.fspath().write_bytes(b"KEEP ORIGINAL")
        with self.assertRaises(OfflineEffectUnknown):
            self.write()
        self.assertEqual(self.fspath().read_bytes(),b"KEEP ORIGINAL")
        self.assertEqual(self.marker_count(),1)
        self.assertEqual(self.db.execute("SELECT status FROM nf_receiver_effect_journal").fetchone()[0],"UNKNOWN")
    def test_symlink_target_does_not_write_outside_test(self):
        outside=self.root.parent/"outside.txt"
        outside.write_bytes(b"NEVER CHANGE")
        self.fspath().parent.mkdir(parents=True,exist_ok=True)
        self.fspath().symlink_to(outside)
        with self.assertRaises(OfflineEffectUnknown):self.write()
        self.assertEqual(outside.read_bytes(),b"NEVER CHANGE")
        self.assertEqual(self.marker_count(),1)
    def test_crash_after_real_fsync_before_receipt_stays_unknown(self):
        with self.assertRaises(OfflineEffectUnknown):
            self.write(simulate_crash_after_fsync=True)
        self.assertEqual(self.fspath().read_bytes(),CONTENT)
        self.assertEqual(self.db.execute("SELECT status FROM nf_receiver_effect_journal").fetchone()[0],"UNKNOWN")
        with self.assertRaises(OfflineReceiverDenied):self.write()
        self.assertEqual(self.fspath().read_bytes(),CONTENT)
        print("NF_LOST_RECEIPT=UNKNOWN_STOP_NO_SECOND_FILE",flush=True)
    def test_caller_provided_positive_crypto_report_is_not_accepted(self):
        with self.assertRaises(TypeError):
            self.receiver.write_fixture_once(
                signed_packet=self.packet,content=CONTENT,
                untrusted_external_override={"status":"GRANTED"})
        self.assertFalse(self.fspath().exists())
    def test_no_default_receiver_activation(self):
        env=os.environ.pop("NF_HOST_RECEIVER_FIXTURE_ONLY")
        try:
            with self.assertRaises(OfflineReceiverDenied):
                OfflineFencedFileReceiver(self.db,self.root,pinned_public_key=self.public)
        finally:
            os.environ["NF_HOST_RECEIVER_FIXTURE_ONLY"]=env

if __name__=="__main__":
    unittest.main()
