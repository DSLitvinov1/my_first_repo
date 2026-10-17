"""Narrow pinned CORE client → actual HOST final receiver, disposable Linux ONLY."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT=Path(__file__).resolve().parents[4]
HOST_SHA="1575812f75040d9f53435c652fc053adc487f5b7"
HOST=ROOT/".nf_pinned_host"
if subprocess.check_output(["git","-C",str(HOST),"rev-parse","HEAD"],text=True).strip()!=HOST_SHA:
    raise RuntimeError("HOST checkout not pinned to independently tested source")
sys.path.insert(0,str(HOST/"bridge/neurofactory/trusted_host"))

from offline_cas import OfflineCAS
from offline_effect_reservation import OfflineEffectReservation
from offline_fenced_file_receiver import (
    OfflineFencedFileReceiver,OfflineReceiverDenied,OfflineEffectUnknown)
from one_task_core import OneTaskCore,CoreSafetyError,_canonical,EMPTY_SHA
from offline_receiver_client import CoreOfflineReceiverClient,OfflineProtectedRouteDenied

DSN="postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"
TASK="NF-DEV-05-Q974"
WORKER="worker-sandbox-01"
TARGET="bridge/neurofactory/development/core_owned/test_single_core_host.txt"
CONTENT="TEST_ONLY_CORE_HOST_FILE\\n"
def sha(b):return hashlib.sha256(b).hexdigest()
def git(path,*args):
    return subprocess.check_output(["git","-C",str(path),*args],stderr=subprocess.PIPE,text=True).strip()
def db():
    c=psycopg.connect(DSN,autocommit=True,connect_timeout=3)
    c.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    return c

class RealCoreToHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("NF_CORE_OFFLINE_RECEIVER_TEST_ONLY")!="1" or os.environ.get("NF_HOST_RECEIVER_FIXTURE_ONLY")!="1":
            raise RuntimeError("both nonlive guards needed")
        cls.setup_db=db()
        cls.addClassCleanup(cls.setup_db.close)
        cls.setup_db.execute((HOST/"bridge/neurofactory/trusted_host/schema_v1.sql").read_text("utf8"))
        cls.setup_db.execute((HOST/"bridge/neurofactory/trusted_host/offline_effect_reservation_schema.sql").read_text("utf8"))
        OfflineFencedFileReceiver.install_fixture_schema(cls.setup_db)
    def setUp(self):
        self.db=db()
        self.addCleanup(self.db.close)
        self.db.execute("""TRUNCATE nf_receiver_effect_journal,nf_receiver_scope_fixture,
          nf_effect_intent,nf_effect_scope_fixture,nf_claim_request,nf_task""")
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-receiver-test-")
        self.addCleanup(self.tmp.cleanup)
        parent=Path(self.tmp.name)
        self.host_root=parent/"nf-receiver-work-001";self.host_root.mkdir(mode=0o700)
        self.core_root=parent/"core-work";self.core_root.mkdir(mode=0o700)
        self.repo=parent/"git-repository";self.repo.mkdir(mode=0o700)
        git(self.repo,"init","-q")
        git(self.repo,"config","user.name","NF offline")
        git(self.repo,"config","user.email","nf@example.invalid")
        (self.repo/"README.md").write_text("offline one task")
        git(self.repo,"add","README.md");git(self.repo,"commit","-qm","initial synthetic preimage")
        orig_sha=git(self.repo,"rev-parse","HEAD")
        self.spec={"schema":"neurofactory.core.task.v1","task_id":TASK,
             "project_id":"nf-sandbox","target":TARGET,
             "objective":"Write one synthetic bounded text file and check it.",
             "source_sha":orig_sha,"source_sha256":EMPTY_SHA,
             "approval_commit":orig_sha,"model":"qwen2.5-coder:1.5b","reserved_units":5}
        self.core=OneTaskCore(self.core_root,self.repo)
        self.assertEqual(self.core.enqueue(
            self.spec,trusted_approval_check=lambda x: x==self.spec)["state"],"QUEUED")
        now=int(time.time())
        self.core_token=self.core.claim(WORKER,now=now,lease_seconds=120)["token"]
        self.proposal={"schema":"neurofactory.core.proposal.v1","target":TARGET,
                       "content":CONTENT,"content_sha256":sha(CONTENT.encode()),
                       "mode":"OFFLINE_TEST"}
        tasksha=sha(_canonical(self.spec));policy=sha(b"only synthetic recipient")
        self.db.execute("""INSERT INTO nf_task
            (task_id,project_id,input_core_sha40,source_file_sha256,input_task_sha256,
             fixture_authorized) VALUES(%s,%s,%s,%s,%s,TRUE)""",
             (TASK,"nf-sandbox",orig_sha,EMPTY_SHA,tasksha))
        self.db.execute("""INSERT INTO nf_effect_scope_fixture
            (task_id,project_id,input_core_sha40,source_file_sha256,input_task_sha256,
             target,policy_sha256,fixture_authorized)
             VALUES(%s,%s,%s,%s,%s,%s,%s,TRUE)""",
             (TASK,"nf-sandbox",orig_sha,EMPTY_SHA,tasksha,TARGET,policy))
        hostclaim=OfflineCAS(self.db).claim(TASK,WORKER,secrets.token_hex(16),lease_seconds=120)
        self.assertEqual(hostclaim["status"],"CLAIMED")
        idem=secrets.token_hex(32)
        reserved=OfflineEffectReservation(self.db).reserve_once(
             task_id=TASK,project_id="nf-sandbox",source_sha40=orig_sha,
             source_file_sha256=EMPTY_SHA,input_task_sha256=tasksha,
             target=TARGET,policy_sha256=policy,worker_id=WORKER,
             lease_epoch=hostclaim["lease_epoch"],fencing_token=hostclaim["fencing_token"],
             idempotency_key=idem)
        self.assertEqual(reserved["status"],"RESERVED_OFFLINE_TEST_ONLY")
        self.db.execute("""INSERT INTO nf_receiver_scope_fixture
             (task_id,issuer_id,key_id,owner_id,repository,operation_id,proposed_content_sha256)
             VALUES(%s,%s,%s,%s,%s,%s,%s)""",
             (TASK,"offline-issuer","temporary-key","sandbox-owner",
              "DSLitvinov1/my_first_repo","operation-once",sha(CONTENT.encode())))
        self.private=Ed25519PrivateKey.generate()
        self.receiver=OfflineFencedFileReceiver(self.db,self.host_root,
                                                pinned_public_key=self.private.public_key())
        self.client=CoreOfflineReceiverClient(self.core,self.receiver)
        self.payload={"schema":"neurofactory.trusted_host.signed_effect_permit.v1",
            "purpose":"EFFECT_RESERVATION_SCOPE_ONLY",
            "issuer_id":"offline-issuer","key_id":"temporary-key",
            "owner_id":"sandbox-owner","repository":"DSLitvinov1/my_first_repo",
            "project_id":"nf-sandbox","task_id":TASK,"worker_id":WORKER,
            "source_sha40":orig_sha,"source_file_sha256":EMPTY_SHA,
            "input_task_sha256":tasksha,"policy_sha256":policy,
            "target":TARGET,"proposed_content_sha256":sha(CONTENT.encode()),
            "fencing_token_sha256":sha(hostclaim["fencing_token"].encode()),
            "lease_epoch":hostclaim["lease_epoch"],"issued_unix":now-3,
            "expires_unix":now+60,"idempotency_key":idem,
            "operation_id":"operation-once"}
        self.packet=self.sign(self.payload)
    def sign(self,p):
        raw=json.dumps(p,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
        return {"payload":dict(p),"signature_base64":
                base64.b64encode(self.private.sign(raw)).decode("ascii")}
    def apply(self,packet=None,proposal=None):
        return self.client.propose_one_test_effect(
          task_id=TASK,core_token=self.core_token,worker_id=WORKER,
          proposal=self.proposal if proposal is None else proposal,
          signed_packet=self.packet if packet is None else packet)
    def file(self):
        return self.host_root/TARGET
    def test_single_signed_task_effect_via_real_core_and_host(self):
        result=self.apply()
        self.assertEqual(result["status"],"CORE_TO_HOST_ONE_EFFECT_OBSERVED_OFFLINE_ONLY")
        self.assertEqual(self.file().read_text("utf8"),CONTENT)
        self.assertEqual(result["content_sha256"],sha(self.file().read_bytes()))
        self.assertFalse((self.core.sandbox/TARGET).exists())
        self.assertFalse(result["live_execution_allowed"])
        self.assertEqual(self.db.execute("SELECT status FROM nf_receiver_effect_journal").fetchone()[0],"COMPLETED_TEST")
        print("CORE_TO_HOST_REAL_TEMP_FILE=ONE_WRITE_ONLY",flush=True)
    def test_repeat_cannot_second_write(self):
        self.apply()
        with self.assertRaises(OfflineReceiverDenied):self.apply()
        self.assertEqual(self.file().read_text(),CONTENT)
        self.assertEqual(self.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],1)
    def test_core_foreign_target_denied_before_effect(self):
        p=dict(self.proposal,target="bridge/neurofactory/development/core_owned/foreign.py")
        with self.assertRaises(OfflineProtectedRouteDenied):self.apply(proposal=p)
        self.assertFalse(self.file().exists())
    def test_signed_other_worker_refused(self):
        p=dict(self.payload,worker_id="another-worker")
        with self.assertRaises(OfflineProtectedRouteDenied):self.apply(packet=self.sign(p))
        self.assertFalse(self.file().exists())
    def test_expired_host_lease_denied_before_write(self):
        self.db.execute("UPDATE nf_task SET lease_deadline=clock_timestamp()-interval '1 second'")
        with self.assertRaises(OfflineReceiverDenied):self.apply()
        self.assertFalse(self.file().exists())
    def test_forged_signature_denied_at_actual_host_recipient(self):
        packet=dict(self.packet)
        packet["signature_base64"]=base64.b64encode(b"z"*64).decode("ascii")
        with self.assertRaises(OfflineReceiverDenied):self.apply(packet=packet)
        self.assertFalse(self.file().exists())
    def test_unknown_lost_receipt_no_automatic_retry(self):
        with self.assertRaises(OfflineEffectUnknown):
            self.receiver.write_fixture_once(signed_packet=self.packet,
                        content=CONTENT.encode(),simulate_crash_after_fsync=True)
        self.assertEqual(self.file().read_text(),CONTENT)
        with self.assertRaises(OfflineReceiverDenied):self.apply()
        self.assertEqual(self.db.execute("SELECT status FROM nf_receiver_effect_journal").fetchone()[0],"UNKNOWN")
        print("CORE_TO_HOST_UNKNOWN=STOP_NO_DUPLICATE",flush=True)
    def test_host_disconnect_causes_no_effect(self):
        self.db.close()
        with self.assertRaises(Exception):self.apply()
        self.assertFalse(self.file().exists())
    def test_current_core_legacy_direct_write_remains_disabled(self):
        with self.assertRaises(CoreSafetyError):
            self.core.apply_offline_test(TASK,self.core_token,self.proposal,now=int(time.time()))
        self.assertFalse((self.core.sandbox/TARGET).exists())

if __name__=="__main__":
    unittest.main()
