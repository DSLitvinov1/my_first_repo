"""Coordinator independent-pinned CORE -> HOST real disposable receiver tests.

Two pinned source commits, one GitHub-hosted machine, ephemeral PostgreSQL16,
temporary git repository and HOST-owned private sandbox. No actual signer
provisioning, owner attestation, genuine remote API or physical two-host trial.
"""
import base64
import hashlib
import importlib.util
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

CORE_SHA="05ab48bf5b04818df2b632906886610587cad642"
HOST_SHA="6bb33d4cdaa26abee6b6f9961b9f1ff5e546ba4e"
TASK="NF-DEV-05-Q987"
PROJECT="nf-sandbox"
WORKER="fixture-worker-01"
TARGET="bridge/neurofactory/development/core_owned/one_result.txt"
CONTENT=b"ONE_PINNED_TWO_COMPONENT_OFFLINE_EFFECT\n"
POLICY_SHA=hashlib.sha256(b"immutable-fixture-policy").hexdigest()
DSN="postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"

def git(repo,*args):
    return subprocess.check_output(
        ["git","-C",str(repo),*args],text=True,stderr=subprocess.PIPE,timeout=12).strip()

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def db():
    c=psycopg.connect(DSN,autocommit=True,connect_timeout=3)
    if c.execute("SELECT current_database()").fetchone()[0]!="nf_test":
        c.close()
        raise RuntimeError("not disposable nf_test")
    c.execute("SET neurofactory.offline_fixture_mode TO 'on'")
    return c

class PinnedCoreHostReceiver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name!="posix" or os.environ.get("NF_HOST_RECEIVER_FIXTURE_ONLY")!="1" or os.environ.get("NF_CORE_OFFLINE_RECEIVER_TEST_ONLY")!="1":
            raise RuntimeError("test-only Linux boundary")
        root=Path(__file__).resolve().parents[3]
        core=root/"_e2e_fixture"/"core"
        host=root/"_e2e_fixture"/"host"
        if git(core,"rev-parse","HEAD")!=CORE_SHA or git(host,"rev-parse","HEAD")!=HOST_SHA:
            raise RuntimeError("exact source SHA mismatch")
        cls.cmod=load("review_pinned_core_queue",core/"bridge/neurofactory/development/core_owned/one_task_core.py")
        cls.clientmod=load("review_pinned_core_client",core/"bridge/neurofactory/development/core_owned/offline_receiver_client.py")
        cls.hcas=load("review_pinned_host_cas",host/"bridge/neurofactory/trusted_host/offline_cas.py")
        cls.hreserve=load("review_pinned_host_reserve",host/"bridge/neurofactory/trusted_host/offline_effect_reservation.py")
        # HOST receiver imports signed_effect_permit as a sibling module.
        import sys
        host_folder=str(host/"bridge/neurofactory/trusted_host")
        if host_folder not in sys.path:
            sys.path.insert(0,host_folder)
        cls.hreceiver=load("review_pinned_host_receiver",host/"bridge/neurofactory/trusted_host/offline_fenced_file_receiver.py")
        with db() as c:
            c.execute((host/"bridge/neurofactory/trusted_host/schema_v1.sql").read_text())
            c.execute((host/"bridge/neurofactory/trusted_host/offline_effect_reservation_schema.sql").read_text())
            cls.hreceiver.OfflineFencedFileReceiver.install_fixture_schema(c)

    def setUp(self):
        self.conn=db()
        self.addCleanup(self.conn.close)
        self.conn.execute("""TRUNCATE nf_receiver_effect_journal,
            nf_receiver_scope_fixture,nf_effect_intent,
            nf_effect_scope_fixture,nf_claim_request,nf_task""")
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-receiver-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.receiver_root=self.root/"nf-receiver-work-001"
        self.receiver_root.mkdir(mode=0o700)
        self.repo=self.root/"test-git"
        self.repo.mkdir(mode=0o700)
        git(self.repo,"init","-q")
        git(self.repo,"config","user.name","ephemeral")
        git(self.repo,"config","user.email","sandbox@example.invalid")
        (self.repo/"README.md").write_text("synthetic fixture\n",encoding="utf8")
        git(self.repo,"add","README.md")
        git(self.repo,"commit","-qm","fixture")
        self.source_sha=git(self.repo,"rev-parse","HEAD")
        self.workspace=self.root/"core-work"
        self.workspace.mkdir(mode=0o700)
        self.core=self.cmod.OneTaskCore(self.workspace,self.repo)
        self.spec=dict(schema="neurofactory.core.task.v1",task_id=TASK,
            project_id=PROJECT,target=TARGET,source_sha=self.source_sha,
            source_sha256=self.cmod.EMPTY_SHA,approval_commit=self.source_sha,
            model="qwen2.5-coder:1.5b",reserved_units=1,
            objective="One inert synthetic non-model file")
        self.core.enqueue(self.spec,trusted_approval_check=lambda s:s==self.spec)
        self.local_claim=self.core.claim(WORKER,now=int(time.time()),lease_seconds=180)
        self.proposal=dict(schema="neurofactory.core.proposal.v1",
            target=TARGET,content=CONTENT.decode("ascii"),
            content_sha256=hashlib.sha256(CONTENT).hexdigest(),mode="OFFLINE_TEST")
        self.input_sha=hashlib.sha256(self.cmod._canonical(self.spec)).hexdigest()
        self.conn.execute("""INSERT INTO nf_task
          (task_id,project_id,input_core_sha40,source_file_sha256,
           input_task_sha256,fixture_authorized)
           VALUES(%s,%s,%s,%s,%s,TRUE)""",
          (TASK,PROJECT,self.source_sha,self.cmod.EMPTY_SHA,self.input_sha))
        self.conn.execute("""INSERT INTO nf_effect_scope_fixture
          (task_id,project_id,input_core_sha40,source_file_sha256,
           input_task_sha256,target,policy_sha256,fixture_authorized)
           VALUES(%s,%s,%s,%s,%s,%s,%s,TRUE)""",
          (TASK,PROJECT,self.source_sha,self.cmod.EMPTY_SHA,
           self.input_sha,TARGET,POLICY_SHA))
        self.host_claim=self.hcas.OfflineCAS(self.conn).claim(
            TASK,WORKER,secrets.token_hex(16),lease_seconds=180)
        self.assertEqual(self.host_claim["status"],"CLAIMED")
        self.idempotency=secrets.token_hex(32)
        self.assertEqual(self.hreserve.OfflineEffectReservation(self.conn).reserve_once(
            task_id=TASK,project_id=PROJECT,source_sha40=self.source_sha,
            source_file_sha256=self.cmod.EMPTY_SHA,
            input_task_sha256=self.input_sha,target=TARGET,policy_sha256=POLICY_SHA,
            worker_id=WORKER,lease_epoch=self.host_claim["lease_epoch"],
            fencing_token=self.host_claim["fencing_token"],
            idempotency_key=self.idempotency)["status"],"RESERVED_OFFLINE_TEST_ONLY")
        self.conn.execute("""INSERT INTO nf_receiver_scope_fixture
             (task_id,issuer_id,key_id,owner_id,repository,operation_id,
              proposed_content_sha256) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
             (TASK,"offline-issuer","ephemeral-key","sandbox-owner",
              "DSLitvinov1/my_first_repo","operation-one",
              hashlib.sha256(CONTENT).hexdigest()))
        self.signer=Ed25519PrivateKey.generate()
        self.packet=self.make_packet()
        self.receiver=self.hreceiver.OfflineFencedFileReceiver(
            self.conn,self.receiver_root,pinned_public_key=self.signer.public_key())
        self.client=self.clientmod.CoreOfflineReceiverClient(self.core,self.receiver)

    def make_packet(self,**changes):
        t=int(time.time())
        body=dict(schema="neurofactory.trusted_host.signed_effect_permit.v1",
            purpose="EFFECT_RESERVATION_SCOPE_ONLY",
            issuer_id="offline-issuer",key_id="ephemeral-key",
            owner_id="sandbox-owner",repository="DSLitvinov1/my_first_repo",
            project_id=PROJECT,task_id=TASK,worker_id=WORKER,
            source_sha40=self.source_sha,
            source_file_sha256=self.cmod.EMPTY_SHA,
            input_task_sha256=self.input_sha,
            policy_sha256=POLICY_SHA,target=TARGET,
            proposed_content_sha256=hashlib.sha256(CONTENT).hexdigest(),
            fencing_token_sha256=hashlib.sha256(
                self.host_claim["fencing_token"].encode()).hexdigest(),
            lease_epoch=self.host_claim["lease_epoch"],
            issued_unix=t-2,expires_unix=t+90,
            idempotency_key=self.idempotency,operation_id="operation-one")
        body.update(changes)
        raw=json.dumps(body,sort_keys=True,ensure_ascii=True,
                       separators=(",",":"),allow_nan=False).encode("ascii")
        return {"payload":body,
                "signature_base64":base64.b64encode(self.signer.sign(raw)).decode("ascii")}

    def ask(self,packet=None,proposal=None):
        return self.client.propose_one_test_effect(
            task_id=TASK,core_token=self.local_claim["token"],
            worker_id=WORKER,
            proposal=self.proposal if proposal is None else proposal,
            signed_packet=self.packet if packet is None else packet)

    def output(self):
        return self.receiver_root/TARGET

    def assert_no_effect(self):
        self.assertFalse(self.output().exists())
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)

    def test_one_CORE_to_HOST_signed_receiver_file(self):
        result=self.ask()
        self.assertEqual(result["status"],"CORE_TO_HOST_ONE_EFFECT_OBSERVED_OFFLINE_ONLY")
        self.assertEqual(self.output().read_bytes(),CONTENT)
        self.assertTrue(result["one_disposable_file_effect_observed"])
        self.assertFalse(result["live_execution_allowed"])
        self.assertFalse(result["core_checkpoint_production_authorized"])
        self.assertEqual(self.conn.execute(
            "SELECT status FROM nf_receiver_effect_journal").fetchone()[0],
                         "COMPLETED_TEST")
        self.assertFalse((self.core.sandbox/TARGET).exists())
        print("NF_PINNED_CORE_HOST_RECEIVER_ONE_INERT_FILE=CONFIRMED")

    def test_blocked_host_zero_effect(self):
        self.conn.execute("UPDATE nf_task SET phase='BLOCKED' WHERE task_id=%s",
                          (TASK,))
        with self.assertRaises(self.hreceiver.OfflineReceiverDenied):
            self.ask()
        self.assert_no_effect()

    def test_unknown_host_zero_effect(self):
        self.conn.execute("UPDATE nf_task SET phase='UNKNOWN' WHERE task_id=%s",
                          (TASK,))
        with self.assertRaises(self.hreceiver.OfflineReceiverDenied):
            self.ask()
        self.assert_no_effect()

    def test_expired_host_lease_zero_effect(self):
        self.conn.execute("UPDATE nf_task SET lease_deadline=clock_timestamp() - "
                          "interval '2 seconds' WHERE task_id=%s",(TASK,))
        with self.assertRaises(self.hreceiver.OfflineReceiverDenied):
            self.ask()
        self.assert_no_effect()

    def test_stale_worker_or_epoch_zero_effect(self):
        for query in (
            "UPDATE nf_task SET holder_id='old-worker' WHERE task_id=%s",
            "UPDATE nf_task SET lease_epoch=lease_epoch+1 WHERE task_id=%s",
        ):
            with self.subTest(query=query):
                self.conn.execute(query,(TASK,))
                with self.assertRaises(self.hreceiver.OfflineReceiverDenied):
                    self.ask()
                self.assert_no_effect()
                self.conn.execute("UPDATE nf_task SET holder_id=%s,lease_epoch=%s WHERE task_id=%s",
                                  (WORKER,self.host_claim["lease_epoch"],TASK))

    def test_replay_after_effect_does_not_modify_file(self):
        self.ask()
        before=self.output().stat()
        with self.assertRaises(self.hreceiver.OfflineReceiverDenied):
            self.ask()
        after=self.output().stat()
        self.assertEqual((before.st_ino,before.st_mtime_ns),
                         (after.st_ino,after.st_mtime_ns))
        self.assertEqual(self.output().read_bytes(),CONTENT)
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],1)

    def test_forged_signer_or_changed_signed_target_zero_effect(self):
        valid=self.packet
        attacker=Ed25519PrivateKey.generate()
        packet=dict(valid,signature_base64=base64.b64encode(
            attacker.sign(b"fake-authority")).decode())
        with self.assertRaises(self.hreceiver.OfflineReceiverDenied):
            self.ask(packet=packet)
        self.assert_no_effect()
        mismatch=self.make_packet(target="bridge/neurofactory/development/core_owned/other.txt")
        with self.assertRaises(self.clientmod.OfflineProtectedRouteDenied):
            self.ask(packet=mismatch)
        self.assert_no_effect()

    def test_crash_after_fsync_unknown_no_retry(self):
        with self.assertRaises(self.hreceiver.OfflineEffectUnknown):
            self.receiver.write_fixture_once(
                signed_packet=self.packet,content=CONTENT,
                simulate_crash_after_fsync=True)
        self.assertEqual(self.output().read_bytes(),CONTENT)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM nf_receiver_effect_journal").fetchone()[0],
            "UNKNOWN")
        with self.assertRaises(self.hreceiver.OfflineReceiverDenied):
            self.ask()
        self.assertEqual(self.output().read_bytes(),CONTENT)

if __name__=="__main__":
    unittest.main()
