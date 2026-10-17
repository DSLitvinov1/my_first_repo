"""One ACTUAL disposable filesystem effect, signer-owned IPC + PG HOST CAS.

Linux only, two distinct short-lived OS UIDs on one GitHub runner; signer
never hands its private key to DB actor. This does not prove a production
trusted host, human owner admission or two physical computers.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

from cryptography.hazmat.primitives import serialization

from test_offline_fenced_file_receiver import (
    TestSignedLiveLeaseOfflineEffect as BasePG)
from offline_operator_anchor import _canonical

PY=os.environ.get("NF_OPERATOR_TEST_PYTHON")
STAGE=Path(os.environ.get("NF_OPERATOR_IPC_STAGED_SOURCE","/nonexistent")).parent
SIGNER=STAGE/"offline_operator_anchor.py"
SERVER=STAGE/"offline_operator_ipc.py"
DSN="postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"

def user(user,*args,input=None,timeout=10):
    return subprocess.run(["sudo","-n","-u",user,"env",
        "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",
        "NF_HOST_RECEIVER_FIXTURE_ONLY=1",PY,*map(str,args)],
        input=input,capture_output=True,text=(input is None),timeout=timeout)

class RealSignedOperatorBoundHostEffect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PY or os.name!="posix" or os.environ.get("NF_HOST_RECEIVER_FIXTURE_ONLY")!="1":
            raise RuntimeError("not disposable Linux runner")
        BasePG.setUpClass()
        cls.addClassCleanup(BasePG.doClassCleanups)
    def setUp(self):
        self.fx=BasePG("test_actual_one_file_written_and_fsynced_with_no_live_permit")
        self.fx.setUp()
        self.addCleanup(self.finish_fx)
        self.temp=tempfile.TemporaryDirectory(prefix="nf-gated-ci-")
        self.addCleanup(self.temp.cleanup)
        self.work=Path(self.temp.name);self.work.chmod(0o755)
        self.home=self.work/"nf-signer-fixture"
        self.api=self.work/"nf-operator-api"
        self.sock=self.api/"nf-readonly-operator.sock"
        subprocess.run(["sudo","-n","mkdir",str(self.home),str(self.api)],check=True)
        subprocess.run(["sudo","-n","chown","nf_signer:nf_signer",
                        str(self.home),str(self.api)],check=True)
        subprocess.run(["sudo","-n","chmod","0700",str(self.home)],check=True)
        subprocess.run(["sudo","-n","chgrp","nf_operator_ipc",str(self.api)],check=True)
        subprocess.run(["sudo","-n","chmod","2750",str(self.api)],check=True)
        boot=user("nf_signer",SIGNER,"bootstrap",self.home)
        self.assertEqual(boot.returncode,0,boot.stderr)
        self.pin=json.loads(boot.stdout)
        payload=self.fx.packet["payload"]
        claim=hashlib.sha256(_canonical(payload)).hexdigest()
        advance=user("nf_signer",SIGNER,"advance",self.home,claim)
        self.assertEqual(advance.returncode,0,advance.stderr)
        self.witness=json.loads(advance.stdout)
        pub=self.fx.private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        keys=("issuer_id","key_id","owner_id","repository","project_id","task_id",
            "worker_id","source_sha40","source_file_sha256","input_task_sha256",
            "policy_sha256","target","proposed_content_sha256",
            "fencing_token_sha256","lease_epoch","idempotency_key","operation_id")
        policy={"schema":"neurofactory.operator.scope_fixture.v1",
           "expected":{k:payload[k] for k in keys},
           "pinned_public_sha256":self.pin["public_key_sha256"],
           "allowed_claim_sha256":claim,
           "effect_issuer_public_b64":base64.b64encode(pub).decode("ascii")}
        program=("import os,sys;fd=os.open(sys.argv[1],"
                 "os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);"
                 "os.write(fd,sys.stdin.buffer.read());os.fsync(fd);os.close(fd)")
        write_policy=subprocess.run(["sudo","-n","-u","nf_signer",PY,
                "-c",program,str(self.home/"pinned-effect-scope.json")],
                input=_canonical(policy),capture_output=True,timeout=5)
        self.assertEqual(write_policy.returncode,0,write_policy.stderr[:150])
        self.fx.root_owner_before=os.geteuid()
        subprocess.run(["sudo","-n","chown","-R","nf_db_actor:nf_db_actor",
                        str(self.fx.root.parent)],check=True)
        self.host_root=self.fx.root
        self.reqfile=self.work/"request.json"
        self.write_request()
        self.proc=None
        self.addCleanup(self.stop_server)
    def finish_fx(self):
        subprocess.run(["sudo","-n","chown","-R",
             str(os.getuid())+":"+str(os.getgid()),
             str(self.fx.root.parent)],check=True)
        self.fx.doCleanups()
    def stop_server(self):
        if getattr(self,"proc",None) is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:self.proc.kill()
        subprocess.run(["sudo","-n","rm","-rf","--",str(self.home),str(self.api)],check=True)
    def write_request(self, packet=None,witness=None):
        req={"packet":self.fx.packet if packet is None else packet,
             "witness":self.witness if witness is None else witness,
             "content_base64":base64.b64encode(self.fx.CONTENT
                if hasattr(self.fx,"CONTENT") else
                __import__("test_offline_fenced_file_receiver").CONTENT).decode(),
             "root":str(self.host_root),
             "pinned_sha":self.pin["public_key_sha256"],
             "pinned_public":self.pin["public_key_base64"],
             "issuer_public":base64.b64encode(self.fx.private.public_key().public_bytes(
                  serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode(),
             "socket":str(self.sock),
             "signer_uid":int(subprocess.check_output(["id","-u","nf_signer"],text=True).strip())}
        self.reqfile.write_text(json.dumps(req),encoding="ascii")
        self.reqfile.chmod(0o644)
    def start_signer(self):
        uid=int(subprocess.check_output(["id","-u","nf_db_actor"],text=True).strip())
        self.proc=subprocess.Popen(["sudo","-n","-u","nf_signer","env",
              "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",PY,str(SERVER),"serve",
              str(self.home),str(self.sock),str(uid)],
              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        for _ in range(80):
            p=subprocess.run(["sudo","-n","-u","nf_signer","test","-S",
                               str(self.sock)],capture_output=True)
            if p.returncode==0:return
            if self.proc.poll() is not None:
                self.fail("signer exited: "+self.proc.stderr.read()[:180])
            time.sleep(.04)
        self.fail("signer never accepted socket")
    def child_apply(self,*,start_signer=True):
        if start_signer:self.start_signer()
        child=("import sys,json,base64;import psycopg;"
          "from offline_fenced_file_receiver import OfflineFencedFileReceiver;"
          "from offline_operator_gated_receiver import OperatorGatedOfflineReceiver;"
          "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey;"
          "req=json.load(open(sys.argv[1]));"
          "db=psycopg.connect(sys.argv[2],autocommit=True);"
          "db.execute(\"SET neurofactory.offline_fixture_mode TO 'on'\");"
          "key=Ed25519PublicKey.from_public_bytes(base64.b64decode(req['issuer_public']));"
          "r=OfflineFencedFileReceiver(db,req['root'],pinned_public_key=key);"
          "client=OperatorGatedOfflineReceiver(r,socket_path=req['socket'],"
          "pinned_signer_uid=req['signer_uid'],"
          "independently_pinned_public_sha=req['pinned_sha'],"
          "independently_pinned_public_b64=req['pinned_public']);"
          "out=client.apply_fixture_with_operator_witness_once("
          "signed_packet=req['packet'],witness=req['witness'],"
          "content=base64.b64decode(req['content_base64']));"
          "print(json.dumps(out))")
        return subprocess.run(["sudo","-n","-u","nf_db_actor","env",
           "PYTHONPATH="+str(STAGE),
           "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",
           "NF_HOST_RECEIVER_FIXTURE_ONLY=1",
           PY,"-c",child,str(self.reqfile),DSN],
           capture_output=True,text=True,timeout=8)
    def read_file(self):
        target=__import__("test_offline_fenced_file_receiver").TARGET
        script=("from pathlib import Path;import sys,hashlib;"
                "p=Path(sys.argv[1]);"
                "print(hashlib.sha256(p.read_bytes()).hexdigest())")
        run=user("nf_db_actor","-c",script,self.host_root/target)
        self.assertEqual(run.returncode,0,run.stderr)
        return run.stdout.strip()
    def test_new_operator_signed_scope_leads_to_one_real_file_and_receipt(self):
        run=self.child_apply()
        self.assertEqual(run.returncode,0,run.stderr[:600])
        ret=json.loads(run.stdout)
        self.assertEqual(ret["status"],"ONE_SIGNER_SCOPE_GATED_FIXTURE_FILE_ONLY")
        self.assertFalse(ret["live_execution_allowed"])
        self.assertEqual(self.read_file(),ret["content_sha256"])
        self.assertEqual(self.fx.db.execute("SELECT status FROM nf_receiver_effect_journal").fetchone()[0],"COMPLETED_TEST")
        print("HOST_SIGNER_UID_TO_FILE_ONE_DISPOSABLE_EFFECT_PASSED",flush=True)
    def test_exact_same_signed_operation_is_not_repeatable(self):
        self.assertEqual(self.child_apply().returncode,0)
        self.proc.wait(timeout=3);self.proc=None
        repeat=self.child_apply()
        self.assertNotEqual(repeat.returncode,0)
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],1)
        print("HOST_SIGNER_UID_TO_FILE_REPLAY_DENIED",flush=True)
    def test_owner_forgery_denied_before_filing_unknown_intent(self):
        packet={"payload":dict(self.fx.packet["payload"],owner_id="wrong-owner"),
                "signature_base64":self.fx.packet["signature_base64"]}
        self.write_request(packet=packet)
        res=self.child_apply()
        self.assertNotEqual(res.returncode,0)
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
    def test_db_rollback_of_valid_old_signer_head_denies_effect(self):
        old=self.witness
        newer=user("nf_signer",SIGNER,"advance",self.home,hashlib.sha256(b"other").hexdigest())
        self.assertEqual(newer.returncode,0,newer.stderr)
        self.write_request(witness=old)
        res=self.child_apply()
        self.assertNotEqual(res.returncode,0)
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
    def test_signer_offline_blocks_file_creation(self):
        res=self.child_apply(start_signer=False)
        self.assertNotEqual(res.returncode,0)
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
    def test_expired_live_postgresql_lease_denies_after_signed_scope(self):
        self.fx.db.execute("UPDATE nf_task SET lease_deadline=clock_timestamp()-interval '1 second'")
        res=self.child_apply()
        self.assertNotEqual(res.returncode,0)
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)

def load_tests(loader, tests, pattern):
    # BasePG is imported as a fixture helper, not a second unchanged test
    # matrix. Target just the six new signer→HOST final-effect cases.
    return loader.loadTestsFromTestCase(RealSignedOperatorBoundHostEffect)

if __name__=="__main__":unittest.main()
