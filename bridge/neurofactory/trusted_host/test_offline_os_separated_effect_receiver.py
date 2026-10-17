"""Three REAL independent Linux UIDs on ONE temporary runner (NOT 2 PCs).

Signer's private key never leaves nf_signer. nf_db_actor (worker / DB actor)
cannot traverse or write the private receiver-owned root or receiver config.
ONLY nf_effect OS UID invokes the actual O_EXCL/PG-fenced test file receiver.
All accounts, credentials, keys, DB and files are disposable synthetic CI.
"""
import base64, hashlib, json, os, subprocess, tempfile, time, unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from offline_operator_anchor import _canonical
from test_offline_fenced_file_receiver import (
    TestSignedLiveLeaseOfflineEffect as BasePG, CONTENT, TARGET)
PY=os.environ.get("NF_OPERATOR_TEST_PYTHON")
STAGE=Path(os.environ.get("NF_OPERATOR_IPC_STAGED_SOURCE","/nonexistent")).parent
SIGNER=STAGE/"offline_operator_anchor.py"
SIGNER_SERVER=STAGE/"offline_operator_ipc.py"
RECEIVER_SERVER=STAGE/"offline_os_separated_effect_receiver.py"

def run_uid(uid,*args,input=None,timeout=9):
    return subprocess.run(["sudo","-n","-u",uid,"env",
       "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",
       "NF_HOST_RECEIVER_FIXTURE_ONLY=1","NF_RECEIVER_OS_FIXTURE_ONLY=1",
       PY,*map(str,args)],capture_output=True,input=input,
       text=input is None,timeout=timeout)
def uid(name):
    return int(subprocess.check_output(["id","-u",name],text=True).strip())

class ProtectedReceiverThreePrincipalE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PY or os.name!="posix" or os.environ.get("NF_RECEIVER_OS_FIXTURE_ONLY")!="1":
            raise RuntimeError("nonlive Linux fixture only")
        BasePG.setUpClass()
        cls.addClassCleanup(BasePG.doClassCleanups)

    def setUp(self):
        self.fx=BasePG("test_actual_one_file_written_and_fsynced_with_no_live_permit")
        self.fx.setUp()
        self.addCleanup(self.cleanup_fx)
        self.temp=tempfile.TemporaryDirectory(prefix="nf-threeuid-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o755)
        self.home=self.root/"nf-signer-fixture"
        self.signer_api=self.root/"nf-operator-api"
        self.signer_socket=self.signer_api/"nf-readonly-operator.sock"
        self.receiver_config=self.root/"nf-recipient-config"
        self.receiver_api=self.root/"nf-recipient-ipc"
        self.receiver_socket=self.receiver_api/"nf-recipient.sock"
        self.reqfile=self.root/"request.json"
        self.signer_proc=None;self.recipient_proc=None
        self.addCleanup(self.stop_services)
        for dirname,who,group,mode in [
            (self.home,"nf_signer","nf_signer","0700"),
            (self.signer_api,"nf_signer","nf_operator_ipc","2750"),
            (self.receiver_config,"nf_effect","nf_effect","0700"),
            (self.receiver_api,"nf_effect","nf_recipient_ipc","2750")]:
            subprocess.run(["sudo","-n","install","-d","-o",who,"-g",group,
                "-m",mode,str(dirname)],check=True)
        boot=run_uid("nf_signer",SIGNER,"bootstrap",self.home)
        self.assertEqual(boot.returncode,0,boot.stderr)
        self.bootstrap=json.loads(boot.stdout)
        body=self.fx.packet["payload"]
        digest=hashlib.sha256(_canonical(body)).hexdigest()
        signed=run_uid("nf_signer",SIGNER,"advance",self.home,digest)
        self.assertEqual(signed.returncode,0,signed.stderr)
        self.witness=json.loads(signed.stdout)
        effect_pub=self.fx.private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        keys=("issuer_id","key_id","owner_id","repository","project_id","task_id",
              "worker_id","source_sha40","source_file_sha256","input_task_sha256",
              "policy_sha256","target","proposed_content_sha256",
              "fencing_token_sha256","lease_epoch","idempotency_key","operation_id")
        policy={"schema":"neurofactory.operator.scope_fixture.v1",
              "expected":{k:body[k] for k in keys},
              "pinned_public_sha256":self.bootstrap["public_key_sha256"],
              "allowed_claim_sha256":digest,
              "effect_issuer_public_b64":base64.b64encode(effect_pub).decode()}
        self.saver=("import os,sys;f=os.open(sys.argv[1],"
                    "os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);"
                    "os.write(f,sys.stdin.buffer.read());os.fsync(f);os.close(f)")
        self.private_write("nf_signer",self.home/"pinned-effect-scope.json",policy)
        config={
            "schema":"neurofactory.os_separated_recipient.fixture.v1",
            "receiver_root":str(self.fx.root),
            "recipient_socket":str(self.receiver_socket),
            "peer_worker_uid":uid("nf_db_actor"),
            "signer_socket":str(self.signer_socket),
            "signer_uid":uid("nf_signer"),
            "signer_public_sha":self.bootstrap["public_key_sha256"],
            "signer_public_base64":self.bootstrap["public_key_base64"],
            "issuer_public_base64":base64.b64encode(effect_pub).decode()}
        self.private_write("nf_effect",self.receiver_config/"receiver.json",config)
        # Critical: filesystem and all ancestors belong only to nf_effect.
        subprocess.run(["sudo","-n","chown","-R","nf_effect:nf_effect",
                        str(self.fx.root.parent)],check=True)
        self.config=config
        self.write_request()
    def private_write(self,who,path,doc):
        p=subprocess.run(["sudo","-n","-u",who,PY,"-c",self.saver,str(path)],
                         input=_canonical(doc),capture_output=True,timeout=6)
        self.assertEqual(p.returncode,0,p.stderr[:240])
    def cleanup_fx(self):
        subprocess.run(["sudo","-n","chown","-R",
            str(os.getuid())+":"+str(os.getgid()),str(self.fx.root.parent)],
            check=True)
        self.fx.doCleanups()
    def stop_services(self):
        for proc in (self.signer_proc,self.recipient_proc):
            if proc and proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=3)
                except subprocess.TimeoutExpired:proc.kill()
        subprocess.run(["sudo","-n","rm","-rf","--",str(self.home),
            str(self.signer_api),str(self.receiver_config),
            str(self.receiver_api)],check=True)
    def write_request(self,packet=None,witness=None,content=CONTENT, extra=None):
        request={
            "schema":"neurofactory.recipient.request.fixture.v1",
            "signed_packet":self.fx.packet if packet is None else packet,
            "witness":self.witness if witness is None else witness,
            "content_base64":base64.b64encode(content).decode()}
        if extra:request.update(extra)
        self.reqfile.write_text(json.dumps(request),encoding="ascii")
        self.reqfile.chmod(0o644)
    def ready(self,who,sock,proc):
        for _ in range(100):
            t=subprocess.run(["sudo","-n","-u",who,"test","-S",str(sock)],
               capture_output=True)
            if t.returncode==0:return
            if proc.poll() is not None:
                raise AssertionError(who+" exited: "+proc.stderr.read()[:550])
            time.sleep(.03)
        raise AssertionError("no Unix listener from "+who)
    def start(self,*,start_signer=True):
        if start_signer:
            self.signer_proc=subprocess.Popen(["sudo","-n","-u","nf_signer","env",
                "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",PY,str(SIGNER_SERVER),"serve",
                str(self.home),str(self.signer_socket),str(uid("nf_effect"))],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            self.ready("nf_signer",self.signer_socket,self.signer_proc)
        self.recipient_proc=subprocess.Popen(["sudo","-n","-u","nf_effect","env",
           "NF_HOST_RECEIVER_FIXTURE_ONLY=1",
           "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",
           "NF_RECEIVER_OS_FIXTURE_ONLY=1",
           "PYTHONPATH="+str(STAGE),PY,str(RECEIVER_SERVER),
           str(self.receiver_config)],
           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.ready("nf_effect",self.receiver_socket,self.recipient_proc)
    def send(self,*,start_signer=True):
        self.start(start_signer=start_signer)
        code=("import json,socket,sys;"
              "s=socket.socket(socket.AF_UNIX);s.settimeout(7);"
              "s.connect(sys.argv[1]);"
              "s.sendall(open(sys.argv[2],'rb').read());"
              "r=s.recv(4000);print(r.decode('ascii'))")
        reply=run_uid("nf_db_actor","-c",code,self.receiver_socket,self.reqfile)
        self.assertEqual(reply.returncode,0,reply.stderr)
        self.assertTrue(reply.stdout.strip())
        data=json.loads(reply.stdout)
        self.recipient_proc.wait(timeout=4)
        if self.signer_proc and self.signer_proc.poll() is None:
            self.signer_proc.terminate()
            self.signer_proc.wait(timeout=4)
        self.signer_proc=None;self.recipient_proc=None
        return data
    def hash_file_from_recipient_uid(self):
        code=("import sys,hashlib;from pathlib import Path;"
              "print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())")
        out=run_uid("nf_effect","-c",code,self.fx.root/TARGET)
        self.assertEqual(out.returncode,0,out.stderr)
        return out.stdout.strip()
    def test_untrusted_worker_cannot_open_protected_writer_directory(self):
        denied=run_uid("nf_db_actor","-c",
            "import sys,os;open(sys.argv[1],'wb').write(b'WRONG')",
            self.fx.root/"nf-worker-direct.txt")
        self.assertNotEqual(denied.returncode,0)
        config=run_uid("nf_db_actor","-c",
            "import sys;open(sys.argv[1]).read()",self.receiver_config/"receiver.json")
        self.assertNotEqual(config.returncode,0)
        signer=run_uid("nf_db_actor","-c",
            "import sys;open(sys.argv[1]).read()",self.home/"issuer-private.raw")
        self.assertNotEqual(signer.returncode,0)
        self.assertFalse(self.fx.fspath().exists())
    def test_one_actual_file_with_three_distinct_uid_and_receipt(self):
        res=self.send()
        self.assertEqual(res["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        self.assertFalse(res["live_execution_allowed"])
        self.assertEqual(self.hash_file_from_recipient_uid(),res["file_sha256"])
        self.assertEqual(self.fx.db.execute("SELECT status FROM nf_receiver_effect_journal").fetchone()[0],
                         "COMPLETED_TEST")
        print("NF_3_UID_PROTECTED_RECEIVER_REAL_FILE_ONCE",flush=True)
    def test_replayed_delivery_no_new_effect(self):
        self.assertEqual(self.send()["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],1)
        print("NF_3_UID_REPLAY_DENIED",flush=True)
    def test_forged_owner_is_denied_before_intent(self):
        bad={"payload":dict(self.fx.packet["payload"],owner_id="unauthorized"),
             "signature_base64":self.fx.packet["signature_base64"]}
        self.write_request(packet=bad)
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
    def test_lost_signer_refuses_effect(self):
        self.assertEqual(self.send(start_signer=False)["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
    def test_expired_pg_lease_denies_without_file(self):
        self.fx.db.execute("UPDATE nf_task SET lease_deadline=clock_timestamp()-interval '1 second'")
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
    def test_old_signer_tip_after_second_step_denied(self):
        updated=run_uid("nf_signer",SIGNER,"advance",self.home,
                        hashlib.sha256(b"second protected signer event").hexdigest())
        self.assertEqual(updated.returncode,0,updated.stderr)
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
    def test_restored_db_unknown_intent_without_manual_reconciliation_denies(self):
        self.assertEqual(self.send()["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        self.fx.db.execute("UPDATE nf_receiver_effect_journal SET status='UNKNOWN'")
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.fx.db.execute("SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],1)
        self.assertEqual(self.hash_file_from_recipient_uid(),hashlib.sha256(CONTENT).hexdigest())

def load_tests(loader,tests,pattern):
    return loader.loadTestsFromTestCase(ProtectedReceiverThreePrincipalE2E)
if __name__=="__main__":unittest.main()
