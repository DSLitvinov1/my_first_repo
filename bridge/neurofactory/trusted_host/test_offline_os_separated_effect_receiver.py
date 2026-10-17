"""Three REAL independent Linux UIDs on ONE temporary runner (NOT 2 PCs).

Signer's private key never leaves nf_signer. nf_db_actor (worker / DB actor)
cannot traverse or write the private receiver-owned root or receiver config.
ONLY nf_effect OS UID invokes the actual O_EXCL/PG-fenced test file receiver.
All accounts, credentials, keys, DB and files are disposable synthetic CI.
"""
import base64, hashlib, json, os, subprocess, tempfile, time, unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
       "PYTHONPATH="+str(STAGE),PY,*map(str,args)],capture_output=True,input=input,
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
        self.owner_private=Ed25519PrivateKey.generate()
        owner_pub=self.owner_private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        owner_enrollment={
            "schema":"neurofactory.owner.authority_pin_fixture.v1",
            "owner_id":body["owner_id"],
            "repository":body["repository"],
            "project_id":body["project_id"],
            "owner_public_key_base64":base64.b64encode(owner_pub).decode(),
            "operator_pinned_fingerprint":hashlib.sha256(owner_pub).hexdigest()}
        self.private_write("nf_signer",self.home/"pinned-project-owner-authority.json",
                           owner_enrollment)
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
    def owner_grant(self,packet=None):
        payload=self.fx.packet["payload"] if packet is None else packet["payload"]
        names=("owner_id","repository","project_id","task_id","worker_id",
               "source_sha40","target","operation_id","lease_epoch")
        statement={k:payload[k] for k in names}
        statement["permit_sha256"]=hashlib.sha256(_canonical(payload)).hexdigest()
        statement["expires_unix"]=min(payload["expires_unix"],int(time.time())+45)
        return {"statement":statement,
                "signature_base64":base64.b64encode(
                    self.owner_private.sign(_canonical(statement))).decode()}
    def write_request(self,packet=None,witness=None,content=CONTENT, extra=None):
        packet=self.fx.packet if packet is None else packet
        request={
            "schema":"neurofactory.recipient.request.fixture.v1",
            "signed_packet":packet,
            "witness":self.witness if witness is None else witness,
            "signed_owner_grant":self.owner_grant(packet),
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
    def start(self,*,start_signer=True,crash_after_fsync=False):
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
           "NF_RECEIVER_TEST_SIMULATE_POST_FSYNC_CRASH="+("1" if crash_after_fsync else "0"),
           "PYTHONPATH="+str(STAGE),PY,str(RECEIVER_SERVER),
           str(self.receiver_config)],
           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.ready("nf_effect",self.receiver_socket,self.recipient_proc)
    def send(self,*,start_signer=True,crash_after_fsync=False):
        self.start(start_signer=start_signer,crash_after_fsync=crash_after_fsync)
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
    def hash_file_from_recipient_uid(self,target=TARGET):
        code=("import sys,hashlib;from pathlib import Path;"
              "print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())")
        out=run_uid("nf_effect","-c",code,self.fx.root/target)
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
        # The untrusted test runner cannot even stat the protected root.
        # Assert absence from the actual recipient's UID instead.
        self.assertNotEqual(subprocess.run(
            ["sudo","-n","-u","nf_effect","test","-e",str(self.fx.fspath())],
            capture_output=True).returncode,0)
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

    def test_qwen_generated_python_bytes_through_protected_receiver_once(self):
        # This is EXACT text observed in genuine model inference CI #39063107445,
        # not a fresh model call here, and it is not an owner-approved project.
        generated="def add_two(a, b):\n    \"\"\"\n    Add two numbers a and b.\n    Parameters:\n    a (int): The first number.\n    b (int): The second number.\n    Returns:\n    int: The sum of a and b.\n    \"\"\"\n    return a + b"
        content=generated.encode("utf8")
        digest=hashlib.sha256(content).hexdigest()
        self.assertEqual(digest,"a271172a3cdc4f02374565dcd0e4f2d21a8b734c807dc784a2136d2d992ceefe")
        target="bridge/neurofactory/development/core_owned/qwen_generated_add_sandbox.py"
        # The temporary operator, never the model/worker, provisions a new
        # exact signer-owned scope for the previously checked model bytes.
        self.fx.db.execute("UPDATE nf_effect_intent SET target=%s",(target,))
        self.fx.db.execute("UPDATE nf_effect_scope_fixture SET target=%s",(target,))
        self.fx.db.execute(
            "UPDATE nf_receiver_scope_fixture SET proposed_content_sha256=%s",(digest,))
        body=dict(self.fx.packet["payload"],target=target,
                  proposed_content_sha256=digest)
        self.fx.packet=self.fx._sign(body)
        newclaim=hashlib.sha256(_canonical(body)).hexdigest()
        second=run_uid("nf_signer",SIGNER,"advance",self.home,newclaim)
        self.assertEqual(second.returncode,0,second.stderr)
        self.witness=json.loads(second.stdout)
        effect_pub=self.fx.private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        keys=("issuer_id","key_id","owner_id","repository","project_id","task_id",
              "worker_id","source_sha40","source_file_sha256","input_task_sha256",
              "policy_sha256","target","proposed_content_sha256",
              "fencing_token_sha256","lease_epoch","idempotency_key","operation_id")
        policy={"schema":"neurofactory.operator.scope_fixture.v1",
             "expected":{k:body[k] for k in keys},
             "pinned_public_sha256":self.bootstrap["public_key_sha256"],
             "allowed_claim_sha256":newclaim,
             "effect_issuer_public_b64":base64.b64encode(effect_pub).decode("ascii")}
        # Test operator OS principal does the fixture policy transition.
        policyfile=self.home/"pinned-effect-scope.json"
        deleted=run_uid("nf_signer","-c",
            "from pathlib import Path;import sys;Path(sys.argv[1]).unlink()",policyfile)
        self.assertEqual(deleted.returncode,0,deleted.stderr)
        self.private_write("nf_signer",policyfile,policy)
        self.write_request(packet=self.fx.packet,witness=self.witness,content=content)
        first=self.send()
        self.assertEqual(first["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        self.assertEqual(self.hash_file_from_recipient_uid(target),digest)
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],1)
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.hash_file_from_recipient_uid(target),digest)
        print("NF_QWEN_GENUINE_SHA_TO_PRIVILEGED_TEST_FILE_ONCE",flush=True)

    def test_real_core_claim_to_protected_recipient_for_previous_qwen_generated_code(self):
        # This uses OneTaskCore's ACTUAL SQLite task and Git preimage,
        # not a fabricated JSON-only CORE grant. The program was genuinely
        # generated by CPU Qwen CI #39063107445; no model run in this test.
        generated="def add_two(a, b):\n    \"\"\"\n    Add two numbers a and b.\n    Parameters:\n    a (int): The first number.\n    b (int): The second number.\n    Returns:\n    int: The sum of a and b.\n    \"\"\"\n    return a + b"
        content=generated.encode("utf8")
        digest=hashlib.sha256(content).hexdigest()
        self.assertEqual(digest,"a271172a3cdc4f02374565dcd0e4f2d21a8b734c807dc784a2136d2d992ceefe")
        task=self.fx.packet["payload"]["task_id"]
        target="bridge/neurofactory/development/core_owned/qwen_from_real_core.py"
        core_root=self.root/"nf-core-worker-state"
        source_repo=self.root/"nf-worker-local-git"
        subprocess.run(["sudo","-n","install","-d","-m","0700",
            "-o","nf_db_actor","-g","nf_db_actor",str(core_root),str(source_repo)],
            check=True)
        # CI test runner does not have owner rights to delete worker-private
        # sandbox. Restore only scratch test ownership before TemporaryDirectory
        # cleanup, without changing the real protected HOST root.
        self.addCleanup(lambda:subprocess.run(["sudo","-n","chown","-R",
            str(os.getuid())+":"+str(os.getgid()),str(core_root),str(source_repo)],
            check=True))
        creator=("import pathlib,sys,subprocess,json,hashlib,time;"
          "from one_task_core import OneTaskCore,EMPTY_SHA,_canonical;"
          "root=pathlib.Path(sys.argv[1]);"
          "repo=pathlib.Path(sys.argv[2]);"
          "repo.mkdir(mode=0o700,exist_ok=True);"
          "subprocess.run(['git','init','-q',str(repo)],check=True);"
          "subprocess.run(['git','-C',str(repo),'config','user.name','NF fixture'],check=True);"
          "subprocess.run(['git','-C',str(repo),'config','user.email','nf@invalid.test'],check=True);"
          "(repo/'README.md').write_text('temporary synthetic CORE input');"
          "subprocess.run(['git','-C',str(repo),'add','README.md'],check=True);"
          "subprocess.run(['git','-C',str(repo),'commit','-qm','synthetic source'],check=True);"
          "source=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip();"
          "spec={'schema':'neurofactory.core.task.v1','task_id':sys.argv[3],"
          "'project_id':'nf-sandbox','target':sys.argv[4],"
          "'objective':'Stage only a previously verified Qwen snippet in temporary files',"
          "'source_sha':source,'source_sha256':EMPTY_SHA,'approval_commit':source,"
          "'model':'qwen3:0.6b','reserved_units':5};"
          "core=OneTaskCore(root,repo);"
          "core.enqueue(spec,trusted_approval_check=lambda x:x==spec);"
          "claimed=core.claim('worker-sandbox-01',now=int(time.time()),lease_seconds=120);"
          "print(json.dumps({'spec':spec,'token':claimed['token'],"
          "'task_sha256':hashlib.sha256(_canonical(spec)).hexdigest()}))")
        prep=run_uid("nf_db_actor","-c",creator,core_root,source_repo,task,target)
        self.assertEqual(prep.returncode,0,prep.stderr[:900])
        state=json.loads(prep.stdout)
        spec=state["spec"]
        task_sha=state["task_sha256"]
        self.fx.db.execute(
          "UPDATE nf_task SET input_core_sha40=%s,input_task_sha256=%s",
          (spec["source_sha"],task_sha))
        self.fx.db.execute(
          "UPDATE nf_effect_scope_fixture SET input_core_sha40=%s,input_task_sha256=%s,target=%s",
          (spec["source_sha"],task_sha,target))
        self.fx.db.execute(
          "UPDATE nf_effect_intent SET source_sha40=%s,input_task_sha256=%s,target=%s",
          (spec["source_sha"],task_sha,target))
        self.fx.db.execute(
          "UPDATE nf_receiver_scope_fixture SET proposed_content_sha256=%s",(digest,))
        signed_body=dict(self.fx.packet["payload"],
          source_sha40=spec["source_sha"],input_task_sha256=task_sha,
          target=target,proposed_content_sha256=digest)
        self.fx.packet=self.fx._sign(signed_body)
        claim=hashlib.sha256(_canonical(signed_body)).hexdigest()
        step=run_uid("nf_signer",SIGNER,"advance",self.home,claim)
        self.assertEqual(step.returncode,0,step.stderr)
        self.witness=json.loads(step.stdout)
        pub=self.fx.private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        fields=("issuer_id","key_id","owner_id","repository","project_id","task_id",
            "worker_id","source_sha40","source_file_sha256","input_task_sha256",
            "policy_sha256","target","proposed_content_sha256",
            "fencing_token_sha256","lease_epoch","idempotency_key","operation_id")
        trusted_policy={
            "schema":"neurofactory.operator.scope_fixture.v1",
            "expected":{k:signed_body[k] for k in fields},
            "pinned_public_sha256":self.bootstrap["public_key_sha256"],
            "allowed_claim_sha256":claim,
            "effect_issuer_public_b64":base64.b64encode(pub).decode("ascii")}
        policy_path=self.home/"pinned-effect-scope.json"
        deleted=run_uid("nf_signer","-c",
            "from pathlib import Path;import sys;Path(sys.argv[1]).unlink()",
            policy_path)
        self.assertEqual(deleted.returncode,0,deleted.stderr)
        self.private_write("nf_signer",policy_path,trusted_policy)
        self.write_request(packet=self.fx.packet,witness=self.witness,content=content)
        proposal={"schema":"neurofactory.core.proposal.v1",
                  "target":target,"content":generated,"content_sha256":digest,
                  "mode":"OFFLINE_TEST"}
        core_request={
            "core_root":str(core_root),"core_repo":str(source_repo),
            "task_id":task,"worker_id":"worker-sandbox-01",
            "core_token":state["token"],"proposal":proposal,
            "signed_packet":self.fx.packet,"witness":self.witness,
            "signed_owner_grant":self.owner_grant(self.fx.packet),
            "recipient_socket":str(self.receiver_socket),
            "receiver_uid":uid("nf_effect")}
        core_file=self.root/"core-request.json"
        core_file.write_text(json.dumps(core_request),encoding="ascii")
        core_file.chmod(0o644)
        # CORE really reads its SQLite checkpoint and task/source snapshot.
        script=("import sys,json;from pathlib import Path;"
          "from one_task_core import OneTaskCore;"
          "from offline_os_receiver_client import CoreProtectedUnixReceiverClient;"
          "r=json.load(open(sys.argv[1]));"
          "core=OneTaskCore(Path(r['core_root']),Path(r['core_repo']));"
          "client=CoreProtectedUnixReceiverClient(core,"
          "socket_path=r['recipient_socket'],pinned_receiver_uid=r['receiver_uid']);"
          "result=client.propose_once(task_id=r['task_id'],worker_id=r['worker_id'],"
          "core_token=r['core_token'],proposal=r['proposal'],"
          "signed_packet=r['signed_packet'],witness=r['witness'],"
          "signed_owner_grant=r['signed_owner_grant']);"
          "print(json.dumps(result))")
        self.start()
        cmd=subprocess.run(["sudo","-n","-u","nf_db_actor","env",
              "PYTHONPATH="+str(STAGE),"NF_CORE_OFFLINE_RECEIVER_TEST_ONLY=1",
              "NF_RECEIVER_OS_FIXTURE_ONLY=1",PY,"-c",script,str(core_file)],
              capture_output=True,text=True,timeout=9)
        self.assertEqual(cmd.returncode,0,cmd.stderr[:1400])
        result=json.loads(cmd.stdout)
        self.assertEqual(result["status"],"CORE_TO_SEPARATE_UID_HOST_ONE_TEST_EFFECT_ONLY")
        self.assertFalse(result["live_execution_allowed"])
        self.assertEqual(self.hash_file_from_recipient_uid(target),digest)
        self.assertEqual(self.fx.db.execute(
            "SELECT status FROM nf_receiver_effect_journal").fetchone()[0],"COMPLETED_TEST")
        self.recipient_proc.wait(timeout=4)
        if self.signer_proc and self.signer_proc.poll() is None:
            self.signer_proc.terminate();self.signer_proc.wait(timeout=3)
        self.recipient_proc=None;self.signer_proc=None
        # A second full CORE call cannot add or replace the protected file.
        self.start()
        again=subprocess.run(["sudo","-n","-u","nf_db_actor","env",
              "PYTHONPATH="+str(STAGE),"NF_CORE_OFFLINE_RECEIVER_TEST_ONLY=1",
              "NF_RECEIVER_OS_FIXTURE_ONLY=1",PY,"-c",script,str(core_file)],
              capture_output=True,text=True,timeout=9)
        self.assertNotEqual(again.returncode,0)
        self.assertEqual(self.hash_file_from_recipient_uid(target),digest)
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],1)
        print("NF_REAL_QWEN_ACTUAL_CORE_CLAIM_OS_HOST_ONCE_PASSED",flush=True)


    def protected_effect_state(self):
        program=("import sys,json;from offline_recipient_protected_journal "
                 "import RecipientProtectedJournal;"
                 "print(json.dumps(RecipientProtectedJournal(sys.argv[1]).inspect(sys.argv[2])))")
        out=run_uid("nf_effect","-c",program,self.receiver_config,
                    self.fx.packet["payload"]["task_id"])
        self.assertEqual(out.returncode,0,out.stderr)
        return json.loads(out.stdout)

    def test_protected_journal_postgres_rollback_and_lost_target_no_repeat(self):
        original=self.send()
        self.assertEqual(original["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        # Only an authorized fixture root simulates a DB admin rollback and
        # physically missing file; a worker can do neither in real OS ACL.
        self.fx.db.execute("DELETE FROM nf_receiver_effect_journal")
        remover=run_uid("nf_effect","-c",
          "from pathlib import Path;import sys;Path(sys.argv[1]).unlink()",
          self.fx.root/TARGET)
        self.assertEqual(remover.returncode,0,remover.stderr)
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        print("NF_RECIPIENT_PROTECTED_LEDGER_REJECTS_DB_ROLLBACK_AND_MISSING_FILE",flush=True)

    def test_protected_journal_crash_between_fsync_and_receipt_manual_stop(self):
        denied=self.send(crash_after_fsync=True)
        self.assertEqual(denied["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],
                         "UNKNOWN_MANUAL_RECONCILIATION")
        self.assertEqual(self.hash_file_from_recipient_uid(),
                         hashlib.sha256(CONTENT).hexdigest())
        self.fx.db.execute("DELETE FROM nf_receiver_effect_journal")
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],
                         "UNKNOWN_MANUAL_RECONCILIATION")
        print("NF_RECIPIENT_PROTECTED_LEDGER_PERSISTS_UNKNOWN_AFTER_RESTART",flush=True)

    def test_protected_journal_worker_cannot_delete_or_alter_evidence(self):
        self.assertEqual(self.send()["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        target=self.receiver_config/"nf-protected-effect-journal"
        denied=run_uid("nf_db_actor","-c",
             "from pathlib import Path;import sys;list(Path(sys.argv[1]).iterdir())",
             target)
        self.assertNotEqual(denied.returncode,0)
        denied=run_uid("nf_db_actor","-c",
             "from pathlib import Path;import sys;Path(sys.argv[1]).rmdir()",
             target)
        self.assertNotEqual(denied.returncode,0)
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        print("NF_RECIPIENT_LEDGER_OS_UID_PROTECTION_ENFORCED",flush=True)


    def test_protected_journal_concurrent_claims_allow_only_one(self):
        from concurrent.futures import ThreadPoolExecutor
        proc_script=(
            "import sys,time;from offline_recipient_protected_journal "
            "import RecipientProtectedJournal,ProtectedEffectDenied;\n"
            "try:\n"
            " with RecipientProtectedJournal(sys.argv[1]).intent_once("
            "task_id=sys.argv[2],operation_id='race-owner-test',"
            "target=sys.argv[3],content_sha256=sys.argv[4]):\n"
            "  time.sleep(.18)\n"
            "  print('ACQUIRED_ONE',flush=True)\n"
            "except ProtectedEffectDenied:\n"
            " print('DENIED_RACE',flush=True)\n"
        )
        task=self.fx.packet["payload"]["task_id"]
        digest=hashlib.sha256(CONTENT).hexdigest()
        def race(_):
            return run_uid("nf_effect","-c",proc_script,self.receiver_config,
                           task,TARGET,digest,timeout=8)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(race,(1,2)))
        self.assertTrue(all(p.returncode==0 for p in results),
                        str([(p.returncode,p.stderr[:120]) for p in results]))
        self.assertEqual(sum("ACQUIRED_ONE" in p.stdout for p in results),1)
        self.assertEqual(sum("DENIED_RACE" in p.stdout for p in results),1)
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
        print("NF_PROTECTED_RECEIPT_OS_FLOCK_ONE_OF_TWO_CONCURRENT",flush=True)

    def test_owner_grant_valid_signer_pin_permits_only_one_scratch_effect(self):
        self.assertEqual(self.send()["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        self.assertEqual(self.hash_file_from_recipient_uid(),hashlib.sha256(CONTENT).hexdigest())
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        print("NF_REAL_SIGNED_OWNER_GRANT_TO_PROTECTED_FINAL_EFFECT_ONCE",flush=True)

    def test_owner_grant_missing_blocks_before_protected_unknown(self):
        payload=json.loads(self.reqfile.read_text())
        del payload["signed_owner_grant"]
        self.reqfile.write_text(json.dumps(payload),encoding="ascii")
        self.assertEqual(self.send(start_signer=False)["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],"NEVER_SEEN")
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)

    def test_owner_grant_forged_signature_denied(self):
        foreign=Ed25519PrivateKey.generate()
        data=self.owner_grant()
        data["signature_base64"]=base64.b64encode(
            foreign.sign(_canonical(data["statement"]))).decode()
        self.write_request(extra={"signed_owner_grant":data})
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],"NEVER_SEEN")

    def test_owner_grant_valid_signature_wrong_repository_denied(self):
        data=self.owner_grant()
        data["statement"]["repository"]="AnotherOrg/foreign"
        data["signature_base64"]=base64.b64encode(
            self.owner_private.sign(_canonical(data["statement"]))).decode()
        self.write_request(extra={"signed_owner_grant":data})
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],"NEVER_SEEN")

    def test_owner_grant_expired_even_with_current_lease_denied(self):
        data=self.owner_grant()
        data["statement"]["expires_unix"]=int(time.time())-1
        data["signature_base64"]=base64.b64encode(
            self.owner_private.sign(_canonical(data["statement"]))).decode()
        self.write_request(extra={"signed_owner_grant":data})
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],"NEVER_SEEN")

    def test_owner_grant_restart_rollback_keeps_effect_locked(self):
        first=self.send()
        self.assertEqual(first["status"],"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY")
        original_sha=self.hash_file_from_recipient_uid()
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        # Simulate DB-administrator rolling the effect receipt back.
        # The recipient and signer processes are restarted by send().
        self.fx.db.execute("DELETE FROM nf_receiver_effect_journal")
        self.assertEqual(self.send()["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertEqual(self.protected_effect_state()["state"],"COMPLETED_TEST_ONLY")
        self.assertEqual(self.hash_file_from_recipient_uid(),original_sha)
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM nf_receiver_effect_journal").fetchone()[0],0)
        print("NF_OWNER_SIGNED_PERMIT_OS_RECEIVER_RESTART_DB_ROLLBACK_REPLAY_DENIED",flush=True)

def load_tests(loader,tests,pattern):
    return loader.loadTestsFromTestCase(ProtectedReceiverThreePrincipalE2E)
if __name__=="__main__":unittest.main()
