"""Witness-UID vs receiver-UID tests on ONE disposable GH Linux runner.

Proves signed, fsynced remote-process highwater denies restored LOCAL state;
NOT proof of physically separate computers / power-loss independence.
"""
import base64,hashlib,json,os,subprocess,tempfile,time,unittest
from pathlib import Path
from offline_external_effect_witness import canon

PY=os.environ.get("NF_WITNESS_TEST_PYTHON")
STAGE=os.environ.get("NF_WITNESS_TEST_STAGE")
SRC=Path(STAGE or "/missing")/"offline_external_effect_witness.py"
def idof(user):return int(subprocess.check_output(["id","-u",user],text=True))
def run_as(user,*args,timeout=6):
    return subprocess.run(["sudo","-n","-u",user,"env",
      "NF_WITNESS_ISOLATED_TEST_ONLY=1","PYTHONPATH="+str(STAGE),PY,
      *map(str,args)],capture_output=True,text=True,timeout=timeout)
class DetachedMonotonicWitnessTests(unittest.TestCase):
    def setUp(self):
        if not PY or not STAGE:self.skipTest("ephemeral two-UID hosted test required")
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-witness-e2e-")
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.base.chmod(0o755)
        self.store=self.base/"nf-witness-store"
        self.ipc=self.base/"nf-witness-ipc"
        self.sock=self.ipc/"nf-witness.sock"
        self.addCleanup(self.cleanup_private)
        for path,group,mode in [(self.store,"nf_witness","0700"),
                                 (self.ipc,"nf_witness_ipc","2750")]:
            subprocess.run(["sudo","-n","install","-d","-o","nf_witness",
                "-g",group,"-m",mode,str(path)],check=True)
        getpub=("import base64,sys;from cryptography.hazmat.primitives "
                "import serialization;from offline_external_effect_witness "
                "import pin_private_dir,keypair;"
                "r=pin_private_dir(sys.argv[1]);"
                "k=keypair(r);"
                "print(base64.b64encode(k.public_key().public_bytes("
                "serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode())")
        p=run_as("nf_witness","-c",getpub,self.store)
        self.assertEqual(p.returncode,0,p.stderr)
        self.pub=p.stdout.strip()
        self.request={"schema":"nf.remote_witness.claim.v1",
          "owner_id":"151650108","repo_id":"723328237",
          "task_id":"NF-DEV-05-Q973","operation_id":"one-operation",
          "target":"bridge/neurofactory/development/core_owned/witness-test.py",
          "lease_epoch":1,
          "permit_sha256":hashlib.sha256(b"owner-scoped permit").hexdigest(),
          "content_sha256":hashlib.sha256(b"code content").hexdigest(),
          "nonce":hashlib.sha256(b"fresh nonce").hexdigest()}
        self.reqfile=self.base/"request.json"
        self.reqfile.write_text(json.dumps(self.request))
        self.reqfile.chmod(0o644)
        self.server=None
        self.addCleanup(self.stop)
    def cleanup_private(self):
        subprocess.run(["sudo","-n","rm","-rf","--",str(self.store),str(self.ipc)],check=True)
    def stop(self):
        if self.server and self.server.poll() is None:
            self.server.terminate()
            try:self.server.wait(timeout=2)
            except subprocess.TimeoutExpired:self.server.kill()
        self.server=None
    def start(self,*,drop=False):
        env=["sudo","-n","-u","nf_witness","env",
             "NF_WITNESS_ISOLATED_TEST_ONLY=1",
             "NF_WITNESS_RECEIVER_UID="+str(idof("nf_effect")),
             "NF_WITNESS_SIMULATE_CRASH_BEFORE_ACK="+("1" if drop else "0"),
             "PYTHONPATH="+str(STAGE),PY,str(SRC),"serve",str(self.store),str(self.sock)]
        self.server=subprocess.Popen(env,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,text=True)
        for i in range(70):
            check=run_as("nf_effect","-c",
              "from pathlib import Path;import sys;sys.exit(not Path(sys.argv[1]).is_socket())",
              self.sock)
            if check.returncode==0:return
            if self.server.poll() is not None:
                raise AssertionError(self.server.stderr.read()[:500])
            time.sleep(.03)
        raise AssertionError("witness did not serve")
    def request_once(self,*,pub=None,uid=None,owner="nf_effect"):
        cli=("import sys,json;from offline_external_effect_witness "
          "import request_once;"
          "obj=json.load(open(sys.argv[2]));"
          "print(json.dumps(request_once(sys.argv[1],obj,"
          "expected_witness_uid=int(sys.argv[3]),"
          "pinned_witness_public_b64=sys.argv[4])))")
        p=run_as(owner,"-c",cli,self.sock,self.reqfile,
                 idof("nf_witness") if uid is None else uid,
                 self.pub if pub is None else pub)
        self.server.wait(timeout=4)
        self.server=None
        return p
    def count_protected_targets(self):
        cli=("import pathlib,sys;print(len(list(pathlib.Path(sys.argv[1]).glob('target-*.json'))))")
        p=run_as("nf_witness","-c",cli,self.store)
        self.assertEqual(p.returncode,0,p.stderr)
        return int(p.stdout.strip())
    def test_legitimate_reservation_and_receiver_rollback_rejected(self):
        self.start()
        r=self.request_once()
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)["status"],
                         "REMOTE_UID_WITNESS_PRECOMMIT_TEST_ONLY")
        # Simulate FULL local DB and receiver state rollback: discard both.
        # The witness store belongs to another UID and remains untouched.
        local=self.base/"receiver-postgres-snapshot"
        local.mkdir();(local/"db.json").write_text("{}")
        (local/"db.json").unlink()
        self.start()
        old=self.request_once()
        self.assertNotEqual(old.returncode,0)
        self.assertEqual(self.count_protected_targets(),1)
        print("NF_SEPARATE_UID_WITNESS_REJECTS_LOCAL_FULL_ROLLBACK",flush=True)
    def test_different_operation_id_same_target_denied(self):
        self.start();self.assertEqual(self.request_once().returncode,0)
        changed=dict(self.request,operation_id="attempt-to-reuse-target",
                     nonce=hashlib.sha256(b"new nonce").hexdigest())
        self.reqfile.write_text(json.dumps(changed))
        self.start();self.assertNotEqual(self.request_once().returncode,0)
        self.assertEqual(self.count_protected_targets(),1)
    def test_ack_lost_after_durable_reservation_denies_retry(self):
        self.start(drop=True)
        first=self.request_once()
        self.assertNotEqual(first.returncode,0)
        self.assertEqual(self.count_protected_targets(),1)
        self.start()
        self.assertNotEqual(self.request_once().returncode,0)
        print("NF_REMOTE_PRE_EFFECT_ACK_LOSS_UNKNOWN_NO_RETRY",flush=True)
    def test_false_witness_os_identity_denied(self):
        self.start()
        p=self.request_once(uid=idof("nf_witness")+50000)
        self.assertNotEqual(p.returncode,0)
    def test_wrong_witness_pubkey_denied_even_with_signed_server(self):
        self.start()
        p=self.request_once(pub=base64.b64encode(b"\x00"*32).decode())
        self.assertNotEqual(p.returncode,0)
        self.assertEqual(self.count_protected_targets(),1)
    def test_database_worker_cannot_read_or_delete_witness_store(self):
        p=run_as("nf_db_actor","-c",
                 "from pathlib import Path;import sys;print(list(Path(sys.argv[1]).iterdir()))",
                 self.store)
        self.assertNotEqual(p.returncode,0)
        p=run_as("nf_db_actor","-c",
                 "from pathlib import Path;import sys;Path(sys.argv[1]).rmdir()",
                 self.store)
        self.assertNotEqual(p.returncode,0)
    def test_witness_unavailable_fails_closed(self):
        cli=("from offline_external_effect_witness import request_once;"
             "import json,sys;request_once(sys.argv[1],json.load(open(sys.argv[2])),"
             "expected_witness_uid=int(sys.argv[3]),"
             "pinned_witness_public_b64=sys.argv[4])")
        p=run_as("nf_effect","-c",cli,self.sock,self.reqfile,idof("nf_witness"),self.pub)
        self.assertNotEqual(p.returncode,0)
if __name__=="__main__":unittest.main()
