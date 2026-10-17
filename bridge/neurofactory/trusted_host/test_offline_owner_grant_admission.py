"""New targeted test-only externally pinned owner-key grant validation.

Owner signature test keys exist only in short-lived GitHub Actions process.
No real human ID or GitHub administrative rights are inferred from test key.
"""
import base64,hashlib,json,os,subprocess,tempfile,time,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

PY=os.environ.get("NF_OWNER_TEST_PYTHON")
STAGE=os.environ.get("NF_OWNER_TEST_STAGE")
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(x):return hashlib.sha256(x).hexdigest()

class IndependentOwnerKeyScopeTests(unittest.TestCase):
    def setUp(self):
        if not PY or not STAGE:self.skipTest("isolated hosted role not available")
        self.temp=tempfile.TemporaryDirectory(prefix="nf-owner-proof-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o755)
        self.home=self.root/"nf-signer-fixture"
        subprocess.run(["sudo","-n","install","-d","-m","0700",
             "-o","nf_signer","-g","nf_signer",str(self.home)],check=True)
        self.addCleanup(lambda:subprocess.run(["sudo","-n","rm","-rf","--",str(self.home)],
                                                   check=True))
        self.owner=Ed25519PrivateKey.generate()
        pub=self.owner.public_key().public_bytes(serialization.Encoding.Raw,
                                                 serialization.PublicFormat.Raw)
        self.enrolled={"schema":"neurofactory.owner.authority_pin_fixture.v1",
            "owner_id":"pinned-owner","repository":"DSLitvinov1/my_first_repo",
            "project_id":"nf-sandbox",
            "owner_public_key_base64":base64.b64encode(pub).decode(),
            "operator_pinned_fingerprint":sha(pub)}
        self.body={"schema":"neurofactory.trusted_host.signed_effect_permit.v1",
             "purpose":"EFFECT_RESERVATION_SCOPE_ONLY",
             "issuer_id":"operator-test","key_id":"test-key",
             "owner_id":"pinned-owner","repository":"DSLitvinov1/my_first_repo",
             "project_id":"nf-sandbox","task_id":"NF-DEV-05-Q973",
             "worker_id":"worker-sandbox-01","source_sha40":"a"*40,
             "source_file_sha256":"b"*64,"input_task_sha256":"c"*64,
             "policy_sha256":"d"*64,
             "target":"bridge/neurofactory/development/core_owned/once.txt",
             "proposed_content_sha256":"e"*64,
             "fencing_token_sha256":"f"*64,
             "lease_epoch":7,"issued_unix":1800000000,
             "expires_unix":1800000300,
             "idempotency_key":"1"*64,"operation_id":"owner-proofs-one"}
        self.packet={"payload":dict(self.body),"signature_base64":"not_an_issuer_signature"}
        self.statement={k:self.body[k] for k in (
           "owner_id","repository","project_id","task_id","worker_id",
           "source_sha40","target","operation_id","lease_epoch")}
        self.statement["permit_sha256"]=sha(canonical(self.body))
        self.statement["expires_unix"]=1800000250
        self.provision()
    def provision(self):
        code=("import os,sys;f=os.open(sys.argv[1],"
              "os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);"
              "os.write(f,sys.stdin.buffer.read());os.fsync(f);os.close(f)")
        out=subprocess.run(["sudo","-n","-u","nf_signer",PY,"-c",code,
          str(self.home/"pinned-project-owner-authority.json")],
          input=canonical(self.enrolled),capture_output=True,timeout=5)
        self.assertEqual(out.returncode,0,out.stderr[:160])
    def signed(self,statement=None,private=None):
        statement=self.statement if statement is None else statement
        return {"statement":statement,
                "signature_base64":base64.b64encode(
                    (self.owner if private is None else private).sign(canonical(statement))).decode()}
    def check(self,grant=None,packet=None,now=1800000200):
        path=self.root/"request.json"
        path.write_text(json.dumps({"packet":self.packet if packet is None else packet,
            "grant":self.signed() if grant is None else grant,"now":now}),encoding="ascii")
        path.chmod(0o644)
        cli=("import json,sys;from offline_owner_grant_admission "
           "import check_owner_grant_under_signer_uid;"
           "data=json.load(open(sys.argv[2]));"
           "print(json.dumps(check_owner_grant_under_signer_uid("
           "sys.argv[1],data['packet'],data['grant'],now_unix=data['now'])))")
        return subprocess.run(["sudo","-n","-u","nf_signer","env",
          "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1","PYTHONPATH="+STAGE,
          PY,"-c",cli,str(self.home),str(path)],
          capture_output=True,text=True,timeout=7)
    def test_accepted_pre_pinned_owner_scope_never_live(self):
        r=self.check();self.assertEqual(r.returncode,0,r.stderr)
        obj=json.loads(r.stdout)
        self.assertEqual(obj["status"],"PINNED_OWNER_KEY_SIGNED_EXACT_SCOPE_TEST_ONLY")
        self.assertFalse(obj["human_legal_identity_independently_confirmed"])
        self.assertFalse(obj["repository_admin_rights_live_confirmed"])
        self.assertFalse(obj["filesystem_write_allowed"])
    def test_wrong_owner_signature_rejected(self):
        r=self.check(grant=self.signed(private=Ed25519PrivateKey.generate()))
        self.assertNotEqual(r.returncode,0)
    def test_other_repo_project_worker_target_and_epoch_rejected(self):
        for name,changed in (("owner_id","another-owner"),("repository","Other/repo"),
             ("project_id","foreign"),("worker_id","stale-worker"),
             ("target","bridge/neurofactory/development/core_owned/foreign.txt"),
             ("source_sha40","f"*40),("lease_epoch",8),("operation_id","replayed-id")):
            with self.subTest(name=name):
                body=dict(self.statement,**{name:changed})
                self.assertNotEqual(self.check(grant=self.signed(body)).returncode,0)
    def test_forged_permit_content_and_digest_rejected(self):
        body=dict(self.packet["payload"],target="bridge/neurofactory/development/core_owned/evil.txt")
        packet=dict(self.packet,payload=body)
        self.assertNotEqual(self.check(packet=packet).returncode,0)
    def test_time_expired_beyond_signed_permit_or_wrong_nonce_denied(self):
        self.assertNotEqual(self.check(now=1800000251).returncode,0)
        changed=dict(self.statement,expires_unix=1800000301)
        self.assertNotEqual(self.check(grant=self.signed(changed)).returncode,0)
        changed=dict(self.statement,permit_sha256="f"*64)
        self.assertNotEqual(self.check(grant=self.signed(changed)).returncode,0)
    def test_worker_cannot_repin_owner_public_key(self):
        path=self.home/"pinned-project-owner-authority.json"
        attempt=subprocess.run(["sudo","-n","-u","nf_db_actor",
          "sh","-c",'echo forgery > "$1"',"sh",str(path)],capture_output=True)
        self.assertNotEqual(attempt.returncode,0)
        self.assertEqual(self.check().returncode,0)

if __name__=="__main__":unittest.main()
