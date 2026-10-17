"""GitHub-hosted ephemeral mTLS integration tests on independent Linux UIDs.

Both certificates and CA are generated at runtime, never committed or shared.
All traffic goes over loopback on ONE hosted Linux machine (not a two-PC test).
"""
import base64,hashlib,json,os,socket,subprocess,tempfile,time,unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,ed25519
from signed_effect_permit import _validated_payload
from offline_external_effect_witness import canon
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

PY=os.environ.get("NF_MTLS_TEST_PYTHON")
STAGE=os.environ.get("NF_MTLS_TEST_STAGE")
def _b64(x):return base64.b64encode(x).decode()
def _sha(x):return hashlib.sha256(x).hexdigest()
def _key():
    return rsa.generate_private_key(public_exponent=65537,key_size=2048)
def _name(name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
def _certificate(key,name,issuer,issuer_key,*,ca=False,client=False):
    now=datetime.now(timezone.utc)
    b=(x509.CertificateBuilder().subject_name(_name(name))
       .issuer_name(_name(issuer)).public_key(key.public_key())
       .serial_number(x509.random_serial_number())
       .not_valid_before(now-timedelta(days=1))
       .not_valid_after(now+timedelta(days=3))
       .add_extension(x509.BasicConstraints(ca=ca,path_length=0 if ca else None),
                      critical=True))
    if not ca:
        eku=ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
        b=b.add_extension(x509.ExtendedKeyUsage([eku]),critical=True)
        if not client:
            b=b.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("nf-witness.test")]),critical=False)
    return b.sign(issuer_key,hashes.SHA256())
def _pemkey(key):
    return key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.TraditionalOpenSSL,
                   serialization.NoEncryption())

class MTLSWitnessLinuxTests(unittest.TestCase):
    def setUp(self):
        if not PY or not STAGE:self.skipTest("requires ephemeral GH Linux venv")
        self.temp=tempfile.TemporaryDirectory(prefix="nf-ephemeral-mtls-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o755)
        self.store=self.root/"nf-witness-store"
        subprocess.run(["sudo","-n","install","-d","-o","nf_witness",
             "-g","nf_witness","-m","0700",str(self.store)],check=True)
        self.addCleanup(lambda:subprocess.run(["sudo","-n","rm","-rf","--",str(self.store)],check=True))
        ca=_key()
        self.ca_key=ca
        cacert=_certificate(ca,"NF temporary fixture CA","NF temporary fixture CA",ca,ca=True)
        srv=_key();cli=_key()
        srvcert=_certificate(srv,"nf-witness.test","NF temporary fixture CA",ca)
        clicert=_certificate(cli,"nf-receiver.test","NF temporary fixture CA",ca,client=True)
        self.ca=self.root/"ca.crt"
        self.ca.write_bytes(cacert.public_bytes(serialization.Encoding.PEM))
        self.srv_crt=self.root/"server.crt"
        self.srv_crt.write_bytes(srvcert.public_bytes(serialization.Encoding.PEM))
        self.srv_key=self.root/"server.key"
        self.srv_key.write_bytes(_pemkey(srv))
        self.cli_crt=self.root/"client.crt"
        self.cli_crt.write_bytes(clicert.public_bytes(serialization.Encoding.PEM))
        self.cli_key=self.root/"client.key"
        self.cli_key.write_bytes(_pemkey(cli))
        for key,who in [(self.srv_key,"nf_witness"),(self.cli_key,"nf_effect")]:
            key.chmod(0o600)
            subprocess.run(["sudo","-n","chown",who+":"+who,str(key)],check=True)
        self.server_fingerprint=_sha(srvcert.public_bytes(serialization.Encoding.DER))
        self.client_fingerprint=_sha(clicert.public_bytes(serialization.Encoding.DER))
        get_public=("import base64,sys;from cryptography.hazmat.primitives "
          "import serialization;from offline_external_effect_witness "
          "import keypair,pin_private_dir;"
          "key=keypair(pin_private_dir(sys.argv[1]));"
          "print(base64.b64encode(key.public_key().public_bytes("
          "serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode())")
        p=self.run_uid("nf_witness","-c",get_public,self.store)
        self.assertEqual(p.returncode,0,p.stderr)
        self.witness_public=p.stdout.strip()
        self.claim={"schema":"nf.remote_witness.claim.v1",
          "owner_id":"151650108","repo_id":"723328237",
          "task_id":"NF-DEV-05-Q973","operation_id":"mtls-case-one",
          "target":"bridge/neurofactory/development/core_owned/mtls-test.py",
          "lease_epoch":3,"permit_sha256":_sha(b"synthetic owner signed permit"),
          "content_sha256":_sha(b"synthetic program bytes"),
          "nonce":_sha(b"unrepeated limited nonce")}
        self.claimfile=self.root/"claim.json"
        self.claimfile.write_text(json.dumps(self.claim),encoding="ascii")
        self.claimfile.chmod(0o644)
        self.port=None;self.proc=None
        self.addCleanup(self.close_server)
    def run_uid(self,user,*args):
        return subprocess.run(["sudo","-n","-u",user,"env",
           "NF_MTLS_WITNESS_TEST_ONLY=1","NF_WITNESS_ISOLATED_TEST_ONLY=1",
           "PYTHONPATH="+str(STAGE),PY,*map(str,args)],
           capture_output=True,text=True,timeout=8)
    def close_server(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:self.proc.kill()
        self.proc=None
    def listen(self,*,drop_ack=False,scoped=False):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1",0));self.port=sock.getsockname()[1]
        server=("sudo","-n","-u","nf_witness","env",
           "NF_MTLS_WITNESS_TEST_ONLY=1","NF_WITNESS_ISOLATED_TEST_ONLY=1",
           "NF_WITNESS_SIMULATE_CRASH_BEFORE_ACK="+("1" if drop_ack else "0"),
           "PYTHONPATH="+str(STAGE),PY,
           str(Path(STAGE)/"offline_mtls_witness_transport.py"),
           ("test-serve-scoped-once" if scoped else "test-serve-once"),
           str(self.store),str(self.port),str(self.srv_crt),
           str(self.srv_key),str(self.ca),self.client_fingerprint)
        self.proc=subprocess.Popen(server,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,text=True)
        time.sleep(.25)
        self.assertIsNone(self.proc.poll(),
            "test witness failed before client connected")
    def call(self,*,server_pin=None,witness_pub=None,certificate=None,
             private_key=None,scoped=False):
        cli=("import json,sys;from offline_mtls_witness_transport "
             "import request_test_once;"
             "result=request_test_once('127.0.0.1',int(sys.argv[1]),"
             "json.load(open(sys.argv[2])),"
             "client_cert=sys.argv[3],client_key=sys.argv[4],"
             "ca_cert=sys.argv[5],pinned_server_cert_sha256=sys.argv[6],"
             "pinned_witness_public_b64=sys.argv[7],"
             "signed_packet=(None if sys.argv[8]=='-' else "
             "json.load(open(sys.argv[8]))['signed_packet']),"
             "signed_owner_grant=(None if sys.argv[8]=='-' else "
             "json.load(open(sys.argv[8]))['signed_owner_grant']));"
             "print(json.dumps(result))")
        return self.run_uid("nf_effect","-c",cli,self.port,self.claimfile,
                 self.cli_crt if certificate is None else certificate,
                 self.cli_key if private_key is None else private_key,
                 self.ca,self.server_fingerprint if server_pin is None else server_pin,
                 self.witness_public if witness_pub is None else witness_pub,
                 self.scopefile if scoped else "-")
    def count(self):
        cmd=("from pathlib import Path;import sys;"
          "print(len(list(Path(sys.argv[1]).glob('target-*.json'))))")
        p=self.run_uid("nf_witness","-c",cmd,self.store)
        self.assertEqual(p.returncode,0,p.stderr)
        return int(p.stdout.strip())
    def test_true_mtls_and_ed25519_signed_witness_ack_once(self):
        self.listen();r=self.call()
        self.assertEqual(r.returncode,0,r.stderr)
        x=json.loads(r.stdout)
        self.assertEqual(x["status"],"MUTUAL_TLS_REMOTE_WITNESS_DURABLE_TEST_ONLY")
        self.assertFalse(x["production_authority"])
        self.assertEqual(self.count(),1)
        self.close_server();self.listen()
        self.assertNotEqual(self.call().returncode,0)
        self.assertEqual(self.count(),1)
        print("NF_MTLS_SIGNED_HIGHWATER_ONE_EFFECT_REPLAY_DENIED",flush=True)
    def test_wrong_pinned_server_certificate_denies_pre_effect(self):
        self.listen()
        r=self.call(server_pin="0"*64)
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(self.count(),0)
    def test_wrong_signed_witness_key_denies_ack_after_reservation(self):
        self.listen()
        r=self.call(witness_pub=_b64(b"\x00"*32))
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(self.count(),1)
    def test_ack_loss_after_durable_fsync_cannot_retry(self):
        self.listen(drop_ack=True)
        self.assertNotEqual(self.call().returncode,0)
        self.assertEqual(self.count(),1)
        self.close_server();self.listen()
        self.assertNotEqual(self.call().returncode,0)
        print("NF_MTLS_ACK_LOSS_UNKNOWN_DENY_RETRY",flush=True)
    def test_unavailable_remote_server_fails_closed(self):
        self.port=48943
        r=self.call()
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(self.count(),0)
    def test_server_rejects_wrong_client_cert_identity(self):
        adversary=_key()
        # CA-signed other cert is NOT sufficient: exact TLS DER pin is needed.
        # Issue via same fixture issuer, but use separate key.
        # A SECOND still-CA-signed client must be refused by exact DER pin
        # even though its certificate chain and client EKU are valid.
        other=self.root/"other_client.key"
        othercert=self.root/"other_client.crt"
        other.write_bytes(_pemkey(adversary));other.chmod(0o600)
        othercert.write_bytes(_certificate(
            adversary,"nf-other-client.test","NF temporary fixture CA",
            self.ca_key,client=True).public_bytes(serialization.Encoding.PEM))
        subprocess.run(["sudo","-n","chown","nf_effect:nf_effect",str(other)],check=True)
        self.listen()
        r=self.call(private_key=other,certificate=othercert)
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(self.count(),0)

    def _setup_scoped_permissions(self):
        self.issuer_private=ed25519.Ed25519PrivateKey.generate()
        self.owner_private=ed25519.Ed25519PrivateKey.generate()
        def b64_pub(k):
            return _b64(k.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw))
        now=int(time.time())
        body={
            "schema":"neurofactory.trusted_host.signed_effect_permit.v1",
            "purpose":"EFFECT_RESERVATION_SCOPE_ONLY",
            "issuer_id":"issuer-witness-fixture","key_id":"test-key",
            "owner_id":"151650108","repository":"DSLitvinov1/my_first_repo",
            "project_id":"nf-sandbox","task_id":self.claim["task_id"],
            "worker_id":"worker-sandbox-01",
            "source_sha40":"a"*40,"source_file_sha256":"b"*64,
            "input_task_sha256":"c"*64,"policy_sha256":"d"*64,
            "target":self.claim["target"],
            "proposed_content_sha256":self.claim["content_sha256"],
            "fencing_token_sha256":"f"*64,
            "lease_epoch":self.claim["lease_epoch"],
            "issued_unix":now-5,"expires_unix":now+110,
            "idempotency_key":"1"*64,"operation_id":self.claim["operation_id"]}
        permit=_validated_payload(body)
        self.claim["permit_sha256"]=_sha(permit)
        self.claimfile.write_text(json.dumps(self.claim),encoding="ascii")
        fields=("owner_id","repository","project_id","task_id","worker_id",
                "source_sha40","target","operation_id","lease_epoch")
        statement={k:body[k] for k in fields}
        statement.update(permit_sha256=_sha(permit),expires_unix=now+90)
        self.envelope={"signed_packet":{
            "payload":body,"signature_base64":_b64(self.issuer_private.sign(permit))},
            "signed_owner_grant":{
                "statement":statement,
                "signature_base64":_b64(self.owner_private.sign(canon(statement)))}}
        self.scopefile=self.root/"scope.json"
        self.scopefile.write_text(json.dumps(self.envelope),encoding="ascii")
        self.scopefile.chmod(0o644)
        issuer_pub=self.issuer_private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        owner_pub=self.owner_private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        policy={"schema":"nf.witness.pinned_scope.test.v1",
            "owner_id":"151650108","repo_id":"723328237",
            "repository":"DSLitvinov1/my_first_repo",
            "project_id":"nf-sandbox","worker_id":"worker-sandbox-01",
            "issuer_public_base64":_b64(issuer_pub),
            "owner_public_base64":_b64(owner_pub),
            "issuer_sha256":_sha(issuer_pub),"owner_sha256":_sha(owner_pub)}
        saver=("import os,sys;f=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|"
               "os.O_WRONLY,0o600);os.write(f,sys.stdin.buffer.read());"
               "os.fsync(f);os.close(f)")
        result=subprocess.run(["sudo","-n","-u","nf_witness","env",
           "NF_WITNESS_ISOLATED_TEST_ONLY=1",
           "PYTHONPATH="+str(STAGE),PY,"-c",saver,
           str(self.store/"signed-witness-authority-pin.json")],
           input=json.dumps(policy).encode(),capture_output=True,timeout=7)
        self.assertEqual(result.returncode,0,result.stderr[:250])
    def test_scoped_valid_signed_owner_and_issuer_required_before_highwater(self):
        self._setup_scoped_permissions()
        self.listen(scoped=True)
        reply=self.call(scoped=True)
        self.assertEqual(reply.returncode,0,reply.stderr)
        self.assertEqual(self.count(),1)
        self.close_server();self.listen(scoped=True)
        self.assertNotEqual(self.call(scoped=True).returncode,0)
        self.assertEqual(self.count(),1)
    def test_scoped_missing_owner_grant_no_reservation(self):
        self._setup_scoped_permissions()
        bundle=json.loads(self.scopefile.read_text())
        bundle["signed_owner_grant"]=None
        self.scopefile.write_text(json.dumps(bundle))
        self.listen(scoped=True)
        self.assertNotEqual(self.call(scoped=True).returncode,0)
        self.assertEqual(self.count(),0)
    def test_scoped_forged_valid_shape_owner_signature_no_reservation(self):
        self._setup_scoped_permissions()
        bundle=json.loads(self.scopefile.read_text())
        fake=ed25519.Ed25519PrivateKey.generate()
        bundle["signed_owner_grant"]["signature_base64"]=_b64(
            fake.sign(canon(bundle["signed_owner_grant"]["statement"])))
        self.scopefile.write_text(json.dumps(bundle))
        self.listen(scoped=True)
        self.assertNotEqual(self.call(scoped=True).returncode,0)
        self.assertEqual(self.count(),0)
    def test_scoped_forged_issuer_signature_no_reservation(self):
        self._setup_scoped_permissions()
        bundle=json.loads(self.scopefile.read_text())
        fake=ed25519.Ed25519PrivateKey.generate()
        bundle["signed_packet"]["signature_base64"]=_b64(
            fake.sign(_validated_payload(bundle["signed_packet"]["payload"])))
        self.scopefile.write_text(json.dumps(bundle))
        self.listen(scoped=True)
        self.assertNotEqual(self.call(scoped=True).returncode,0)
        self.assertEqual(self.count(),0)
    def test_scoped_foreign_target_claim_no_reservation(self):
        self._setup_scoped_permissions()
        altered=dict(self.claim,target="bridge/neurofactory/development/core_owned/foreign.py")
        self.claimfile.write_text(json.dumps(altered),encoding="ascii")
        self.listen(scoped=True)
        self.assertNotEqual(self.call(scoped=True).returncode,0)
        self.assertEqual(self.count(),0)
    def test_scoped_pinned_authority_absent_denied(self):
        self._setup_scoped_permissions()
        out=subprocess.run(["sudo","-n","-u","nf_witness",
            "rm",str(self.store/"signed-witness-authority-pin.json")],
            capture_output=True,timeout=5)
        self.assertEqual(out.returncode,0,out.stderr)
        self.listen(scoped=True)
        self.assertNotEqual(self.call(scoped=True).returncode,0)
        self.assertEqual(self.count(),0)

if __name__=="__main__":unittest.main()
