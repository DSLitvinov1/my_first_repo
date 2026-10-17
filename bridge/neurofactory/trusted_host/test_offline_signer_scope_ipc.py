"""Targeted signer-owned policy and Unix peer UID scope checks (nonlive).

The fixture owner/issuer policies are prepared by the isolated signer OS UID,
NOT the DB client. No signer private key is sent over IPC.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PY=os.environ.get("NF_OPERATOR_TEST_PYTHON")
BASE=Path(os.environ.get("NF_OPERATOR_IPC_STAGED_SOURCE","/nonexistent")).parent
SIGNER=BASE/"offline_operator_anchor.py"
SERVER=BASE/"offline_operator_ipc.py"

def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
def digest(x):return hashlib.sha256(x).hexdigest()
def as_signer(*args):
    return subprocess.run(["sudo","-n","-u","nf_signer","env",
        "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",PY,str(SIGNER),*map(str,args)],
        capture_output=True,text=True,timeout=8)

class SignerScopeIPCTests(unittest.TestCase):
    def setUp(self):
        if not PY or os.name!="posix":self.skipTest("Linux isolated runner required")
        self.temp=tempfile.TemporaryDirectory(prefix="nf-scope-ipc-test-")
        self.addCleanup(self.clean)
        self.dir=Path(self.temp.name);self.dir.chmod(0o755)
        self.home=self.dir/"nf-signer-fixture";self.api=self.dir/"nf-operator-api"
        self.sock=self.api/"nf-readonly-operator.sock"
        subprocess.run(["sudo","-n","mkdir",str(self.home),str(self.api)],check=True)
        subprocess.run(["sudo","-n","chown","nf_signer:nf_signer",str(self.home),str(self.api)],check=True)
        subprocess.run(["sudo","-n","chmod","0700",str(self.home)],check=True)
        subprocess.run(["sudo","-n","chgrp","nf_operator_ipc",str(self.api)],check=True)
        subprocess.run(["sudo","-n","chmod","2770",str(self.api)],check=True)
        boot=as_signer("bootstrap",self.home)
        self.assertEqual(boot.returncode,0,boot.stderr)
        self.key=json.loads(boot.stdout)
        self.issuer=Ed25519PrivateKey.generate()
        self.issuer_pub=base64.b64encode(self.issuer.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        now=int(time.time())
        self.payload={
            "schema":"neurofactory.trusted_host.signed_effect_permit.v1",
            "purpose":"EFFECT_RESERVATION_SCOPE_ONLY",
            "issuer_id":"ephemeral-issuer","key_id":"issuer-key-test",
            "owner_id":"approved-fixture-owner","repository":"DSLitvinov1/my_first_repo",
            "project_id":"nf-sandbox","task_id":"NF-DEV-05-Q990",
            "worker_id":"allowed-worker-01",
            "source_sha40":"a"*40,"source_file_sha256":"b"*64,
            "input_task_sha256":"c"*64,"policy_sha256":"d"*64,
            "target":"bridge/neurofactory/development/core_owned/guarded_test.txt",
            "proposed_content_sha256":"e"*64,"fencing_token_sha256":"f"*64,
            "lease_epoch":7,"issued_unix":now-3,"expires_unix":now+60,
            "idempotency_key":"1"*64,"operation_id":"guarded-fixture-one"}
        self.packet=self.sign(self.payload)
        claim=digest(canonical(self.payload))
        packet=as_signer("advance",self.home,claim)
        self.assertEqual(packet.returncode,0,packet.stderr)
        self.witness=json.loads(packet.stdout)
        self.provision={
            "schema":"neurofactory.operator.scope_fixture.v1",
            "expected":{k:self.payload[k] for k in (
               "issuer_id","key_id","owner_id","repository","project_id","task_id",
               "worker_id","source_sha40","source_file_sha256","input_task_sha256",
               "policy_sha256","target","proposed_content_sha256",
               "fencing_token_sha256","lease_epoch","idempotency_key","operation_id")},
            "pinned_public_sha256":self.key["public_key_sha256"],
            "allowed_claim_sha256":claim,
            "effect_issuer_public_b64":self.issuer_pub}
        self.proc=None
        self.provision_scope()
    def clean(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:self.proc.kill()
        subprocess.run(["sudo","-n","rm","-rf","--",str(self.home),str(self.api)],check=True)
        self.temp.cleanup()
    def sign(self,p):
        return {"payload":dict(p),"signature_base64":base64.b64encode(
            self.issuer.sign(canonical(p))).decode("ascii")}
    def provision_scope(self):
        script=("import sys,os; fd=os.open(sys.argv[1],"
                "os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);"
                "os.write(fd,sys.stdin.buffer.read());os.fsync(fd);os.close(fd)")
        p=subprocess.run(["sudo","-n","-u","nf_signer",PY,"-c",script,
             str(self.home/"pinned-effect-scope.json")],
             input=canonical(self.provision),capture_output=True,timeout=8)
        self.assertEqual(p.returncode,0,p.stderr.decode()[:150])
    def req(self,packet=None,witness=None):
        return {"schema":"neurofactory.operator.scope_check_fixture.v1",
                "signed_permit":self.packet if packet is None else packet,
                "witness":self.witness if witness is None else witness,
                "public_sha":self.key["public_key_sha256"],
                "public_key":self.key["public_key_base64"]}
    def serve(self):
        uid=int(subprocess.check_output(["id","-u","nf_db_actor"],text=True).strip())
        self.proc=subprocess.Popen(["sudo","-n","-u","nf_signer","env",
           "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",PY,str(SERVER),"serve",
           str(self.home),str(self.sock),str(uid)],
           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        for _ in range(70):
            ready=subprocess.run(["sudo","-n","-u","nf_signer","test","-S",str(self.sock)],
                  capture_output=True)
            if ready.returncode==0:break
            if self.proc.poll() is not None:
                raise RuntimeError("IPC server refused: "+self.proc.stderr.read()[:200])
            time.sleep(.04)
        else:raise RuntimeError("IPC never bound")
    def send(self,req,user="nf_db_actor"):
        self.serve()
        f=self.dir/"request.json";f.write_text(json.dumps(req),encoding="ascii");f.chmod(0o644)
        script=("import sys,json;from offline_operator_ipc import client_send;"
                "print(json.dumps(client_send(sys.argv[1],json.load(open(sys.argv[2])))))")
        proc=subprocess.run(["sudo","-n","-u",user,"env","PYTHONPATH="+str(BASE),
             PY,"-c",script,str(self.sock),str(f)],
             capture_output=True,text=True,timeout=7)
        if proc.returncode!=0:
            server_error=""
            if self.proc is not None:
                try:self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:pass
                if self.proc.poll() is not None:
                    server_error=self.proc.stderr.read()[:900]
            self.fail("client refused: "+proc.stderr[:250]+" server failure: "+server_error)
        return json.loads(proc.stdout)
    def test_exact_owner_scope_current_claim_only_returns_nonlive(self):
        ret=self.send(self.req())
        self.assertEqual(ret["status"],"OWNER_SCOPE_FIXTURE_MATCHED_NOT_AUTHORITY")
        self.assertTrue(ret["peer_uid_checked"])
        self.assertFalse(ret["filesystem_write_allowed"])
        self.assertFalse(ret["owner_authenticated"])
        self.assertFalse(ret["private_key_shared"])
        self.assertEqual(ret["signed_permit_sha256"],digest(canonical(self.payload)))
    def test_forged_owner_worker_file_repo_epoch_and_operation_denied(self):
        for k,v in [("owner_id","other-owner"),("worker_id","other-worker"),
            ("repository","AnotherOrg/other_repo"),
            ("target","bridge/neurofactory/development/core_owned/other.txt"),
            ("lease_epoch",8),("operation_id","other-operation"),
            ("project_id","other-project"),("source_sha40","9"*40)]:
            with self.subTest(k=k):
                p=dict(self.payload)
                p[k]=v
                self.assertEqual(self.send(self.req(packet=self.sign(p)))["status"],"DENIED_WITNESS")
                self.proc.wait(timeout=3);self.proc=None
    def test_forged_effect_signature_denied(self):
        packet=dict(self.packet,signature_base64=base64.b64encode(b"x"*64).decode())
        self.assertEqual(self.send(self.req(packet=packet))["status"],"DENIED_WITNESS")
    def test_outdated_tip_after_new_signer_claim_denied(self):
        other=as_signer("advance",self.home,digest(b"another signer operation"))
        self.assertEqual(other.returncode,0,other.stderr)
        self.assertEqual(self.send(self.req())["status"],"DENIED_WITNESS")
    def test_fake_witness_from_other_signer_denied(self):
        forged=dict(self.witness)
        forged["certificate"]=dict(self.witness["certificate"],head="9"*64)
        self.assertEqual(self.send(self.req(witness=forged))["status"],"DENIED_WITNESS")
    def test_wrong_peer_same_socket_group_denied(self):
        ret=self.send(self.req(),user="nf_unapproved_client")
        self.assertEqual(ret["status"],"DENIED_PEER")
    def test_signer_unavailable_returns_no_fallback_success(self):
        # An explicitly disabled signer cannot be treated as positive.
        script=("import socket,sys;s=socket.socket(socket.AF_UNIX);"
                "s.settimeout(1);s.connect(sys.argv[1])")
        result=subprocess.run(["sudo","-n","-u","nf_db_actor",PY,"-c",script,
                str(self.sock)],capture_output=True,timeout=3)
        self.assertNotEqual(result.returncode,0)
        self.assertNotEqual(subprocess.run(["sudo","-n","-u","nf_db_actor","test","-r",
                     str(self.home/"issuer-private.raw")]).returncode,0)
    def test_db_actor_cannot_replace_signer_owned_scope(self):
        attempted=subprocess.run(["sudo","-n","-u","nf_db_actor","sh","-c",
          'echo forged > "$1"',"sh",str(self.home/"pinned-effect-scope.json")],
          capture_output=True)
        self.assertNotEqual(attempted.returncode,0)
        self.assertEqual(self.send(self.req())["status"],"OWNER_SCOPE_FIXTURE_MATCHED_NOT_AUTHORITY")

if __name__=="__main__":
    unittest.main()
