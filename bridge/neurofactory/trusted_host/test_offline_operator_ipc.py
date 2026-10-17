"""Real two-UID local-only AF_UNIX read-only signer request/response tests.

All identities and signing keys exist only on throwaway GitHub Ubuntu runner.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

PY=os.environ.get("NF_OPERATOR_TEST_PYTHON")
SOURCE=Path(os.environ.get("NF_OPERATOR_IPC_STAGED_SOURCE","/nonexistent"))
BASE=SOURCE.parent
SIGNER=BASE/"offline_operator_anchor.py"
SERVER=SOURCE

def signer(*args):
    return subprocess.run(["sudo","-n","-u","nf_signer","env",
         "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",PY,str(SIGNER),*map(str,args)],
         capture_output=True,text=True,timeout=10)

class ReadOnlyIPCTests(unittest.TestCase):
    def setUp(self):
        if os.name!="posix" or os.environ.get("NF_OPERATOR_ANCHOR_FIXTURE_ONLY")!="1" or not PY:
            self.skipTest("ephemeral linux two UID fixture required")
        self.temp=tempfile.TemporaryDirectory(prefix="nf-ipc-ci-")
        self.addCleanup(self.cleanup)
        self.base=Path(self.temp.name);self.base.chmod(0o755)
        self.home=self.base/"nf-signer-fixture"
        self.api=self.base/"nf-operator-api"
        self.sock=self.api/"nf-readonly-operator.sock"
        subprocess.run(["sudo","-n","mkdir",str(self.home),str(self.api)],check=True)
        subprocess.run(["sudo","-n","chown","nf_signer:nf_signer",str(self.home),str(self.api)],check=True)
        subprocess.run(["sudo","-n","chmod","0700",str(self.home)],check=True)
        subprocess.run(["sudo","-n","chgrp","nf_operator_ipc",str(self.api)],check=True)
        subprocess.run(["sudo","-n","chmod","2770",str(self.api)],check=True)
        x=signer("bootstrap",self.home)
        self.assertEqual(x.returncode,0,x.stderr)
        self.boot=json.loads(x.stdout)
        self.proc=None
    def cleanup(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:self.proc.wait(timeout=4)
            except subprocess.TimeoutExpired:self.proc.kill()
        subprocess.run(["sudo","-n","rm","-rf","--",str(self.home),str(self.api)],check=True)
        self.temp.cleanup()
    def issue(self,tag):
        cmd=signer("advance",self.home,hashlib.sha256(tag.encode()).hexdigest())
        self.assertEqual(cmd.returncode,0,cmd.stderr)
        return json.loads(cmd.stdout)
    def request(self,packet):
        return {"schema":"neurofactory.operator.readonly_current.v1",
                "packet":packet,"public_sha":self.boot["public_key_sha256"],
                "public_key":self.boot["public_key_base64"]}
    def start(self,uid="nf_db_actor"):
        target=int(subprocess.check_output(["id","-u",uid],text=True).strip())
        self.proc=subprocess.Popen(["sudo","-n","-u","nf_signer","env",
            "NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1",PY,str(SERVER),"serve",
            str(self.home),str(self.sock),str(target)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        for _ in range(80):
            if self.sock.exists():break
            if self.proc.poll() is not None:
                raise AssertionError("signer IPC exited before bound socket: "+
                                     self.proc.stderr.read()[:150])
            time.sleep(0.04)
        self.assertTrue(self.sock.exists())
    def call(self,user,req):
        p=self.base/"request.json"
        p.write_text(json.dumps(req),encoding="ascii")
        p.chmod(0o644)
        script=("import sys,json;from offline_operator_ipc import client_send;"
                "print(json.dumps(client_send(sys.argv[1],"
                "json.load(open(sys.argv[2])))))")
        run=subprocess.run(["sudo","-n","-u",user,"env",
            "PYTHONPATH="+str(BASE),PY,"-c",script,str(self.sock),str(p)],
            capture_output=True,text=True,timeout=5)
        return run
    def test_approved_db_actor_sees_current_signed_witness_not_private_key(self):
        current=self.issue("one")
        self.start()
        r=self.call("nf_db_actor",self.request(current))
        self.assertEqual(r.returncode,0,r.stderr)
        obj=json.loads(r.stdout)
        self.assertEqual(obj["status"],"CURRENT_CHECK_ONLY_NOT_AUTHORITY")
        self.assertTrue(obj["peer_uid_checked"])
        self.assertFalse(obj["private_key_shared"])
        self.assertFalse(obj["filesystem_write_allowed"])
        self.assertNotIn("private_key",r.stdout)
        self.assertNotIn("issuer-private",r.stdout)
    def test_rollback_old_signed_db_receipt_denied_from_consumer_uid(self):
        old=self.issue("first")
        latest=self.issue("second")
        self.start()
        r=self.call("nf_db_actor",self.request(old))
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)["status"],"DENIED_WITNESS")
        self.assertNotEqual(old["certificate"]["head"],latest["certificate"]["head"])
    def test_tampered_signed_witness_denied(self):
        current=self.issue("one")
        current["certificate"]["claim_sha256"]="9"*64
        self.start()
        r=self.call("nf_db_actor",self.request(current))
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)["status"],"DENIED_WITNESS")
    def test_same_shared_group_wrong_uid_denied_by_peercred(self):
        current=self.issue("one")
        self.start()
        r=self.call("nf_unapproved_client",self.request(current))
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)["status"],"DENIED_PEER")
    def test_unsigned_external_process_cannot_read_private_key(self):
        current=self.issue("one")
        attempt=subprocess.run(["sudo","-n","-u","nf_db_actor","cat",
          str(self.home/"issuer-private.raw")],capture_output=True,text=True)
        self.assertNotEqual(attempt.returncode,0)
        self.start()
        r=self.call("nf_db_actor",self.request(current))
        self.assertEqual(json.loads(r.stdout)["status"],"CURRENT_CHECK_ONLY_NOT_AUTHORITY")
    def test_wrong_pinned_public_key_denied_with_valid_signed_packet(self):
        current=self.issue("one")
        req=self.request(current);req["public_sha"]="0"*64
        self.start()
        r=self.call("nf_db_actor",req)
        self.assertEqual(json.loads(r.stdout)["status"],"DENIED_WITNESS")

if __name__=="__main__":
    unittest.main()
