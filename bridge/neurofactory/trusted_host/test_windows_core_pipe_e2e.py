"""Real pinned CORE SQLite/Git claim -> Windows SID-ACL named pipe -> one inert file.

Runs ONLY on disposable GitHub-hosted Windows; does NOT install a service,
touch owner's PC, deploy real keys, authorize live work or use real project
data. Test-P256 private keys exist only in this ephemeral test process.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from multiprocessing.connection import Client

HERE=Path(__file__).resolve().parent
CORE_DIR=Path(os.environ.get("NF_PINNED_CORE_DIR","/missing"))
sys.path.insert(0,str(CORE_DIR))
from one_task_core import OneTaskCore
from windows_core_pipe_client import CoreProtectedWindowsReceiverClient,WindowsCoreRouteDenied

WORKER="worker-windows-sandbox"
TASK="NF-DEV-05-Q982"
TARGET="bridge/neurofactory/development/core_owned/core-e2e-proof.txt"
CONTENT="NEUROFACTORY isolated Windows one-file effect, not real project code."
DLL=Path(os.environ.get("NF_WIN_RECEIVER_DLL","/missing"))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(data):
    return json.dumps(data,ensure_ascii=True,sort_keys=True,
                      separators=(",",":"),allow_nan=False).encode("ascii")


def sid():
    cmd=["powershell.exe","-NoProfile","-NonInteractive","-Command",
         "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"]
    result=subprocess.run(cmd,capture_output=True,text=True,check=True,timeout=12)
    value=result.stdout.strip()
    if not value.startswith("S-1-"):raise RuntimeError("Windows current SID missing")
    return value


class ActualCoreWindowsPipeE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (os.name=="nt" and os.environ.get("GITHUB_ACTIONS")=="true"
                and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted"
                and os.environ.get("NF_WINDOWS_RECEIVER_CI_ONLY")=="1"
                and DLL.is_file() and CORE_DIR.is_dir()):
            raise RuntimeError("DISPOSABLE GH WINDOWS ONLY, not local user's PC")
        cls.worker_sid=sid()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="nfwin-core-host-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.repo=self.root/"repo"
        self.repo.mkdir()
        subprocess.run(["git","init","-q",str(self.repo)],check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run(["git","-C",str(self.repo),"-c","user.email=nf@example.invalid",
                        "-c","user.name=NF CI Fixture","commit","--allow-empty","-qm",
                        "fresh empty pinned source"],check=True)
        self.head=subprocess.check_output(
            ["git","-C",str(self.repo),"rev-parse","HEAD"],text=True).strip()
        self.core_root=self.root/"core"
        self.core_root.mkdir()
        self.core=OneTaskCore(self.core_root,self.repo)
        self.spec={
            "schema":"neurofactory.core.task.v1",
            "task_id":TASK,"project_id":"nf-sandbox",
            "target":TARGET,
            "objective":"Create one harmless Windows scratch evidence line only.",
            "source_sha":self.head,
            "source_sha256":sha(b""),
            "model":"qwen2.5-coder:1.5b",
            "reserved_units":2,"approval_commit":self.head,
        }
        result=self.core.enqueue(self.spec,trusted_approval_check=lambda s: True)
        self.assertEqual(result["state"],"QUEUED")
        self.claim=self.core.claim(WORKER,lease_seconds=180)
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")
        self.proposal={
            "schema":"neurofactory.core.proposal.v1",
            "target":TARGET,"content":CONTENT,
            "content_sha256":sha(CONTENT.encode("utf-8")),
            "mode":"OFFLINE_TEST"
        }
        self.key=ec.generate_private_key(ec.SECP256R1())
        spki=self.key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.outdir=self.root/"protected-recipient"
        self.outdir.mkdir()
        self.pipe_name="nf-ci-"+secrets.token_hex(8)
        self.config=self.root/"receiver.json"
        self.config.write_text(json.dumps({
            "PipeName":self.pipe_name,
            "ScratchRoot":str(self.outdir),
            "WorkerSid":self.worker_sid,
            "OwnerPublicSpkiBase64":base64.b64encode(spki).decode("ascii"),
            "TaskId":TASK,"ProjectId":"nf-sandbox",
            "SourceSha40":self.head,
            "AllowedTarget":"core-e2e-proof.txt",
        }),encoding="ascii")
        self.client=CoreProtectedWindowsReceiverClient(
            self.core,pipe_name=self.pipe_name)

    def body(self,**changes):
        p={
            "schema":"neurofactory.windows.core_signed_scratch.v1",
            "task_id":TASK,"project_id":"nf-sandbox",
            "source_sha40":self.head,
            "target":"core-e2e-proof.txt",
            "mode":"CORE_SIGNED_SCRATCH_TEST_ONLY",
            "model_invoked":False,"owner_confirmed":True,
            "content_sha256":self.proposal["content_sha256"],
            "operation_id":"op-"+secrets.token_hex(12),
            "worker_id":WORKER,"expires_unix":int(time.time())+60,
        }
        p.update(changes)
        return canonical(p)

    def signing(self,body=None):
        data=self.body() if body is None else body
        der=self.key.sign(data,ec.ECDSA(hashes.SHA256()))
        r,s=utils.decode_dss_signature(der)
        sig=r.to_bytes(32,"big")+s.to_bytes(32,"big")
        return data,base64.b64encode(sig).decode("ascii")

    def start(self,*,crash_after_intent=False):
        e=os.environ.copy()
        if crash_after_intent:e["NF_WIN_CI_CRASH_AFTER_INTENT"]="1"
        else:e.pop("NF_WIN_CI_CRASH_AFTER_INTENT",None)
        p=subprocess.Popen(["dotnet",str(DLL),"--ci-one-shot",str(self.config)],
                           cwd=str(self.root),
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           text=True,env=e)
        self.addCleanup(self.stop_if_running,p)
        line=p.stdout.readline()
        self.assertEqual(line.strip(),"NF_WIN_RECEIVER_LISTENING_TEST_ONLY",
                         "receiver did not start: "+p.stderr.read() if p.poll() is not None else
                         "receiver listener not available")
        return p

    @staticmethod
    def stop_if_running(p):
        if p.poll() is None:
            p.kill()
            p.communicate(timeout=5)

    def finish(self,p):
        p.wait(timeout=12)
        self.assertEqual(p.returncode,0,
                         "receiver failure: "+p.stderr.read())

    def send_direct(self,body=None,signature=None,content=None):
        body,sig=self.signing(body)
        msg={
            "schema":"nf.windows.receiver.request.v1",
            "body_base64":base64.b64encode(body).decode("ascii"),
            "owner_signature_base64":sig if signature is None else signature,
            "content_base64":base64.b64encode(
                CONTENT.encode() if content is None else content).decode("ascii")
        }
        with Client(r"\\.\pipe\\".rstrip("\\")+"\\"+self.pipe_name,
                    family="AF_PIPE") as pipe:
            pipe.send_bytes(canonical(msg))
            response=json.loads(pipe.recv_bytes(4096).decode("ascii"))
        return response

    def assert_no_file(self):
        self.assertFalse((self.outdir/"core-e2e-proof.txt").exists())
        self.assertFalse((self.outdir/"nf-effect-unknown.receipt").exists())

    def test_actual_core_sqlite_git_claim_one_file_and_restart_replay_denied(self):
        signed,sig=self.signing()
        host=self.start()
        res=self.client.propose_once(
            task_id=TASK,worker_id=WORKER,core_token=self.claim["token"],
            proposal=self.proposal,signed_body_bytes=signed,
            owner_signature_base64=sig)
        self.finish(host)
        self.assertEqual(res["status"],"CORE_WINDOWS_PROTECTED_SCRATCH_ONE_EFFECT_TEST_ONLY")
        self.assertFalse(res["live_execution_allowed"])
        self.assertFalse(res["core_wrote_local_file"])
        self.assertEqual((self.outdir/"core-e2e-proof.txt").read_bytes(),
                         CONTENT.encode("utf-8"))
        self.assertTrue((self.outdir/"nf-effect-unknown.receipt").is_file())
        self.assertFalse((self.core.sandbox/"bridge").exists())
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")
        second=self.start()
        with self.assertRaises(WindowsCoreRouteDenied):
            self.client.propose_once(
                task_id=TASK,worker_id=WORKER,core_token=self.claim["token"],
                proposal=self.proposal,signed_body_bytes=signed,
                owner_signature_base64=sig)
        self.finish(second)
        self.assertEqual(len(list(self.outdir.glob("core-e2e-proof.txt"))),1)
        print("NF_REAL_CORE_WINDOWS_PIPE_ONE_FILE_RESTART_NO_REPLAY=PASS")

    def test_foreign_signer_denied_before_intent(self):
        other=ec.generate_private_key(ec.SECP256R1())
        data=self.body()
        r,s=utils.decode_dss_signature(other.sign(data,ec.ECDSA(hashes.SHA256())))
        forged=base64.b64encode(r.to_bytes(32,"big")+s.to_bytes(32,"big")).decode()
        host=self.start()
        reply=self.send_direct(data,signature=forged)
        self.finish(host)
        self.assertEqual(reply["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assert_no_file()

    def test_expired_owner_grant_denied(self):
        host=self.start()
        response=self.send_direct(self.body(expires_unix=int(time.time())-1))
        self.finish(host)
        self.assertEqual(response["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assert_no_file()

    def test_source_commit_substitution_denied(self):
        host=self.start()
        response=self.send_direct(self.body(source_sha40="f"*40))
        self.finish(host)
        self.assertEqual(response["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assert_no_file()

    def test_escape_target_traversal_denied(self):
        host=self.start()
        response=self.send_direct(self.body(target="../escape.txt"))
        self.finish(host)
        self.assertEqual(response["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assert_no_file()

    def test_signed_digest_with_modified_content_denied(self):
        host=self.start()
        response=self.send_direct(content=b"not the bytes signed by owner")
        self.finish(host)
        self.assertEqual(response["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assert_no_file()

    def test_intent_before_file_crash_then_no_retry(self):
        signed,sig=self.signing()
        first=self.start(crash_after_intent=True)
        response=self.send_direct(signed)
        self.finish(first)
        self.assertEqual(response["status"],"DENIED_OR_UNKNOWN_MANUAL_STOP")
        self.assertTrue((self.outdir/"nf-effect-unknown.receipt").exists())
        self.assertFalse((self.outdir/"core-e2e-proof.txt").exists())
        again=self.start()
        with self.assertRaises(WindowsCoreRouteDenied):
            self.client.propose_once(
                task_id=TASK,worker_id=WORKER,core_token=self.claim["token"],
                proposal=self.proposal,signed_body_bytes=signed,
                owner_signature_base64=sig)
        self.finish(again)
        self.assertFalse((self.outdir/"core-e2e-proof.txt").exists())
        print("NF_WINDOWS_CRASH_AFTER_UNKNOWN_RESTART_MANUAL_STOP=PASS")

    def test_core_stale_local_claim_rejected_before_pipe(self):
        signed,sig=self.signing()
        with self.core._connect() as c:
            c.execute("UPDATE single_job SET lease_until=0")
        with self.assertRaises(WindowsCoreRouteDenied):
            self.client.propose_once(
                task_id=TASK,worker_id=WORKER,core_token=self.claim["token"],
                proposal=self.proposal,signed_body_bytes=signed,
                owner_signature_base64=sig)
        self.assert_no_file()

if __name__=="__main__":
    unittest.main()
