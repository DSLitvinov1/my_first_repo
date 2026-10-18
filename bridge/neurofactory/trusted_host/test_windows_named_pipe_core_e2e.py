"""Windows HOST named-pipe ↔ pinned real CORE one-file E2E; CI fixture only."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from windows_named_pipe_pilot_receiver import (
    serve_one_pilot, core_pilot_send, WindowsReceiverDenied,
)

if os.name != "nt":
    raise RuntimeError("Windows-only explicit SID protected recipient test")
import win32api
import win32con
import win32security

CORE=Path(__file__).resolve().parents[3]/".nf_pinned_core"/"bridge"/"neurofactory"/"development"/"core_owned"
if not CORE.is_dir():
    # GitHub checkout under repository root
    CORE=Path(__file__).resolve().parents[3]/".nf_pinned_core"/"bridge"/"neurofactory"/"development"/"core_owned"
sys.path.insert(0,str(CORE))
from one_task_core import OneTaskCore, EMPTY_SHA, CoreSafetyError

TARGET="bridge/neurofactory/development/core_owned/windows_pilot.txt"


def git(repo,*args):
    return subprocess.check_output(["git","-C",str(repo),*args],
                                   stderr=subprocess.DEVNULL,text=True).strip()


def current_user_sid():
    tok=win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                       win32con.TOKEN_QUERY)
    sid=win32security.GetTokenInformation(tok,win32security.TokenUser)[0]
    return win32security.ConvertSidToStringSid(sid)


class WindowsNamedPipeCoreE2E(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.receiver_root=root/"recipient_only_disposable"
        self.receiver_root.mkdir()
        self.repository=root/"source_git"
        self.repository.mkdir()
        git(self.repository,"init","-q")
        git(self.repository,"config","user.name","test-only")
        git(self.repository,"config","user.email","test@example.invalid")
        (self.repository/"README.md").write_text("synthetic local data\n",encoding="utf8")
        git(self.repository,"add","README.md")
        git(self.repository,"commit","-qm","pinned inert content")
        self.sha=git(self.repository,"rev-parse","HEAD")
        self.workspace=root/"core_state"
        self.workspace.mkdir()
        self.core=OneTaskCore(self.workspace,self.repository)
        self.spec=dict(
            schema="neurofactory.core.task.v1",
            task_id="NF-DEV-05-Q901",project_id="core-test",
            target=TARGET,
            objective="Save one verified inert Windows pilot file without production operation.",
            source_sha=self.sha,source_sha256=EMPTY_SHA,
            model="qwen2.5-coder:1.5b",reserved_units=10,approval_commit=self.sha)
        self.core.enqueue(self.spec,trusted_approval_check=lambda q:q==self.spec)
        self.claim=self.core.claim("worker-one",now=int(time.time()),lease_seconds=120)
        data="NEUROFACTORY_WINDOWS_SAFE_PILOT_ONE_FILE\n"
        self.proposal=dict(schema="neurofactory.core.proposal.v1",
                           target=TARGET,content=data,
                           content_sha256=hashlib.sha256(data.encode()).hexdigest(),
                           mode="OFFLINE_TEST")
        self.signer=Ed25519PrivateKey.generate()
        self.sid=current_user_sid()
        self.pipe=r"\\.\pipe\neurofactory-pilot-"+secrets.token_hex(12)
        self.errors=[]
        self.results=[]

    def start_server(self,*,pub=None):
        def run():
            try:
                self.results.append(serve_one_pilot(
                    self.pipe,self.receiver_root,
                    self.signer.public_key() if pub is None else pub,
                    self.sid))
            except Exception as e:
                self.errors.append(repr(e))
                print('NF_TEMP_WINDOWS_SERVER_EXCEPTION='+repr(e),flush=True)
        th=threading.Thread(target=run,daemon=True)
        th.start()
        return th

    def send(self,*,key=None,token=None):
        return core_pilot_send(
            self.pipe,self.proposal,self.spec,self.signer if key is None else key,
            core=self.core,worker_id="worker-one",
            core_token=self.claim["token"] if token is None else token)

    def test_real_core_claim_to_windows_protected_pipe_one_inert_file(self):
        thread=self.start_server()
        result=self.send()
        thread.join(timeout=8)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors,[])
        self.assertEqual(result["status"],"CORE_WINDOWS_ONE_INERT_PILOT_TEST_ONLY")
        self.assertFalse(result["core_wrote_local_file"])
        self.assertFalse(result["live_execution_allowed"])
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")
        target=self.receiver_root/"windows_pilot.txt"
        self.assertEqual(target.read_text(encoding="utf8"),
                         self.proposal["content"])
        receipt=json.loads((self.receiver_root/"one_effect_unknown.json").read_text())
        self.assertEqual(receipt["state"],"UNKNOWN_NO_AUTO_RETRY")
        self.assertEqual({p.name for p in self.receiver_root.iterdir()},
                         {"windows_pilot.txt","one_effect_unknown.json"})
        self.assertFalse((self.core.sandbox/TARGET).exists())
        print("NF_WINDOWS_REAL_CORE_PIPE_ONE_FILE=PASS_TEST_ONLY")

    def test_duplicate_message_cannot_overwrite_inert_result(self):
        thread=self.start_server()
        self.send()
        thread.join(timeout=8)
        self.assertFalse(self.errors,self.errors)
        second=self.start_server()
        with self.assertRaises(WindowsReceiverDenied):
            self.send()
        second.join(timeout=8)
        self.assertFalse(second.is_alive())
        target=self.receiver_root/"windows_pilot.txt"
        self.assertEqual(target.read_text(),self.proposal["content"])
        self.assertEqual(len(list(self.receiver_root.iterdir())),2)
        print("NF_WINDOWS_ONE_FILE_REPLAY_NO_OVERWRITE=PASS_TEST_ONLY")

    def test_forged_owner_signature_never_creates_file(self):
        thread=self.start_server()
        with self.assertRaises(WindowsReceiverDenied):
            self.send(key=Ed25519PrivateKey.generate())
        thread.join(timeout=8)
        self.assertFalse(thread.is_alive())
        self.assertFalse(list(self.receiver_root.iterdir()))
        self.assertFalse(self.errors,self.errors)
        print("NF_WINDOWS_FORGED_OWNER_NO_FILE=PASS")

    def test_invalid_core_claim_cannot_send_to_protected_receiver(self):
        with self.assertRaises(WindowsReceiverDenied):
            self.send(token="malicious-local-claim")
        self.assertFalse(list(self.receiver_root.iterdir()))
        self.assertFalse((self.core.sandbox/TARGET).exists())

    def test_core_legacy_direct_writer_remains_denied(self):
        with self.assertRaisesRegex(CoreSafetyError,"LEGACY_WRITE_DISABLED"):
            self.core.apply_offline_test(self.spec["task_id"],self.claim["token"],
                                         self.proposal,now=int(time.time()))
        self.assertFalse((self.core.sandbox/TARGET).exists())


if __name__=="__main__":
    unittest.main()
