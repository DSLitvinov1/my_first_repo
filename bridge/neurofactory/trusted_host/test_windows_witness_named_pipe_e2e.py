"""Real Windows CORE SQLite -> Named Pipe receiver -> mTLS witness -> inert file.

All run on ONE ephemeral GitHub Windows runner, using same user SID.
Do not claim physical node separation, reboot or production authorization.
"""
import hashlib
import json
import os
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

import test_windows_named_pipe_core_e2e as corefixture
import test_windows_external_witness_pilot as witnessfixture
from windows_named_pipe_pilot_receiver import (
    WindowsReceiverDenied,serve_one_pilot,
)
from windows_external_witness_pilot import PinnedWindowsWitnessSandboxAdapter

class WindowsReceiverWitnessIntegration(unittest.TestCase):
    def setUp(self):
        self.env=patch.dict(os.environ,{
            "NF_WINDOWS_WITNESS_TEST_ONLY":"1",
            "NF_WINDOWS_WITNESS_REQUIRED_TEST_ONLY":"1",
        })
        self.env.start();self.addCleanup(self.env.stop)
        self.c=corefixture.WindowsNamedPipeCoreE2E(
            "test_real_core_claim_to_windows_protected_pipe_one_inert_file")
        self.c.setUp()
        self.addCleanup(self.c.doCleanups)
        self.w=witnessfixture.WindowsExternalWitnessPilotTests(
            "test_one_signed_mutual_tls_durable_reservation_and_process_restart")
        self.w.setUp()
        self.addCleanup(self.w.doCleanups)
        self.errors=[]
        self.responses=[]

    def adapter(self,**changes):
        args=dict(task_id=self.c.spec["task_id"],
                  target_sha256=hashlib.sha256(
                      self.c.proposal["target"].encode("utf8")).hexdigest(),
                  port=self.w.port,client_cert=self.w.cli_cert,
                  client_key=self.w.cli_key,ca_cert=self.w.ca,
                  pinned_server_cert_sha256=self.w.srv_fp,
                  pinned_witness_public_b64=self.w.witness_pub)
        args.update(changes)
        return PinnedWindowsWitnessSandboxAdapter(**args)

    def pipe(self, remote):
        self.errors=[]
        self.responses=[]
        def run():
            try:
                self.responses.append(serve_one_pilot(
                    self.c.pipe,self.c.receiver_root,
                    self.c.signer.public_key(),self.c.sid,
                    remote_witness=remote))
            except Exception as e:self.errors.append(str(e))
        t=threading.Thread(target=run,daemon=True)
        t.start()
        # On Windows WaitNamedPipe can fail with FILE_NOT_FOUND if the
        # receiving thread has not called CreateNamedPipe yet.
        import win32pipe
        import pywintypes
        for _ in range(80):
            try:
                win32pipe.WaitNamedPipe(self.c.pipe,100)
                break
            except pywintypes.error as exc:
                if exc.winerror not in (2, 231):
                    raise
                time.sleep(0.025)
        else:
            self.fail("Named Pipe receiver did not reach listening state")
        return t

    def finish(self,t):
        t.join(8)
        self.assertFalse(t.is_alive(),"test Named Pipe listener hung")
        self.assertEqual(self.errors,[])
        self.assertEqual(len(self.responses),1)

    def test_positive_one_real_core_pipe_mtls_witness_and_file(self):
        self.w.start()
        t=self.pipe(self.adapter())
        result=self.c.send()
        self.finish(t)
        self.assertEqual(result["status"],"CORE_WINDOWS_ONE_INERT_PILOT_TEST_ONLY")
        self.assertEqual(self.w.database_count(),1)
        self.assertEqual((self.c.receiver_root/"windows_pilot.txt").read_text(),
                         self.c.proposal["content"])
        self.assertEqual(self.c.core.snapshot()["state"],"CLAIMED")
        self.assertFalse(result["live_execution_allowed"])

    def test_denied_forged_owner_does_not_reserve_or_write(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.w.start()
        t=self.pipe(self.adapter())
        with self.assertRaises(WindowsReceiverDenied):
            self.c.send(key=Ed25519PrivateKey.generate())
        self.finish(t)
        self.assertEqual(self.w.database_count(),0)
        self.assertFalse((self.c.receiver_root/"windows_pilot.txt").exists())

    def test_denied_expired_actual_core_sqlite_lease(self):
        with self.c.core._connect() as db:
            db.execute("UPDATE single_job SET lease_until=1 WHERE singleton=1")
        with self.assertRaises(WindowsReceiverDenied):
            self.c.send()
        self.assertEqual(self.w.database_count(),0)
        self.assertFalse((self.c.receiver_root/"windows_pilot.txt").exists())

    def test_denied_wrong_pinned_remote_server_certificate(self):
        self.w.start()
        t=self.pipe(self.adapter(pinned_server_cert_sha256="f"*64))
        with self.assertRaises(WindowsReceiverDenied):
            self.c.send()
        self.finish(t)
        self.assertEqual(self.w.database_count(),0)
        self.assertFalse((self.c.receiver_root/"windows_pilot.txt").exists())
        self.assertEqual(json.loads(
            (self.c.receiver_root/"one_effect_unknown.json").read_text()
        )["state"],"UNKNOWN_NO_AUTO_RETRY")

    def test_denied_wrong_pinned_task_or_target_before_witness(self):
        self.w.start()
        t=self.pipe(self.adapter(target_sha256="b"*64))
        with self.assertRaises(WindowsReceiverDenied):
            self.c.send()
        self.finish(t)
        self.assertEqual(self.w.database_count(),0)
        self.assertFalse((self.c.receiver_root/"windows_pilot.txt").exists())

    def test_lost_witness_ack_keeps_remote_reservation_and_no_file(self):
        self.w.start(drop=True)
        t=self.pipe(self.adapter())
        with self.assertRaises(WindowsReceiverDenied):
            self.c.send()
        self.finish(t)
        self.assertEqual(self.w.database_count(),1)
        self.assertFalse((self.c.receiver_root/"windows_pilot.txt").exists())
        self.assertTrue((self.c.receiver_root/"one_effect_unknown.json").exists())

    def test_receiver_checkpoint_rollback_remote_witness_still_denies_replay(self):
        self.w.start()
        t=self.pipe(self.adapter())
        self.c.send()
        self.finish(t)
        self.assertEqual(self.w.database_count(),1)
        # Simulate receiver-only state rollback, not physical OS or disk reboot.
        (self.c.receiver_root/"windows_pilot.txt").unlink()
        (self.c.receiver_root/"one_effect_unknown.json").unlink()
        self.w.stop()
        self.w.start()
        t=self.pipe(self.adapter())
        with self.assertRaises(WindowsReceiverDenied):
            self.c.send()
        self.finish(t)
        self.assertEqual(self.w.database_count(),1)
        self.assertFalse((self.c.receiver_root/"windows_pilot.txt").exists())

if __name__=="__main__": unittest.main()
