"""Targeted real named-pipe signed admission against real CORE SQLite.

Creates two distinct real Windows user SIDs on disposable GitHub runner via
existing tested owner fixture; NEVER installs/starts HOST SCM or an AI model.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import secrets
import sys
from threading import Event, Thread
import unittest

import test_windows_owner_controller_candidate as owner_ci
from windows_core_admission_pipe import (
    CorePipeDenied, _parse_packet, send_one_owner_permit,
    serve_one_signed_core_admission
)
from signed_owner_admission import AdmissionDenied


class WindowsNamedPipeOwnerCoreCI(unittest.TestCase):
    def setUp(self):
        if (os.name != "nt" or os.getenv("GITHUB_ACTIONS") != "true" or
                os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or
                os.getenv("NF_CORE_OWNER_PIPE_CI_ONLY") != "1"):
            self.skipTest("Disposable CI Windows only")
        self.fixture = owner_ci.OwnerControllerWindowsCI(
            methodName="test_real_dpapi_signing_and_real_core_queue_one_shot")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.pipe = r"\\.\pipe\neurofactory-admission-" + secrets.token_hex(12)
        self.errors = []
        self.responses = []

    def server(self, **overrides):
        ready = Event()
        opts = {
            "trusted_sender_sid": self.fixture.signer_identity,
            "owner_public_raw": self.fixture.pub,
            "workspace": self.fixture.fi.workspace,
            "core": self.fixture.fi.core,
            "ready": ready,
        }
        opts.update(overrides)

        def receive():
            try:
                self.responses.append(serve_one_signed_core_admission(
                    self.pipe, **opts))
            except Exception as exc:
                self.errors.append(type(exc).__name__ + ": " + str(exc))
        thread = Thread(target=receive, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(timeout=5), "Windows named pipe never opened")
        return thread

    def finish(self, thread):
        thread.join(timeout=7)
        self.assertFalse(thread.is_alive(), "Windows named-pipe receiver not terminated")
        self.assertEqual(self.errors, [])
        self.assertEqual(len(self.responses), 1)

    def test_real_dpapi_signed_owner_pipe_enqueue_once_and_replay_denied(self):
        permit = self.fixture.sign()
        thread = self.server()
        received = send_one_owner_permit(
            self.pipe, permit, expected_receiver_sid=self.fixture.signer_identity)
        self.finish(thread)
        self.assertEqual(received["status"], "QUEUED_SIGNED_TEST_ONLY")
        self.assertEqual(received["task_id"], self.fixture.fi.permit()["spec"]["task_id"])
        self.assertFalse(received["execution_allowed"])
        self.assertFalse(received["auto_retry_allowed"])
        self.assertEqual(self.fixture.fi.core.snapshot()["state"], "QUEUED")
        # Actual second pipe instance with same signed permit is denied
        # at existing CORE SQLite singleton. No automatic retry inside app.
        self.responses.clear()
        thread2 = self.server()
        duplicate = send_one_owner_permit(
            self.pipe, permit, expected_receiver_sid=self.fixture.signer_identity)
        self.finish(thread2)
        self.assertEqual(duplicate["status"], "DENIED_OR_UNKNOWN_MANUAL_REVIEW")
        self.assertEqual(duplicate["task_id"], "")
        self.assertEqual(self.fixture.fi.core.snapshot()["state"], "QUEUED")
        print("NF_WINDOWS_REAL_SIGNED_NAMED_PIPE_CORE_QUEUED_ONCE=PASS")
        print("NF_WINDOWS_REAL_SIGNED_NAMED_PIPE_DUPLICATE=DENIED")

    def test_unknown_result_after_real_core_commit_never_auto_retries(self):
        class CommitThenLoseAcknowledgement:
            def __init__(self, core):
                self.core = core

            def enqueue(self, *args, **kwargs):
                self.core.enqueue(*args, **kwargs)
                # Simulates disconnect/crash AFTER the real SQLite commit.
                raise RuntimeError("Injected CI-only post-commit unknown result")

        permit = self.fixture.sign()
        thread = self.server(
            core=CommitThenLoseAcknowledgement(self.fixture.fi.core))
        result = send_one_owner_permit(
            self.pipe, permit,
            expected_receiver_sid=self.fixture.signer_identity)
        self.finish(thread)
        self.assertEqual(result["status"], "DENIED_OR_UNKNOWN_MANUAL_REVIEW")
        self.assertFalse(result["auto_retry_allowed"])
        # Real CORE database is already QUEUED. Never trust the failed
        # response as proof that it was not admitted.
        self.assertEqual(self.fixture.fi.core.snapshot()["state"], "QUEUED")
        self.assertEqual(
            self.fixture.fi.workspace.list_tasks()[0]["state"],
            "DRAFT_PENDING_OWNER_AUTH")
        print("NF_WINDOWS_CORE_POST_COMMIT_UNKNOWN=MANUAL_STOP_NO_RETRY")

    def test_forged_signed_task_via_pipe_fails_closed(self):
        permit = self.fixture.sign()
        permit["spec"]["objective"] = "Mutated request with invalid signature and changed owner decision."
        thread = self.server()
        result = send_one_owner_permit(
            self.pipe, permit, expected_receiver_sid=self.fixture.signer_identity)
        self.finish(thread)
        self.assertEqual(result["status"], "DENIED_OR_UNKNOWN_MANUAL_REVIEW")
        self.assertEqual(self.fixture.fi.core.snapshot()["state"], "EMPTY")
        print("NF_WINDOWS_PIPE_OWNER_SIGNATURE_TAMPER=DENIED_NO_CORE")

    def test_actual_foreign_windows_ui_sid_cannot_connect_to_owner_pipe(self):
        import win32security
        import win32con
        identity = win32security.LogonUser(
            self.fixture.ci_user_name, os.environ["COMPUTERNAME"],
            self.fixture.ci_user_password,
            win32con.LOGON32_LOGON_INTERACTIVE,
            win32con.LOGON32_PROVIDER_DEFAULT,
        )
        permit = self.fixture.sign()
        thread = self.server()
        try:
            win32security.ImpersonateLoggedOnUser(identity)
            with self.assertRaises(CorePipeDenied):
                send_one_owner_permit(
                    self.pipe, permit, expected_receiver_sid=self.fixture.signer_identity)
        finally:
            win32security.RevertToSelf()
            identity.Close()
        self.assertEqual(self.fixture.fi.core.snapshot()["state"], "EMPTY")
        result = send_one_owner_permit(
            self.pipe, permit, expected_receiver_sid=self.fixture.signer_identity)
        self.finish(thread)
        self.assertEqual(result["status"], "QUEUED_SIGNED_TEST_ONLY")
        print("NF_WINDOWS_SECOND_USER_ACTUAL_NAMED_PIPE_ACCESS=DENIED")

    def test_unsigned_and_duplicate_json_never_admitted(self):
        with self.assertRaises(CorePipeDenied):
            _parse_packet(b'{"schema":"A","schema":"A","permit":{}}')
        with self.assertRaises(CorePipeDenied):
            _parse_packet(b'{"schema":"nf.windows.core.signed_admission_transport_ci.v1",'
                          b'"permit":{},"owner_public_key":"attacker"}')
        with self.assertRaises(CorePipeDenied):
            _parse_packet(b"x" * 8193)
        with self.assertRaises(CorePipeDenied):
            _parse_packet(b'{"schema":"nf.windows.core.signed_admission_transport_ci.v1",'
                          b'"permit":{}}', response=True)
        self.assertEqual(self.fixture.fi.core.snapshot()["state"], "EMPTY")
        print("NF_WINDOWS_PIPE_UNKNOWN_FIELDS_OVERSIZE_DUPLICATES=DENIED")


if __name__ == "__main__":
    unittest.main()
