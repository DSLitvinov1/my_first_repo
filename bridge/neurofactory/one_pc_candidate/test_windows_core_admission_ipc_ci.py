"""Addressed Windows kernel SID named-pipe delivery, genuine signed CORE SQLite.

Only ephemeral GitHub-hosted Windows. No owner computer, deployment or Qwen
repeat. The pipeline source modules from PR48 remain unmodified.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import secrets
import sys
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_windows_owner_controller_candidate import OwnerControllerWindowsCI
from windows_owner_controller_candidate import protect_acl, PRIVATE_FILE
from windows_core_admission_ipc_ci import (
    serve_signed_core_once_ci, send_signed_permit_once_ci, PREFIX,
    AdmissionIPCRejected,
)

if os.name == "nt":
    import win32con
    import win32security


class SignedIPCRealWindows(unittest.TestCase):
    def setUp(self):
        if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or
                os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
                os.environ.get("NF_CORE_ADMISSION_PIPE_CI_ONLY") != "1"):
            self.skipTest("Disposable GitHub Windows only")
        self.operator = OwnerControllerWindowsCI(
            "test_real_dpapi_signing_and_real_core_queue_one_shot")
        self.operator.setUp()
        self.addCleanup(self.operator.tearDown)
        self.fi = self.operator.fi
        self.sid = self.operator.ui_sid
        self.public = self.operator.pub
        # Protect BOTH independently durable SQLite stores using genuine
        # NTFS ACLs so the unprivileged pipe sender cannot bypass the
        # receiver and enqueue directly by opening files itself.
        protect_acl(self.fi.workspace.directory, directory=True)
        protect_acl(self.fi.workspace.database, directory=False)
        protect_acl(self.fi.core.state, directory=True)
        protect_acl(self.fi.core.state / "queue.sqlite3", directory=False)

    def send_as_unprivileged_user(self, name, permit, *, assert_denied_db=False):
        token = win32security.LogonUser(
            self.operator.ci_user_name, os.environ["COMPUTERNAME"],
            self.operator.ci_user_password,
            win32con.LOGON32_LOGON_INTERACTIVE,
            win32con.LOGON32_PROVIDER_DEFAULT)
        try:
            win32security.ImpersonateLoggedOnUser(token)
            try:
                if assert_denied_db:
                    for protected in (
                        self.operator.root / PRIVATE_FILE,
                        self.fi.workspace.database,
                        self.fi.core.state / "queue.sqlite3",
                    ):
                        with self.assertRaises((PermissionError, OSError)):
                            protected.read_bytes()
                return send_signed_permit_once_ci(name, permit)
            finally:
                win32security.RevertToSelf()
        finally:
            token.Close()

    def serve(self, name, *, pub=None):
        result = []
        errors = []
        def receiver():
            try:
                result.append(serve_signed_core_once_ci(
                    name, client_sid=self.sid,
                    pinned_owner_public_raw=self.public if pub is None else pub,
                    workspace=self.fi.workspace, core=self.fi.core))
            except Exception as exc:
                errors.append(type(exc).__name__ + ": " + str(exc))
        t = threading.Thread(target=receiver, daemon=True)
        t.start()
        return t, result, errors

    def one_exchange(self, permit, *, from_ui=True, pub=None,
                     assert_denied_db=False):
        name = PREFIX + secrets.token_hex(12)
        t, result, errors = self.serve(name, pub=pub)
        try:
            answer = (self.send_as_unprivileged_user(
                name, permit, assert_denied_db=assert_denied_db)
                if from_ui else send_signed_permit_once_ci(name, permit))
        finally:
            t.join(timeout=8)
        self.assertFalse(t.is_alive(), "Trust-boundary receiver blocked or hung")
        self.assertFalse(errors, errors)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], answer)
        self.assertFalse(answer["queue_claim_allowed"])
        self.assertFalse(answer["host_execution_allowed"])
        self.assertFalse(answer["automatic_retry_allowed"])
        self.assertFalse(answer["independently_verified"])
        return answer

    def test_real_different_windows_sid_delivers_one_approved_core_task(self):
        permit = self.operator.sign()
        result = self.one_exchange(
            permit, assert_denied_db=True)
        self.assertEqual(result["status"], "OBSERVED_QUEUED_TEST_ONLY")
        self.assertEqual(result["core_task_id"], permit["spec"]["task_id"])
        self.assertEqual(self.fi.core.snapshot()["state"], "QUEUED")
        self.assertEqual(self.fi.workspace.list_tasks()[0]["state"],
                         "DRAFT_PENDING_OWNER_AUTH")
        # Another pipe instance does not imply permission for a second
        # durable CORE enqueue or another model request.
        repeat = self.one_exchange(permit)
        self.assertEqual(repeat["status"], "DENIED_OR_UNKNOWN_NO_AUTO_RETRY")
        self.assertEqual(self.fi.core.snapshot()["state"], "QUEUED")
        print("NF_IPC_REAL_DIFFERENT_USER_SID_SIGNED_CORE_QUEUED_ONCE=PASS")
        print("NF_IPC_REAL_CORE_SQLITE_AND_DPAPI_NTFS_FOREIGN_READ=DENIED")
        print("NF_IPC_SIGNED_PERMIT_REPLAY=DENIED_NO_RETRY")

    def test_unpinned_sender_sid_cannot_enqueue_even_valid_owner_signature(self):
        signed = self.operator.sign()
        reply = self.one_exchange(signed, from_ui=False)
        self.assertEqual(reply["status"], "DENIED_OR_UNKNOWN_NO_AUTO_RETRY")
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        print("NF_IPC_SIGNED_OWNER_BUT_WRONG_CLIENT_OS_SID=DENIED")

    def test_fake_owner_and_cross_project_or_expired_permit_cannot_enqueue(self):
        forged = self.fi.permit(private=Ed25519PrivateKey.generate())
        self.assertEqual(
            self.one_exchange(forged)["status"],
            "DENIED_OR_UNKNOWN_NO_AUTO_RETRY")
        correct = self.operator.sign()
        foreign = {**correct, "spec": {
            **correct["spec"], "project_id": "p-" + "f" * 32}}
        # Signature is now invalid and project differs.
        self.assertEqual(self.one_exchange(foreign)["status"],
                         "DENIED_OR_UNKNOWN_NO_AUTO_RETRY")
        expired = {**correct, "expires_at": int(time.time()) - 900}
        self.assertEqual(self.one_exchange(expired)["status"],
                         "DENIED_OR_UNKNOWN_NO_AUTO_RETRY")
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        print("NF_IPC_FORGED_FOREIGN_PROJECT_EXPIRED_PERMIT=DENIED")

    def test_stale_draft_and_malformed_wire_payload_do_not_enqueue(self):
        signed = self.operator.sign()
        with self.fi.workspace.connect() as conn:
            conn.execute("UPDATE tasks SET objective=? WHERE id=?",
                         ("Different saved objective after owner's signature.",
                          self.fi.draft["id"]))
            conn.commit()
        self.assertEqual(self.one_exchange(signed)["status"],
                         "DENIED_OR_UNKNOWN_NO_AUTO_RETRY")
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        with self.assertRaises(AdmissionIPCRejected):
            send_signed_permit_once_ci(
                r"\\.\pipe\wrong-admission-name", signed)
        print("NF_IPC_MUTATED_PERSISTED_DRAFT=DENIED")
        print("NF_IPC_FOREIGN_PIPE_NAME=DENIED")
        
    def test_non_ci_host_cannot_start_receiver(self):
        existing = os.environ.pop("NF_CORE_ADMISSION_PIPE_CI_ONLY")
        try:
            name = PREFIX + secrets.token_hex(12)
            with self.assertRaises(AdmissionIPCRejected):
                serve_signed_core_once_ci(
                    name, client_sid=self.sid,
                    pinned_owner_public_raw=self.public,
                    workspace=self.fi.workspace, core=self.fi.core)
        finally:
            os.environ["NF_CORE_ADMISSION_PIPE_CI_ONLY"] = existing
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        print("NF_IPC_OUTSIDE_ISOLATED_CI_GATE=DENIED")


if __name__ == "__main__":
    unittest.main()
