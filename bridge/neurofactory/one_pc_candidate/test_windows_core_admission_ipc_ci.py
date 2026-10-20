"""Addressed Windows kernel SID named-pipe delivery, genuine signed CORE SQLite.

Only ephemeral GitHub-hosted Windows. No owner computer, deployment or Qwen
repeat. The pipeline source modules from PR48 remain unmodified.
"""
from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import json
import subprocess
import shutil
import stat
import os
from pathlib import Path
import secrets
import sys
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_windows_owner_controller_candidate as fixture_module
from windows_owner_controller_candidate import protect_acl, PRIVATE_FILE
from windows_core_admission_ipc_ci import (
    serve_signed_core_once_ci, send_signed_permit_once_ci, PREFIX,
    AdmissionIPCRejected, _message,
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
        self.operator = fixture_module.OwnerControllerWindowsCI(
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

    def protect_disposable_signed_input(self, permit):
        """Same-owner writable + other-user read-only NTFS; no broad grant.

        Existing TRUSTED HOST SCM tests use a separate ProgramData CI folder.
        This folder is NOT the owner key store, nor a CORE state path.
        """
        import ntsecuritycon
        root = Path(os.environ["PROGRAMDATA"]) / (
            "nf-core-admission-ci-" + secrets.token_hex(10))
        self.assertFalse(root.exists())
        root.mkdir()
        file = root / "signed-owner-permit.json"
        # The child proves its own actual primary-token SID and real
        # NTFS read-denial of three protected operator/CORE resources.
        # These CI-only probe paths do NOT enter the Named Pipe message.
        document = {
            "schema": "nf.onepc.ci.signed_input_and_acl_probes.v1",
            "expected_client_sid": self.sid,
            "permit": permit,
            "denied_read_paths": [
                str(self.operator.root / PRIVATE_FILE),
                str(self.fi.workspace.database),
                str(self.fi.core.state / "queue.sqlite3"),
            ],
        }
        data = json.dumps(
            document, sort_keys=True, ensure_ascii=False,
            separators=(",", ":")).encode("utf-8")
        self.assertTrue(500 <= len(data) <= 6500)
        with file.open("xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())

        owner = win32security.ConvertStringSidToSid(
            fixture_module.operator_sid())
        client = win32security.ConvertStringSidToSid(self.sid)
        for path, is_folder in ((root, True), (file, False)):
            acl = win32security.ACL()
            flags = (win32con.CONTAINER_INHERIT_ACE |
                     win32con.OBJECT_INHERIT_ACE) if is_folder else 0
            acl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION, flags, win32con.GENERIC_ALL,
                owner)
            acl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION, flags,
                ntsecuritycon.FILE_GENERIC_READ |
                ntsecuritycon.FILE_GENERIC_EXECUTE if is_folder else
                ntsecuritycon.FILE_GENERIC_READ,
                client)
            win32security.SetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION |
                win32security.DACL_SECURITY_INFORMATION |
                win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                owner, None, acl, None)
            desc = win32security.GetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION |
                win32security.DACL_SECURITY_INFORMATION)
            dacl = desc.GetSecurityDescriptorDacl()
            allowed = {fixture_module.operator_sid(), self.sid}
            observed = {
                win32security.ConvertSidToStringSid(dacl.GetAce(i)[2])
                for i in range(dacl.GetAceCount())
            }
            self.assertEqual(observed, allowed,
                             "Foreign SID found in staged permit ACL")
            self.assertFalse(path.is_symlink())
            self.assertFalse(
                path.lstat().st_file_attributes &
                stat.FILE_ATTRIBUTE_REPARSE_POINT)
        self.assertEqual(file.read_bytes(), data)
        return root, file

    def test_separate_windows_user_process_delivers_genuine_signed_permit(self):
        """Use Windows CreateProcessWithLogonW, not same-process impersonation.

        No delegated password, bearer token, owner key or CORE path arrives
        in child args/env. Only a pre-signed permit and pinned pipe name.
        """
        permit = self.operator.sign()
        shared, signed_file = self.protect_disposable_signed_input(permit)
        name = PREFIX + secrets.token_hex(12)
        listener, records, errors = self.serve(name)
        child = Path(__file__).resolve().with_name(
            "windows_core_admission_client_process_ci.py")

        class Startup(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),
            ]

        class ProcessInfo(ctypes.Structure):
            _fields_ = [
                ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
            ]

        # Reuse exact Windows 2025 SCM proven launch contract from
        # trusted_host/test_windows_scm_two_user_recovery.py:
        # CreateProcessWithLogonW with "." domain, NULL environment,
        # CREATE_NO_WINDOW and existing source directory.
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline([
            sys.executable, "-B", str(child), name, str(signed_file),
        ]))
        self.assertLess(len(command.value), 1024,
                        "Win32 CreateProcessWithLogonW command limit")
        startup = Startup()
        startup.cb = ctypes.sizeof(startup)
        pi = ProcessInfo()
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        creator = adv.CreateProcessWithLogonW
        creator.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR,
            wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.POINTER(Startup), ctypes.POINTER(ProcessInfo),
        ]
        creator.restype = wintypes.BOOL
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.GetExitCodeProcess.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        try:
            created = creator(
                self.operator.ci_user_name, ".", self.operator.ci_user_password,
                0, sys.executable, command,
                0x08000000, None, str(child.parent),
                ctypes.byref(startup), ctypes.byref(pi))
            self.assertTrue(created,
                            "Existing SCM-proven CreateProcessWithLogonW refused "
                            "real separate UI account, Win32 error=" +
                            str(ctypes.get_last_error()))
            try:
                code = kernel.WaitForSingleObject(pi.hProcess, 20000)
                if code != 0:
                    kernel.TerminateProcess(pi.hProcess, 3)
                    self.fail("Unprivileged Windows child process hung")
                exit_code = wintypes.DWORD(999)
                self.assertTrue(kernel.GetExitCodeProcess(
                    pi.hProcess, ctypes.byref(exit_code)))
                self.assertEqual(exit_code.value, 0,
                                 "Unprivileged separate process denied IPC")
            finally:
                kernel.CloseHandle(pi.hThread)
                kernel.CloseHandle(pi.hProcess)
        finally:
            listener.join(timeout=8)
            shutil.rmtree(shared)
        self.assertFalse(listener.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "OBSERVED_QUEUED_TEST_ONLY")
        self.assertEqual(self.fi.core.snapshot()["state"], "QUEUED")
        self.assertEqual(self.fi.workspace.list_tasks()[0]["state"],
                         "DRAFT_PENDING_OWNER_AUTH")
        # SAME existing read-only UI projection sees the persisted CORE state,
        # including after this distinct client process has already exited.
        from core_readonly_observer import observe_core
        shown = observe_core(self.fi.core.state)
        self.assertEqual(shown["reported_state"], "QUEUED")
        self.assertEqual(shown["task"]["task_id"], permit["spec"]["task_id"])
        self.assertEqual(shown["task"]["project_id"], permit["spec"]["project_id"])
        self.assertFalse(shown.get("execution_allowed", False))
        print("NF_IPC_EXISTING_UI_OBSERVER_SEES_DURABLE_QUEUED=PASS_READ_ONLY")
        # Exercise the real existing LOCAL UI HTTP route, rather than
        # pretending a read-only observer object is a browser response.
        import socket
        import http.client
        from http.server import HTTPServer
        from local_workspace import handler
        with socket.socket() as probe_port:
            probe_port.bind(("127.0.0.1", 0))
            port = probe_port.getsockname()[1]
        ui_dir = Path(__file__).resolve().parents[1] / "control_ui"
        server = HTTPServer(
            ("127.0.0.1", port),
            handler(self.fi.workspace, ui_dir, secrets.token_hex(16),
                    port, core_state_dir=self.fi.core.state))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
            try:
                connection.request("GET", "/api/core/status")
                result = connection.getresponse()
                self.assertEqual(result.status, 200)
                observed_ui = json.loads(result.read().decode("utf-8"))
            finally:
                connection.close()
            self.assertEqual(observed_ui["reported_state"], "QUEUED")
            self.assertEqual(observed_ui["task"]["task_id"],
                             permit["spec"]["task_id"])
            self.assertEqual(observed_ui["task"]["project_id"],
                             permit["spec"]["project_id"])
            self.assertFalse(observed_ui["execution_allowed"])
            self.assertFalse(observed_ui["queue_mutation_allowed"])
            self.assertFalse(observed_ui["independently_verified"])
            self.assertEqual(self.fi.workspace.list_tasks()[0]["state"],
                             "DRAFT_PENDING_OWNER_AUTH")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        print("NF_IPC_REAL_UI_HTTP_CORE_STATUS=QUEUED_READ_ONLY_AFTER_CHILD_EXIT")

        print("NF_IPC_REAL_SEPARATE_WINDOWS_PROCESS_TO_CORE=PASS_NO_OWNER_KEY")

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

    def test_true_signature_cannot_override_independent_wrong_owner_key_pin(self):
        genuine = self.operator.sign()
        wrong_pin = b"\x42" * 32
        denied = self.one_exchange(genuine, pub=wrong_pin)
        self.assertEqual(denied["status"], "DENIED_OR_UNKNOWN_NO_AUTO_RETRY")
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        print("NF_IPC_WRONG_INDEPENDENT_OWNER_KEY_PIN=DENIED")

    def test_wire_contract_rejects_duplicate_keys_and_extra_authorities(self):
        with self.assertRaises(AdmissionIPCRejected):
            _message(b'{"schema":"nf.onepc.ipc.owner_admission_delivery_ci.v1",'
                     b'"schema":"nf.onepc.ipc.owner_admission_delivery_ci.v1",'
                     b'"permit":{}}')
        with self.assertRaises(AdmissionIPCRejected):
            _message(b'{"schema":"nf.onepc.ipc.owner_admission_delivery_ci.v1",'
                     b'"permit":{},"owner_key":"attacker_key"}')
        with self.assertRaises(AdmissionIPCRejected):
            _message(b"x" * 9000)
        self.assertEqual(self.fi.core.snapshot()["state"], "EMPTY")
        print("NF_IPC_DUPLICATE_KEY_EXTRA_AUTHORITY_AND_OVERSIZE=DENIED")

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
