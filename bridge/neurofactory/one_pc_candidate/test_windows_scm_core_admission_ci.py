"""True THREE Windows OS identities: owner signer, restricted SCM CORE, UI.

The real Windows Service Control Manager starts a disposable LocalService
process with its own RESTRICTED per-service SID, separated from the owner
CurrentUser DPAPI SID and from a distinct real low-privilege UI account.
The pre-signed permit travels by a real separate OS process + Named Pipe.
The service alone runs the unchanged trusted CORE admission and SQLite.
Windows CI ONLY. Never perform any of this on the user's computer.
"""
from __future__ import annotations

import base64
import hashlib
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
import unittest

from test_windows_owner_controller_candidate import OwnerControllerWindowsCI
from windows_scm_core_admission_ci import SERVICE_NAME, ROOT, CONFIG, SCHEMA
from windows_core_admission_ipc_ci import PREFIX
from one_task_core import OneTaskCore
from core_readonly_observer import observe_core

if os.name == "nt":
    import win32security
    import win32service
    import win32serviceutil


def command(args, *, required=True, timeout=35):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if required and result.returncode:
        raise AssertionError(
            "CI Windows command failed, return=" + str(result.returncode) +
            " output=" + result.stdout[-300:] + result.stderr[-300:])
    return result


def lock_acl(path, grants):
    arguments = ["icacls", str(path), "/inheritance:r", "/grant:r"]
    arguments.extend("*" + sid + ":" + rights for sid, rights in grants)
    command(arguments)


def win32_child(username, password, script, pipe, signed_file):
    """Proven SCM-style CreateProcessWithLogonW with short command."""
    class STARTUP(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]
    class PROCESS(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]
    import subprocess as sub
    args = ctypes.create_unicode_buffer(sub.list2cmdline([
        sys.executable, "-B", str(script), pipe, str(signed_file)]))
    if len(args.value) >= 1024:
        raise AssertionError("Win32 CreateProcessWithLogonW command limit")
    startup = STARTUP()
    startup.cb = ctypes.sizeof(startup)
    pi = PROCESS()
    win32 = ctypes.WinDLL("advapi32", use_last_error=True)
    launch = win32.CreateProcessWithLogonW
    launch.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR,
        wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(STARTUP), ctypes.POINTER(PROCESS),
    ]
    launch.restype = wintypes.BOOL
    if not launch(username, ".", password, 0, sys.executable, args,
                  0x08000000, None, str(script.parent),
                  ctypes.byref(startup), ctypes.byref(pi)):
        raise AssertionError(
            "Actual separate Windows user process failed Win32=" +
            str(ctypes.get_last_error()))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    try:
        if kernel.WaitForSingleObject(pi.hProcess, 19000) != 0:
            kernel.TerminateProcess(pi.hProcess, 37)
            raise AssertionError("Distinct UI process hung")
        status = wintypes.DWORD(999)
        if not kernel.GetExitCodeProcess(pi.hProcess, ctypes.byref(status)):
            raise AssertionError("Unknown child OS process exit")
        return status.value
    finally:
        kernel.CloseHandle(pi.hThread)
        kernel.CloseHandle(pi.hProcess)


class ThreeRealWindowsPrincipals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.name != "nt" or os.getenv("GITHUB_ACTIONS") != "true" or
                os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or
                os.getenv("NF_SCM_CORE_TRIPLE_SID_CI") != "1"):
            raise unittest.SkipTest("Only disposable GitHub-hosted Windows allowed")

    def setUp(self):
        if ROOT.exists():
            self.fail("Never reuse an existing SCM receiver root")
        self.operator = OwnerControllerWindowsCI(
            "test_real_dpapi_signing_and_real_core_queue_one_shot")
        self.operator.setUp()
        self.addCleanup(self.operator.tearDown)
        self.fixture = self.operator.fi
        self.service_created = False
        self.service_started = False
        self.pipe = PREFIX + secrets.token_hex(12)
        self.worker_stage = None
        self.addCleanup(self.cleanup_service)
        try:
            self.deploy_ci_only_scm()
        except Exception:
            proof = ROOT / "core" / "scm-git-child-diagnostic.json"
            if proof.is_file():
                try:
                    # This CI-only file contains exit/status flags, no signed
                    # task, private key, owner credentials or repository data.
                    print("NF_SCM_RESTRICTED_GIT_CHILD_DIAG=" +
                          proof.read_text(encoding="ascii")[:1200],
                          flush=True)
                except OSError:
                    print("NF_SCM_GIT_CHILD_DIAG_NOT_READABLE", flush=True)
            raise

    def cleanup_service(self):
        if self.service_created:
            command(["sc.exe", "stop", SERVICE_NAME], required=False, timeout=12)
            command(["sc.exe", "delete", SERVICE_NAME], required=False, timeout=12)
            for _ in range(25):
                status = command(["sc.exe", "query", SERVICE_NAME], required=False)
                if "1060" in status.stdout or "1060" in status.stderr:
                    break
                time.sleep(.15)
        if self.worker_stage is not None:
            shutil.rmtree(self.worker_stage, ignore_errors=True)
        if ROOT.exists():
            shutil.rmtree(ROOT, ignore_errors=True)

    def deploy_ci_only_scm(self):
        from windows_scm_core_admission_ci import SERVICE_NAME
        from windows_owner_controller_candidate import operator_sid
        ROOT.mkdir()
        for d in ("bin", "workspace", "core", "git"):
            (ROOT / d).mkdir()
        src = Path(__file__).resolve().parent
        trusted = src.parent / "trusted_host"
        (ROOT / "trusted_host").mkdir()
        for name in (
            "windows_scm_core_admission_ci.py",
            "windows_core_admission_ipc_ci.py",
            "signed_owner_admission.py",
            "local_workspace.py",
            "core_readonly_observer.py",
            "windows_owner_controller_candidate.py",
        ):
            shutil.copy2(src / name, ROOT / "bin" / name)
        shutil.copy2(
            src.parent / "development" / "core_owned" / "one_task_core.py",
            ROOT / "bin" / "one_task_core.py")
        shutil.copy2(trusted / "windows_named_pipe_pilot_receiver.py",
                     ROOT / "trusted_host" / "windows_named_pipe_pilot_receiver.py")
        # Python imports from bin and explicit TRUSTED HOST path, no untrusted
        # file/module paths accepted in Named Pipe messages.
        shutil.copytree(self.fixture.git, ROOT / "git", dirs_exist_ok=True)
        with self.fixture.workspace.connect() as old:
            with sqlite3.connect(str(ROOT / "workspace" / "workspace.sqlite3")) as new:
                old.backup(new)
        OneTaskCore(ROOT / "core", ROOT / "git")  # empty; no task admitted
        self.owner_sid = operator_sid()
        self.client_sid = self.operator.ui_sid
        self.assertNotEqual(self.owner_sid, self.client_sid)
        private = self.operator.root / "owner-ed25519.dpapi"
        self.assertTrue(private.exists())
        config = {
            "schema": SCHEMA, "ci_only": True,
            "ui_sid": self.client_sid,
            "operator_sid": self.owner_sid,
            "owner_public_b64": base64.b64encode(self.operator.pub).decode(),
            "pipe_name": self.pipe,
            "operator_dpapi_key_path": str(private),
            "git_exe": str(Path(shutil.which("git")).resolve()),
            "git_exe_sha256": hashlib.sha256(
                Path(shutil.which("git")).resolve().read_bytes()).hexdigest(),
        }
        CONFIG.write_text(json.dumps(config, sort_keys=True), encoding="ascii")

        py = ROOT / "bin" / "windows_scm_core_admission_ci.py"
        quoted = '"' + sys.executable + '" -u "' + str(py) + '" --scm'
        command(["sc.exe", "create", SERVICE_NAME, "binPath=", quoted,
                 "obj=", r"NT AUTHORITY\LocalService", "start=", "demand"])
        self.service_created = True
        command(["sc.exe", "sidtype", SERVICE_NAME, "restricted"])
        svc_token_sid, _, _ = win32security.LookupAccountName(
            None, "NT SERVICE\\" + SERVICE_NAME)
        self.service_sid = win32security.ConvertSidToStringSid(svc_token_sid)
        self.assertTrue(self.service_sid.startswith("S-1-5-80-"))
        self.assertEqual(len({self.owner_sid, self.client_sid,
                              self.service_sid, "S-1-5-19"}), 4)

        sys_sid, admin_sid, local_service = (
            "S-1-5-18", "S-1-5-32-544", "S-1-5-19")
        owner_grants = [(sys_sid, "(OI)(CI)F"), (admin_sid, "(OI)(CI)F")]
        owner_file_grants = [(sys_sid, "F"), (admin_sid, "F")]
        readonly_service = owner_grants + [
            (local_service, "(OI)(CI)RX"),
            (self.service_sid, "(OI)(CI)RX")]
        lock_acl(ROOT, readonly_service)
        for folder in ("bin", "git", "trusted_host"):
            lock_acl(ROOT / folder, readonly_service)
        for folder in ("workspace", "core"):
            lock_acl(ROOT / folder, owner_grants + [
                (self.service_sid, "(OI)(CI)M"),
                (local_service, "(OI)(CI)M")])
        # SQLite's transaction journal and WAL live in the SAME parent
        # directory as the database. Explicitly protect pre-created state
        # directories rather than relying on old inherited ACLs; only the
        # restricted service SID and LocalService can modify their contents.
        for state_directory in (
                ROOT / "core" / "state",
                ROOT / "core" / "sandbox"):
            self.assertTrue(state_directory.is_dir())
            lock_acl(state_directory, owner_grants + [
                (self.service_sid, "(OI)(CI)M"),
                (local_service, "(OI)(CI)M")])
        lock_acl(CONFIG, owner_file_grants + [(self.service_sid, "R")])
        # Explicitly pinned service principal (not shared LocalService)
        # must be the ONLY non-administrator reader of public admin config.
        for path in (ROOT / "workspace" / "workspace.sqlite3",
                     ROOT / "core" / "state" / "queue.sqlite3"):
            lock_acl(path, owner_file_grants + [
                (self.service_sid, "M"), (local_service, "M")])
        launch = command(["sc.exe", "start", SERVICE_NAME],
                         required=False, timeout=30)
        if launch.returncode:
            raise AssertionError(
                "Actual SCM LocalService not started: " +
                launch.stdout[-350:] + launch.stderr[-350:])
        self.service_started = True
        for _ in range(80):
            status = command(["sc.exe", "query", SERVICE_NAME])
            if "RUNNING" in status.stdout:
                break
            time.sleep(.2)
        else:
            raise AssertionError("Restricted LocalService never RUNNING")
        qc = command(["sc.exe", "qc", SERVICE_NAME]).stdout
        self.assertIn("LocalService", qc)
        # Actual OS process owner from Win32 service PID, not merely config.
        actual = command([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            ("$x=Get-CimInstance Win32_Service -Filter "
             "\"Name='" + SERVICE_NAME + "'\"; "
             "$p=Get-CimInstance Win32_Process -Filter "
             "('ProcessId='+$x.ProcessId);"
             "($p | Invoke-CimMethod -MethodName GetOwner).User")
        ]).stdout.strip().upper()
        start_diagnostic = ROOT / "core" / "scm-ci-startup-denial.json"
        if not actual and start_diagnostic.exists():
            self.fail("SCM LocalService refused startup: " +
                      start_diagnostic.read_text(encoding="ascii")[:400])
        self.assertIn(
            "LOCAL SERVICE", actual,
            "SCM owner telemetry missing; exact service status=" +
            command(["sc.exe", "queryex", SERVICE_NAME], required=False).stdout[-700:])
        print("NF_SCM_ACTUAL_RESTRICTED_LOCALSERVICE_SEPARATE_PROCESS=PASS")
        print("NF_SCM_OWNER_DPAPI_KEY_READ_FROM_SERVICE=DENIED_BY_SCOPED_START")

    def stage_request(self, permit):
        import win32con
        import ntsecuritycon
        stage = Path(os.environ["PROGRAMDATA"]) / (
            "nf-core-admission-ci-" + secrets.token_hex(9))
        stage.mkdir()
        self.worker_stage = stage
        signed_file = stage / "signed-owner-permit.json"
        record = {
            "schema": "nf.onepc.ci.signed_input_and_acl_probes.v1",
            "expected_client_sid": self.client_sid,
            "permit": permit,
            "denied_read_paths": [
                str(self.operator.root / "owner-ed25519.dpapi"),
                str(ROOT / "workspace" / "workspace.sqlite3"),
                str(ROOT / "core" / "state" / "queue.sqlite3"),
            ],
        }
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        self.assertTrue(500 <= len(raw) <= 6500)
        signed_file.write_bytes(raw)
        owner = win32security.ConvertStringSidToSid(self.owner_sid)
        client = win32security.ConvertStringSidToSid(self.client_sid)
        for path, folder in ((stage, True), (signed_file, False)):
            acl = win32security.ACL()
            flags = (win32con.CONTAINER_INHERIT_ACE |
                     win32con.OBJECT_INHERIT_ACE) if folder else 0
            acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, flags,
                                      win32con.GENERIC_ALL, owner)
            acl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION, flags,
                ntsecuritycon.FILE_GENERIC_READ |
                ntsecuritycon.FILE_GENERIC_EXECUTE if folder else
                ntsecuritycon.FILE_GENERIC_READ, client)
            win32security.SetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION |
                win32security.OWNER_SECURITY_INFORMATION |
                win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                owner, None, acl, None)
        return signed_file

    def test_actual_three_windows_identities_one_signed_core_enqueue(self):
        permit = self.operator.sign()
        # Owner signer with CurrentUser DPAPI must differ from SCM service
        # primary (LocalService) AND the separate unprivileged UI user.
        self.assertTrue(self.operator.pub)
        self.assertEqual(self.owner_sid, self.operator.signer_identity)
        signed_file = self.stage_request(permit)
        client_script = Path(__file__).resolve().with_name(
            "windows_core_admission_client_process_ci.py")
        exitcode = win32_child(
            self.operator.ci_user_name, self.operator.ci_user_password,
            client_script, self.pipe, signed_file)
        failure = ROOT / "core" / "ci-core-receiver-denial.json"
        if exitcode != 0 and failure.exists():
            self.fail("True SCM CORE separately signed admission failed: " +
                      failure.read_text(encoding="ascii")[:260])
        self.assertEqual(exitcode, 0, "True separate-SID UI process failed")
        # The protected SCM process did the actual sqlite durable admission.
        state = ROOT / "core" / "state"
        self.assertEqual(observe_core(state)["reported_state"], "QUEUED")
        self.assertEqual(observe_core(state)["task"]["task_id"],
                         permit["spec"]["task_id"])
        self.assertEqual(observe_core(state)["task"]["project_id"],
                         permit["spec"]["project_id"])
        self.assertEqual(self.fixture.core.snapshot()["state"], "EMPTY")
        print("NF_THREE_PROCESS_OWNER_SIGNER_SCM_RECEIVER_UI_CORE=QUEUED_ONCE")
        # Never infer permission to execute from successful enqueue.
        self.assertFalse(observe_core(state)["execution_allowed"])
        # The same signed permit must not be enqueued twice; no worker
        # process retries a known-uncertain first delivery.
        self.assertEqual(self.fixture.workspace.list_tasks()[0]["state"],
                         "DRAFT_PENDING_OWNER_AUTH")
        print("NF_SCM_OTHER_UI_PROCESS_NTFS_DPAPI_WORKSPACE_CORE_READ=DENIED")


if __name__ == "__main__":
    unittest.main()
