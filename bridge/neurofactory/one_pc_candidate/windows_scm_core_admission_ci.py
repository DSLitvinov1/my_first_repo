"""Disposable SCM LocalService CORE admission receiver, no owner private key.

Creates no new queue or UI. It REUSES the actual OneTaskCore and
signed_owner_admission.admit_signed_draft, plus TRUSTED HOST _peer_matches
for kernel Windows SID client verification. Only an administrator-provisioned
CI config fixes the single source Git tree, protected owner public pin, CORE
SQLite, workspace SQLite and a distinct REAL UI user SID.

SCM installed ONLY by the separate ephemeral hosted Windows CI orchestrator,
NEVER copied to the user's local installer. Does NOT execute, claim, run a
model, write project files, sign permissions, publish PRs or enable HANDOFF.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading

import pywintypes
import win32event
import win32file
import win32pipe
import win32security
import win32service
import win32serviceutil

from signed_owner_admission import _canon, admit_signed_draft
from local_workspace import WorkspaceStore
from one_task_core import OneTaskCore

# Same rooted TRUSTED HOST code, pinned/copied by the CI-only orchestrator.
_TRUSTED_HOST_PINNED = Path(__file__).resolve().parents[1] / "trusted_host"
if str(_TRUSTED_HOST_PINNED) not in sys.path:
    sys.path.insert(0, str(_TRUSTED_HOST_PINNED))
from windows_named_pipe_pilot_receiver import _peer_matches
from windows_core_admission_ipc_ci import PREFIX, MAX_REQUEST, MAX_REPLY, _message

SERVICE_NAME = "NeurofactoryCoreAdmissionCI"
SCHEMA = "nf.onepc.scm.core_admission_disposable_config.v1"
ROOT = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "NFCoreAdmissionSCMCI"
CONFIG = ROOT / "core-receiver-config.json"
ALLOWED_FIELDS = {
    "schema", "ci_only", "ui_sid", "operator_sid", "owner_public_b64",
    "pipe_name", "operator_dpapi_key_path",
}
SID_PATTERN = re.compile(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+\Z")
SERVICE_SID = "NT SERVICE\\" + SERVICE_NAME


def _fail(message):
    raise RuntimeError("SCM CORE admission fail-closed: " + message)


def _load_admin_config():
    if os.name != "nt" or not ROOT.is_dir() or ROOT.is_symlink():
        _fail("Non-Windows or missing fixed CI-only service root")
    if not CONFIG.is_file() or CONFIG.is_symlink():
        _fail("Absent separately provisioned service configuration")
    try:
        raw = CONFIG.read_bytes()
        if not 50 < len(raw) < 5000:
            _fail("Admin config size")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    _fail("Duplicate privileged config field")
                result[key] = value
            return result
        cfg = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
        public = base64.b64decode(cfg["owner_public_b64"], validate=True)
    except (UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("Invalid CI admin-provisioned CORE config") from exc
    if (type(cfg) is not dict or set(cfg) != ALLOWED_FIELDS or
            cfg["schema"] != SCHEMA or cfg["ci_only"] is not True or
            type(cfg["ui_sid"]) is not str or
            not SID_PATTERN.fullmatch(cfg["ui_sid"]) or
            type(cfg["operator_sid"]) is not str or
            not SID_PATTERN.fullmatch(cfg["operator_sid"]) or
            cfg["ui_sid"] == cfg["operator_sid"] or
            type(cfg["pipe_name"]) is not str or
            not cfg["pipe_name"].startswith(PREFIX) or
            not re.fullmatch(r"[a-f0-9]{24}",
                             cfg["pipe_name"][len(PREFIX):]) or
            len(public) != 32 or
            type(cfg["operator_dpapi_key_path"]) is not str):
        _fail("Invalid operator, worker or public-key trust pin")
    service_sid, domain, kind = win32security.LookupAccountName(None, SERVICE_SID)
    if win32security.ConvertSidToStringSid(service_sid) == cfg["operator_sid"]:
        _fail("Service SID cannot also be owner signer")
    if win32security.ConvertSidToStringSid(service_sid) == cfg["ui_sid"]:
        _fail("Service SID cannot also be unprivileged UI user")

    # Prove this ACTUAL SCM process does not have protected DPAPI file READ
    # capability. A merely absent file is NOT sufficient evidence.
    operator_private = Path(cfg["operator_dpapi_key_path"])
    if (not operator_private.is_absolute() or
            operator_private.name != "owner-ed25519.dpapi"):
        _fail("Unexpected private signing key path in test provenance")
    try:
        operator_private.read_bytes()
    except PermissionError:
        pass
    except Exception as exc:
        raise RuntimeError("SCM signer key inaccessible, but not ACL-denied") from exc
    else:
        _fail("SCM receiver can read owner encrypted signing key")
    return cfg, public, service_sid


def _pipe_acl(ui_sid, service_sid):
    import ntsecuritycon
    acl = win32security.ACL()
    mask = ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE
    # Actual Service SID also present in restricted and enabled token group;
    # no EVERYONE / ANONYMOUS / administrators or cross-account owner grants.
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, mask, service_sid)
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, mask,
                            win32security.ConvertStringSidToSid(ui_sid))
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1, acl, 0)
    sa = pywintypes.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = sd
    return sa


def _one_request(pipe_name, ui_sid, service_sid, public, store, core):
    handle = None
    try:
        handle = win32pipe.CreateNamedPipe(
            pipe_name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE |
            win32pipe.PIPE_WAIT | getattr(win32pipe, "PIPE_REJECT_REMOTE_CLIENTS", 0x8),
            1, MAX_REPLY, MAX_REQUEST, 3000, _pipe_acl(ui_sid, service_sid))
        try:
            win32pipe.ConnectNamedPipe(handle, None)
        except pywintypes.error as exc:
            if exc.winerror != 535:
                raise
        result = {
            "schema": "nf.onepc.core_admission_observation_ci.v1",
            "status": "DENIED_OR_UNKNOWN_NO_AUTO_RETRY",
            "queue_claim_allowed": False,
            "host_execution_allowed": False,
            "automatic_retry_allowed": False,
            "independently_verified": False,
            "production_release": False,
        }
        try:
            status, packet = win32file.ReadFile(handle, MAX_REQUEST)
            if status != 0 or not packet:
                _fail("Incomplete or oversized sender bytes")
            # Existing Windows HOST kernel check, BEFORE parsing untrusted
            # JSON or checking the Ed25519 permit.
            if not _peer_matches(handle, ui_sid):
                _fail("Named pipe client is not administrator-pinned UI SID")
            envelope = _message(packet)
            permit = envelope["permit"]
            if len(_canon(permit)) > 6500:
                _fail("Oversized signed permit")
            answer = admit_signed_draft(
                store, core, permit, owner_public_raw=public)
            if (answer["core_reported_state"] != "QUEUED" or
                    answer["queue_claim_allowed"] is not False or
                    answer["host_execution_allowed"] is not False):
                _fail("Unattested CORE admission status")
            result.update({
                "status": "OBSERVED_QUEUED_TEST_ONLY",
                "core_task_id": answer["core_task_id"],
                "signed_permit_sha256": hashlib.sha256(_canon(permit)).hexdigest(),
            })
        except Exception as exc:
            # Temporary CI-only operator-visible diagnostic. Never includes
            # owner key, signed packet, model proposal or filesystem content.
            # No client may write to CORE-owned protected diagnostic folder.
            try:
                diagnosis = {
                    "status": "DENIED_OR_UNKNOWN_NO_AUTO_RETRY",
                    "exception_class": type(exc).__name__,
                    "reason": str(exc)[:180],
                    "production_release": False,
                }
                (ROOT / "core" / "ci-core-receiver-denial.json").write_text(
                    json.dumps(diagnosis, sort_keys=True), encoding="ascii")
            except Exception:
                pass
        win32file.WriteFile(handle, _canon(result))
        win32file.FlushFileBuffers(handle)
    finally:
        if handle is not None:
            try:
                win32pipe.DisconnectNamedPipe(handle)
            except Exception:
                pass
            win32file.CloseHandle(handle)


class NeurofactoryCoreAdmissionCI(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "Neurofactory CI-only protected CORE admission"
    _svc_description_ = "DISPOSABLE LOCAL TEST ONLY — signed queue admission; no execution"

    def __init__(self, args):
        super().__init__(args)
        self.stop = win32event.CreateEvent(None, 0, 0, None)
        self.is_stopping = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.is_stopping.set()
        win32event.SetEvent(self.stop)

    def SvcDoRun(self):
        cfg, public, service_sid = _load_admin_config()
        core_dir = ROOT / "core"
        workspace_dir = ROOT / "workspace"
        git_dir = ROOT / "git"
        if not all(p.is_dir() and not p.is_symlink() for p in
                   (core_dir, workspace_dir, git_dir)):
            _fail("Missing administrator-provisioned protected state")
        store = WorkspaceStore(workspace_dir)
        core = OneTaskCore(core_dir, git_dir)
        def run():
            while not self.is_stopping.is_set():
                try:
                    _one_request(cfg["pipe_name"], cfg["ui_sid"],
                                 service_sid, public, store, core)
                except Exception:
                    # Never turn error into a write/retry/claim path.
                    if self.is_stopping.is_set():
                        break
                    # A pipe startup error is not a permission for model work.
                    import time
                    time.sleep(.2)
        threading.Thread(target=run, daemon=True).start()
        win32event.WaitForSingleObject(self.stop, win32event.INFINITE)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--scm":
        import servicemanager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NeurofactoryCoreAdmissionCI)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        raise SystemExit("CI SCM only. Do not install or run on owner computer.")
