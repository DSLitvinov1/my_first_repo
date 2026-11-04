"""Windows SCM service (isolated CI candidate, not a production release).

Actual Windows Service Control Manager registers LocalService account. Separate
worker SID is pinned in an administrator-installed root-owned config; receiver
does NOT accept config/path/key from messages and cannot mint owner permits.
Only a strictly fixed inert file name can be written by the service.

This is NOT live authority: no external antirollback witness, production
PostgreSQL fencing, protected TPM signing or independent REVIEW yet.
Intended ONLY for an isolated, disposable Windows GitHub runner configured
by a separate privileged ephemeral test installer.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import threading

import win32event
import win32service
import win32serviceutil
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey,Ed25519PrivateKey
from windows_named_pipe_pilot_receiver import serve_one_pilot
# In the source tree the guard belongs to one_pc_candidate. During the
# disposable SCM install the operator copies it into the service's own bin.
import sys
_candidate=Path(__file__).resolve().parents[1]/"one_pc_candidate"
if _candidate.is_dir() and str(_candidate) not in sys.path:
    sys.path.insert(0,str(_candidate))
from scm_recipient_core_claim_guard import assert_recipient_core_claim

SERVICE_NAME = "NeurofactorySandboxReceiverCI"
CI_ROOT = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "NeurofactoryCIReceiver"
CI_CONFIG = CI_ROOT / "receiver-config.json"
CI_PIPE = r"\\.\pipe\neurofactory-pilot-101010101010101010101010"
CONFIG_FIELDS = {"schema", "worker_sid", "owner_public_raw_base64",
                 "host_receipt_private_raw_base64", "core_state_path",
                 "core_spec_sha256", "core_payload_sha256", "core_claim_owner"}
SID_PATTERN = re.compile(r"S-1-(?:\d+-){2,14}\d+\Z")
SERVICE_MODE_ONLY_CI = True  # Not a production daemon.


def load_ci_config():
    """Config must be provisioned by the test operator, never CORE/worker."""
    if os.name != "nt" or not CI_ROOT.is_dir() or CI_ROOT.is_symlink():
        raise ValueError("Windows service root unavailable")
    config = json.loads(CI_CONFIG.read_text(encoding="ascii"))
    remote_required=(type(config) is dict and
                     config.get("schema")=="neurofactory.windows.ci_service.remote_required.v1")
    if type(config) is not dict or set(config) != CONFIG_FIELDS or \
            config["schema"] not in ("neurofactory.windows.ci_service.v1",
                                     "neurofactory.windows.ci_service.remote_required.v1") or \
            type(config["worker_sid"]) is not str or \
            not SID_PATTERN.fullmatch(config["worker_sid"]) or \
            type(config["owner_public_raw_base64"]) is not str or \
            len(config["owner_public_raw_base64"]) != 44 or \
            type(config["host_receipt_private_raw_base64"]) is not str or \
            len(config["host_receipt_private_raw_base64"]) != 44 or \
            type(config["core_state_path"]) is not str or \
            type(config["core_spec_sha256"]) is not str or \
            not re.fullmatch(r"[a-f0-9]{64}",config["core_spec_sha256"]) or \
            type(config["core_payload_sha256"]) is not str or \
            not re.fullmatch(r"[a-f0-9]{64}",config["core_payload_sha256"]) or \
            type(config["core_claim_owner"]) is not str or \
            not re.fullmatch(r"[A-Za-z0-9_-]{1,50}",config["core_claim_owner"]):
        raise ValueError("invalid externally pinned CI owner or worker")
    raw=base64.b64decode(config["owner_public_raw_base64"],validate=True)
    if len(raw)!=32:
        raise ValueError("invalid pinned Ed25519 public bytes")
    # CI ONLY: installer provisions a short-lived HOST signing key in an
    # NT SERVICE\\restricted SID-only protected config. This is NOT TPM custody.
    host_raw=base64.b64decode(config["host_receipt_private_raw_base64"],validate=True)
    if len(host_raw)!=32:
        raise ValueError("Invalid ephemeral HOST signing key")
    state=Path(config["core_state_path"])
    if (not state.is_absolute() or state.is_symlink()
            or state.name != "state"
            or not (state / "queue.sqlite3").is_file()):
        raise ValueError("Missing separately operator-pinned CORE persistent state")
    return (config["worker_sid"],Ed25519PublicKey.from_public_bytes(raw),
            Ed25519PrivateKey.from_private_bytes(host_raw),
            state,config["core_spec_sha256"],
            config["core_payload_sha256"],config["core_claim_owner"],
            remote_required)


class NeurofactorySandboxReceiverCI(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "Neurofactory CI sandbox named-pipe receiver"
    _svc_description_ = "DISPOSABLE TEST ONLY — blocks production jobs, ONE inert file"

    def __init__(self,args):
        super().__init__(args)
        self.stop = win32event.CreateEvent(None,0,0,None)
        self.is_stopping=threading.Event()
        self.handler=None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.is_stopping.set()
        win32event.SetEvent(self.stop)

    def SvcDoRun(self):
        (sid,owner_public,host_signer,state,spec_sha,
         payload_sha,claim_owner,remote_required)=load_ci_config()
        # Only an operator-installed exact service config opts into this mode.
        # In that mode missing sealed witness policy is fatal during startup;
        # never fall back to CORE-only file execution.
        witness_guard=None
        if remote_required:
            import win32security
            from scm_witness_service_policy import load_scm_witness_guard
            live_service_sid=win32security.ConvertSidToStringSid(
                win32security.LookupAccountName(
                    None,"NT SERVICE\\"+SERVICE_NAME)[0])
            if not live_service_sid.startswith("S-1-5-80-"):
                raise RuntimeError("actual SCM service identity invalid")
            witness_guard=load_scm_witness_guard(
                operator_service_root=CI_ROOT, core_state=state,
                expected_spec_sha256=spec_sha,
                expected_payload_sha256=payload_sha,
                expected_owner=claim_owner,
                actual_worker_sid=sid,
                actual_service_sid=live_service_sid)
        root=CI_ROOT / "protected_output"
        if not root.is_dir() or root.is_symlink():
            raise RuntimeError("operator-provisioned protected output missing")
        # Worker runs with a different OS account. Service's LocalService
        # identity and ACLs are imposed via SCM + operator install script.
        self.handler=threading.Thread(
            target=self._serve_forever,args=(sid,owner_public,root,host_signer,state,spec_sha,payload_sha,claim_owner,witness_guard,remote_required),daemon=True)
        self.handler.start()
        # Graceful stop never waits on a pending adversarial pipe client.
        win32event.WaitForSingleObject(self.stop,win32event.INFINITE)

    def _ci_crash_after_unknown(self):
        # Operator-only disposable CI failpoint. Worker SID cannot write the
        # protected parent directory; no remote/client-controlled flag.
        marker=CI_ROOT / "operator_ci_crash_after_unknown"
        if marker.is_file():
            os._exit(87)

    def _serve_forever(self,sid,owner_public,root,host_signer,
                       state,spec_sha,payload_sha,claim_owner,
                       witness_guard,remote_required):
        def core_guard(signed_body):
            return assert_recipient_core_claim(
                core_state=state, body=signed_body,
                expected_spec_sha256=spec_sha,
                expected_payload_sha256=payload_sha,
                expected_owner=claim_owner)
        while not self.is_stopping.is_set():
            try:
                serve_one_pilot(CI_PIPE,root,owner_public,sid,
                                ci_after_unknown_hook=self._ci_crash_after_unknown,
                                host_receipt_signer=host_signer,
                                recipient_core_guard=core_guard,
                                recipient_signed_witness_guard=witness_guard,
                                require_signed_external_witness=remote_required)
            except Exception:
                # Fail closed; no exception must promote to a new write mode.
                if self.is_stopping.is_set():
                    break
                # Do not use auto replay after an UNKNOWN file effect.
                # Stop accepting further requests rather than spin.
                self.is_stopping.set()
                win32event.SetEvent(self.stop)
                break


if __name__=="__main__":
    import sys
    if sys.argv[1:] == ["--scm"]:
        import servicemanager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NeurofactorySandboxReceiverCI)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        raise SystemExit("CI SCM only, no user-triggered installation or run")
