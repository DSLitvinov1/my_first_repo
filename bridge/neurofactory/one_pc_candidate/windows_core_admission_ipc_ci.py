"""Windows one-shot signed permit transport -> existing REAL CORE SQLite (CI ONLY).

Reuses the existing TRUSTED HOST named-pipe peer SID check. A separate
Windows user can DELIVER an already owner-signed permit; the pipe does not
sign, claim a task, start Qwen, grant file writes or authorize HANDOFF.
No browser-facing endpoint, no listener installation, no production service.

The receiver process needs OS permissions to existing WorkspaceStore and CORE
SQLite. The unprivileged sender must NOT receive these permissions. DPAPI
signing stays in the separate offline operator process. The CI receiver is NOT
an independent reviewer or a disk rollback witness; unknown results never
auto-retry. This candidate requires separate deployment security review.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

from signed_owner_admission import admit_signed_draft, AdmissionDenied, _canon
from windows_owner_controller_candidate import (
    operator_sid, require_real_different_ui_account,
)

_TRUSTED_HOST_SOURCE = Path(__file__).resolve().parents[1] / "trusted_host"
if str(_TRUSTED_HOST_SOURCE) not in sys.path:
    sys.path.insert(0, str(_TRUSTED_HOST_SOURCE))
from windows_named_pipe_pilot_receiver import _peer_matches

PREFIX = "\\\\.\\pipe\\nf-core-admission-ci-"
SCHEMA = "nf.onepc.ipc.owner_admission_delivery_ci.v1"
MAX_REQUEST = 8192
MAX_REPLY = 2048


class AdmissionIPCRejected(ValueError):
    """No relay of malformed permits, foreign Windows SIDs or unknown results."""


def reject(reason="Signed one-task admission over IPC denied"):
    raise AdmissionIPCRejected(reason)


def _ci_only():
    if (os.name != "nt" or
            os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("NF_CORE_ADMISSION_PIPE_CI_ONLY") != "1"):
        reject("IPC listener is disabled outside disposable Windows-hosted CI")


def _pipe_name(name):
    if (type(name) is not str or not name.startswith(PREFIX) or
            not re.fullmatch("[a-f0-9]{24}", name[len(PREFIX):])):
        reject("Only exact per-test random local pipe names are allowed")
    return name


def _message(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_REQUEST:
        reject("Signed request is missing or oversized")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                reject("Duplicate signed request JSON field")
            result[key] = value
        return result

    try:
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise AdmissionIPCRejected("Signed request not valid UTF-8/JSON") from exc
    if (type(request) is not dict or set(request) != {"schema", "permit"} or
            request["schema"] != SCHEMA or type(request["permit"]) is not dict):
        reject("No additional trusted payload keys are accepted")
    return request


def _acl_client_and_receiver(client_sid):
    import ntsecuritycon
    import pywintypes
    import win32security
    if require_real_different_ui_account(client_sid) != client_sid:
        reject("Client user SID must be independently pinned")
    acl = win32security.ACL()
    mask = ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE
    receiver = win32security.ConvertStringSidToSid(operator_sid())
    client = win32security.ConvertStringSidToSid(client_sid)
    # Unlike default Windows pipe DACL: no Everyone/Anonymous/network ACE.
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, mask, receiver)
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, mask, client)
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1, acl, 0)
    sa = pywintypes.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = sd
    return sa


def serve_signed_core_once_ci(name, *, client_sid, pinned_owner_public_raw,
                              workspace, core):
    """One message, independently verified and durable CORE enqueue once.

    The client is a *different actual Windows user* with permission to send
    one signed JSON message but NOT to read protected CORE SQLite or signer
    key. Caller pins the public key OUTSIDE any untrusted IPC payload.
    """
    _ci_only()
    _pipe_name(name)
    require_real_different_ui_account(client_sid)
    if type(pinned_owner_public_raw) is not bytes or len(pinned_owner_public_raw) != 32:
        reject("Independently pinned owner public key not configured")
    import pywintypes
    import win32file
    import win32pipe

    handle = None
    try:
        handle = win32pipe.CreateNamedPipe(
            name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE |
            win32pipe.PIPE_WAIT | getattr(win32pipe, "PIPE_REJECT_REMOTE_CLIENTS", 0x8),
            1, MAX_REPLY, MAX_REQUEST, 3000,
            _acl_client_and_receiver(client_sid),
        )
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
            # ReadFile FIRST is required to cache Windows client token for
            # ImpersonateNamedPipeClient; validate token before JSON parse.
            status, packet = win32file.ReadFile(handle, MAX_REQUEST)
            if status != 0 or not packet:
                reject("Incomplete named pipe request")
            if not _peer_matches(handle, client_sid):
                reject("Windows kernel client SID differs from pinned sender")
            request = _message(packet)
            permit = request["permit"]
            raw_envelope = _canon(permit)
            if len(raw_envelope) > 6500:
                reject("Owner permit exceeds signed envelope bounds")
            # Existing PR43 logic re-reads LIVE WorkspaceStore SQLite, checks
            # exact Ed25519 owner signature and current pinned Git preimage,
            # then calls the REAL OneTaskCore.enqueue transaction.
            admitted = admit_signed_draft(
                workspace, core, permit,
                owner_public_raw=pinned_owner_public_raw)
            if (admitted["core_reported_state"] != "QUEUED" or
                    admitted["queue_claim_allowed"] is not False or
                    admitted["host_execution_allowed"] is not False):
                reject("CORE admission did not return a safe one-task snapshot")
            result.update({
                "status": "OBSERVED_QUEUED_TEST_ONLY",
                "core_task_id": admitted["core_task_id"],
                "signed_permit_sha256": hashlib.sha256(raw_envelope).hexdigest(),
            })
        except Exception:
            # In particular, a disk write may have succeeded just before an
            # IPC failure. No implicit retry, re-enqueue or claim.
            pass
        win32file.WriteFile(handle, _canon(result))
        win32file.FlushFileBuffers(handle)
        return result
    finally:
        if handle is not None:
            try:
                win32pipe.DisconnectNamedPipe(handle)
            except Exception:
                pass
            win32file.CloseHandle(handle)


def send_signed_permit_once_ci(name, permit):
    """Unprivileged client: deliver already-signed bytes; cannot add a key.

    Never signs, retries submission or treats a pipe receipt as owner consent.
    """
    _ci_only()
    _pipe_name(name)
    raw = _canon({"schema": SCHEMA, "permit": permit})
    if len(raw) > MAX_REQUEST:
        reject("Oversized signed IPC request")
    import pywintypes
    import win32pipe
    import win32file
    import win32con
    deadline = time.monotonic() + 4.0
    while True:
        try:
            win32pipe.WaitNamedPipe(name, 800)
            break
        except pywintypes.error as exc:
            if exc.winerror not in (2, 231) or time.monotonic() > deadline:
                reject("Pinned named pipe was not available")
            time.sleep(0.04)

    pipe = win32file.CreateFile(
        name, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
        0, None, win32con.OPEN_EXISTING, 0, None)
    try:
        win32pipe.SetNamedPipeHandleState(
            pipe, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(pipe, raw)
        status, received = win32file.ReadFile(pipe, MAX_REPLY)
        if status != 0 or len(received) > MAX_REPLY:
            reject("Uncertain IPC reply; never repeat")
    finally:
        win32file.CloseHandle(pipe)
    reply = _message_result(received)
    # This is observational telemetry, not proof of service identity.
    return reply


def _message_result(raw):
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise AdmissionIPCRejected("Invalid IPC response") from exc
    if (type(obj) is not dict or
            obj.get("schema") != "nf.onepc.core_admission_observation_ci.v1" or
            obj.get("status") not in (
                "OBSERVED_QUEUED_TEST_ONLY",
                "DENIED_OR_UNKNOWN_NO_AUTO_RETRY",
            ) or obj.get("queue_claim_allowed") is not False or
            obj.get("host_execution_allowed") is not False or
            obj.get("automatic_retry_allowed") is not False or
            obj.get("independently_verified") is not False or
            obj.get("production_release") is not False):
        reject("IPC response cannot grant trusted execution")
    return obj
