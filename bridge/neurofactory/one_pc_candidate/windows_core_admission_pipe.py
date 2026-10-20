"""CI-ONLY Windows protected named-pipe owner-permit -> real CORE admission.

Reuses the existing TRUSTED HOST pilot's Windows named-pipe DACL and
ImpersonateNamedPipeClient peer-SID validator. Does NOT activate the HOST
service, execute a task, call Ollama, or expose signing material. The
protected receiver independently uses signed_owner_admission to reread
the durable workspace, revalidate Git preimage, and enqueue ONCE in
the existing CORE SQLite singleton.

SECURITY LIMIT: caller and CORE receiver run under the SAME SID in this
disposable Windows GitHub Actions pilot. A different user SID is tested
as forbidden, but an independently provisioned service/owner SID and
rollback-resistant external witness remain unverified. NO LIVE DEPLOY.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import time

from signed_owner_admission import AdmissionDenied, admit_signed_draft, _canon

# Import only the EXISTING TRUSTED HOST Windows Named Pipe primitives.
# Source sibling is in the same pinned Git checkout, never a model path.
import sys
_TRUSTED_HOST = Path(__file__).resolve().parents[1] / "trusted_host"
if not _TRUSTED_HOST.is_dir() or _TRUSTED_HOST.is_symlink():
    raise RuntimeError("Original trusted host named-pipe primitives missing")
sys.path.insert(0, str(_TRUSTED_HOST))
from windows_named_pipe_pilot_receiver import _named_pipe_sid, _peer_matches

PIPE_BASE = r"\\.\pipe\neurofactory-admission-"
PIPE_NAME = re.compile(r"neurofactory-admission-[a-f0-9]{24}\Z")
MAX_PACKET = 8192
MAX_RESPONSE = 1024
TRANSPORT = "nf.windows.core.signed_admission_transport_ci.v1"
RESPONSE = "nf.windows.core.admission_observation_ci.v1"


class CorePipeDenied(ValueError):
    """No automatic replay, retry or implied owner approval."""


def deny():
    raise CorePipeDenied("Windows owner-to-CORE protected pipe denied or unknown")


def require_ci():
    if (os.name != "nt" or os.getenv("GITHUB_ACTIONS") != "true" or
            os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.getenv("NF_CORE_OWNER_PIPE_CI_ONLY") != "1"):
        deny()


def pipe_name(raw: str):
    if (type(raw) is not str or not raw.startswith(PIPE_BASE) or
            not PIPE_NAME.fullmatch(raw.rsplit("\\", 1)[-1])):
        deny()
    return raw


def _parse_packet(raw, *, response=False):
    if type(raw) is not bytes or not 1 <= len(raw) <= (
        MAX_RESPONSE if response else MAX_PACKET
    ):
        deny()

    def unique(items):
        result = {}
        for key, val in items:
            if key in result:
                deny()
            result[key] = val
        return result

    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                         parse_constant=lambda _: deny())
    except (ValueError, UnicodeError, TypeError, OverflowError) as exc:
        raise CorePipeDenied("Bounded Windows named-pipe JSON rejected") from exc
    if type(obj) is not dict:
        deny()
    if response:
        if (set(obj) != {"schema", "status", "execution_allowed",
                         "auto_retry_allowed", "task_id"} or
                obj.get("schema") != RESPONSE or
                obj.get("status") not in (
                    "QUEUED_SIGNED_TEST_ONLY", "DENIED_OR_UNKNOWN_MANUAL_REVIEW") or
                obj.get("execution_allowed") is not False or
                obj.get("auto_retry_allowed") is not False or
                type(obj.get("task_id")) is not str or
                not re.fullmatch(r"(?:NF-DEV-05-Q[0-9]{3})?\Z", obj["task_id"])):
            deny()
    else:
        if set(obj) != {"schema", "permit"} or obj.get("schema") != TRANSPORT or \
                type(obj.get("permit")) is not dict:
            deny()
    return obj


def _pin_public(raw):
    if type(raw) is not bytes or len(raw) != 32:
        deny()
    return raw


def _pin_sid(raw):
    import win32security
    if type(raw) is not str or not raw.startswith("S-1-5-21-"):
        deny()
    try:
        sid = win32security.ConvertStringSidToSid(raw)
        _, _, kind = win32security.LookupAccountSid(None, sid)
        if kind != win32security.SidTypeUser:
            deny()
        return sid
    except Exception as exc:
        raise CorePipeDenied("Trusted Windows sender SID cannot be independently resolved") from exc


def serve_one_signed_core_admission(pipe_path, *, trusted_sender_sid, owner_public_raw,
                                   workspace, core, ready=None):
    """One strict, ephemeral CI-only pipe session.

    The *receiver* supplies pinned sender SID and owner key, NEVER browser
    arguments. The sender cannot submit an unsigned path, key, or CORE root.
    """
    require_ci()
    pipe_name(pipe_path)
    _pin_public(owner_public_raw)
    sid = _pin_sid(trusted_sender_sid)
    import win32file
    import win32pipe
    import pywintypes
    handle = None
    try:
        # FILE_FLAG_FIRST_PIPE_INSTANCE blocks accidental competing instances.
        handle = win32pipe.CreateNamedPipe(
            pipe_path,
            win32pipe.PIPE_ACCESS_DUPLEX | 0x00080000,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE |
                win32pipe.PIPE_WAIT,
            1, MAX_PACKET, MAX_PACKET, 2000, _named_pipe_sid(sid),
        )
        if ready is not None:
            ready.set()
        try:
            win32pipe.ConnectNamedPipe(handle, None)
        except pywintypes.error as exc:
            if exc.winerror != 535:
                raise
        try:
            status, raw = win32file.ReadFile(handle, MAX_PACKET)
            if status != 0 or not raw or len(raw) > MAX_PACKET:
                deny()
            # Existing TRUSTED HOST impersonates the actual client token
            # before parsing or touching CORE.
            if not _peer_matches(handle, trusted_sender_sid):
                deny()
            request = _parse_packet(raw)
            permit = request["permit"]
            result = admit_signed_draft(
                workspace, core, permit, owner_public_raw=owner_public_raw)
            if (result.get("core_reported_state") != "QUEUED" or
                    result.get("queue_claim_allowed") is not False or
                    result.get("host_execution_allowed") is not False or
                    result.get("production_release") is not False):
                deny()
            response = {
                "schema": RESPONSE, "status": "QUEUED_SIGNED_TEST_ONLY",
                "task_id": result["core_task_id"],
                "execution_allowed": False, "auto_retry_allowed": False,
            }
        except Exception:
            # Unknown outcome may have COMMITTED CORE SQLite already: never
            # request a retry or mark the task completed.
            response = {
                "schema": RESPONSE, "status": "DENIED_OR_UNKNOWN_MANUAL_REVIEW",
                "task_id": "", "execution_allowed": False,
                "auto_retry_allowed": False,
            }
        out = _canon(response)
        if len(out) > MAX_RESPONSE:
            deny()
        try:
            win32file.WriteFile(handle, out)
            win32file.FlushFileBuffers(handle)
        except (pywintypes.error, OSError):
            # A disconnected sender MUST inspect durable CORE manually.
            pass
        return response
    finally:
        if handle is not None:
            try:
                win32pipe.DisconnectNamedPipe(handle)
            except Exception:
                pass
            win32file.CloseHandle(handle)


def _server_process_sid(pipe_handle):
    """Verify Windows server process SID from real named-pipe server PID."""
    import win32api
    import win32con
    import win32security
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    getpid = kernel.GetNamedPipeServerProcessId
    getpid.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    getpid.restype = wintypes.BOOL
    process_id = wintypes.ULONG()
    if not getpid(wintypes.HANDLE(int(pipe_handle)), ctypes.byref(process_id)):
        deny()
    process = win32api.OpenProcess(
        win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, process_id.value)
    try:
        token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
        try:
            user = win32security.GetTokenInformation(
                token, win32security.TokenUser)[0]
            return win32security.ConvertSidToStringSid(user)
        finally:
            token.Close()
    finally:
        process.Close()


def send_one_owner_permit(pipe_path, permit, *, expected_receiver_sid):
    """One client send only; caller MUST NOT loop or resend unknown outcomes."""
    require_ci()
    pipe_name(pipe_path)
    _pin_sid(expected_receiver_sid)
    data = _canon({"schema": TRANSPORT, "permit": permit})
    if not 1 <= len(data) <= MAX_PACKET:
        deny()
    import win32file
    import win32pipe
    import win32con
    import pywintypes
    # This waits for server availability but NEVER retries a written request.
    try:
        win32pipe.WaitNamedPipe(pipe_path, 5000)
        handle = win32file.CreateFile(
            pipe_path, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            0, None, win32con.OPEN_EXISTING, 0, None)
    except pywintypes.error as exc:
        raise CorePipeDenied("No authorized named-pipe connection") from exc
    try:
        if _server_process_sid(handle) != expected_receiver_sid:
            deny()
        win32pipe.SetNamedPipeHandleState(
            handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(handle, data)
        win32file.FlushFileBuffers(handle)
        status, raw = win32file.ReadFile(handle, MAX_RESPONSE)
        if status != 0:
            deny()
        return _parse_packet(raw, response=True)
    except (pywintypes.error, OSError) as exc:
        raise CorePipeDenied("CORE admission outcome unknown; no automatic retry") from exc
    finally:
        win32file.CloseHandle(handle)
