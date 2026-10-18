"""Windows Named Pipe protected file receiver — isolated pilot ONLY.

A real Windows named pipe with explicit SID-only DACL, peer-token SID check,
Ed25519 owner-signed exact payload, CREATE_NEW (never overwrite), fsync and
receiver-owned append-only attempt marker. Designed for ONE inert text file
under a disposable test root; not installed as a Windows Service.

SECURITY BOUNDARY: before running on user's PC, owner must provision a
different Service SID and ACL-protected folder, non-exportable signing keys,
external antirollback store and independent REVIEW. The CI fixture deliberately
uses the SAME Windows user SID to show protocol and one file, which does NOT
prove different OS principals or production admission.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re

MAX_BYTES = 8192
PIPE_PREFIX = r"\\.\pipe\neurofactory-pilot-"
_SAFE_PIPE = re.compile(r"neurofactory-pilot-[a-f0-9]{24}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{3,90}\Z")
_SHA64 = re.compile(r"[a-f0-9]{64}\Z")
_SHA40 = re.compile(r"[a-f0-9]{40}\Z")
_FIELDS = frozenset({
    "schema","task_id","project_id","source_sha40","operation_id",
    "target","content_base64","content_sha256","approved_owner_signature",
})
_ALLOWED_TARGET = "bridge/neurofactory/development/core_owned/windows_pilot.txt"


class WindowsReceiverDenied(ValueError):
    pass


def _deny():
    raise WindowsReceiverDenied("protected Windows pilot receiver rejected operation")


def canon(obj):
    return json.dumps(obj,sort_keys=True,ensure_ascii=True,
                      separators=(",",":"),allow_nan=False).encode("ascii")


def canonical_signed_body(msg):
    if type(msg) is not dict or set(msg) != _FIELDS or \
            msg.get("schema") != "neurofactory.windows.single_file_pilot.v1":
        _deny()
    if not all(type(msg[k]) is str for k in _FIELDS):
        _deny()
    if not _TOKEN.fullmatch(msg["task_id"]) or \
            not _TOKEN.fullmatch(msg["project_id"]) or \
            not _TOKEN.fullmatch(msg["operation_id"]) or \
            not _SHA40.fullmatch(msg["source_sha40"]) or \
            not _SHA64.fullmatch(msg["content_sha256"]) or \
            msg["target"] != _ALLOWED_TARGET:
        _deny()
    if len(msg["approved_owner_signature"]) != 88 or \
            len(msg["content_base64"]) > 5500:
        _deny()
    body={k:v for k,v in msg.items() if k!="approved_owner_signature"}
    raw=canon(body)
    if len(raw)>MAX_BYTES:
        _deny()
    return body,raw


def validate_owner_signature(msg, owner_public):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    body,raw=canonical_signed_body(msg)
    if not isinstance(owner_public,Ed25519PublicKey):
        _deny()
    try:
        sig=base64.b64decode(msg["approved_owner_signature"],validate=True)
        if len(sig)!=64:
            _deny()
        owner_public.verify(sig,b"NF_WINDOWS_PILOT_V1\x00"+raw)
        payload=base64.b64decode(body["content_base64"],validate=True)
    except (InvalidSignature,ValueError,TypeError):
        _deny()
    if not payload or len(payload)>2048 or \
            hashlib.sha256(payload).hexdigest()!=body["content_sha256"]:
        _deny()
    return body,payload


def _private_root(root):
    p=Path(root)
    if os.name!="nt" or p.is_symlink() or not p.is_dir():
        _deny()
    st=p.stat()
    if st.st_file_attributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
        _deny()
    return p


def _named_pipe_sid(peer_user_sid, receiver_user_sid=None):
    import ntsecuritycon
    import pywintypes
    import win32api
    import win32security
    try:
        win32security.ConvertSidToStringSid(peer_user_sid)
    except Exception:
        _deny()
    sd=win32security.SECURITY_DESCRIPTOR()
    acl=win32security.ACL()
    # Explicit allow-list. No Everyone, Anonymous, or generic insecure DACL.
    acl.AddAccessAllowedAce(win32security.ACL_REVISION,
                            ntsecuritycon.FILE_GENERIC_READ |
                            ntsecuritycon.FILE_GENERIC_WRITE,
                            peer_user_sid)
    if receiver_user_sid is not None:
        # Dedicated service user also needs access to create/read this pipe.
        if win32security.ConvertSidToStringSid(peer_user_sid) == receiver_user_sid:
            _deny()
        receiver=win32security.ConvertStringSidToSid(receiver_user_sid)
        acl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                ntsecuritycon.FILE_GENERIC_READ |
                                ntsecuritycon.FILE_GENERIC_WRITE,
                                receiver)
    sd.SetSecurityDescriptorDacl(1,acl,0)
    sa=pywintypes.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR=sd
    return sa


def _peer_matches(pipe_handle, pinned_peer_sid_text):
    # pywin32's win32pipe does not expose ImpersonateNamedPipeClient on
    # supported builds. Call the documented Windows Advapi32 entrypoint.
    import ctypes
    import win32security
    import win32con
    import win32api
    kernel=ctypes.WinDLL("advapi32",use_last_error=True)
    impersonate=kernel.ImpersonateNamedPipeClient
    impersonate.argtypes=[ctypes.c_void_p]
    impersonate.restype=ctypes.c_int
    revert=kernel.RevertToSelf
    revert.argtypes=[]
    revert.restype=ctypes.c_int
    if not impersonate(ctypes.c_void_p(int(pipe_handle))):
        _deny()
    try:
        thread=win32security.OpenThreadToken(
            win32api.GetCurrentThread(),win32con.TOKEN_QUERY,True)
        found=win32security.GetTokenInformation(
            thread,win32security.TokenUser)[0]
        return win32security.ConvertSidToStringSid(found)==pinned_peer_sid_text
    finally:
        if not revert():
            _deny()

def serve_one_pilot(pipe_path,root,owner_public,peer_user_sid,*,
                    receiver_user_sid=None):
    """One request. Never a production daemon, no queue activation.

    CI tests must supply a fixed user SID pinned outside the worker message.
    Receiver-owned root ACL and separate service principal are a deployment
    prerequisite, NOT established by this function.
    """
    import win32file
    import win32pipe
    import win32con
    import win32security
    import pywintypes
    if os.name!="nt" or type(pipe_path) is not str or \
            not pipe_path.startswith(PIPE_PREFIX) or \
            not _SAFE_PIPE.fullmatch(pipe_path.rsplit("\\",1)[-1]):
        _deny()
    safe=_private_root(root)
    if receiver_user_sid is not None:
        from windows_receiver_sid_acl_guard import verify_receiver_isolation
        verify_receiver_isolation(safe,receiver_sid=receiver_user_sid,
                                  worker_sid=peer_user_sid)
    try:
        sid=win32security.ConvertStringSidToSid(peer_user_sid)
    except (TypeError,ValueError,pywintypes.error):
        _deny()
    pipe=None
    try:
        pipe=win32pipe.CreateNamedPipe(
            pipe_path,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE|win32pipe.PIPE_READMODE_MESSAGE|
                win32pipe.PIPE_WAIT,
            1,MAX_BYTES,MAX_BYTES,3000,
            _named_pipe_sid(sid,receiver_user_sid))
        try:
            win32pipe.ConnectNamedPipe(pipe,None)
        except pywintypes.error as exc:
            if exc.winerror != 535:  # ERROR_PIPE_CONNECTED
                raise
        try:
            # Win32 needs ReadFile first to cache the client's token for
            # ImpersonateNamedPipeClient. Check SID before parsing or effects.
            status,data=win32file.ReadFile(pipe,MAX_BYTES)
            if status!=0 or not data or len(data)>MAX_BYTES:
                _deny()
            if not _peer_matches(pipe,peer_user_sid):
                _deny()
            req=json.loads(data.decode("ascii"))
            body,payload=validate_owner_signature(req,owner_public)
            # Pilot name is fixed and derived from the exact signed target.
            # Store only under isolated root. No arbitrary user-supplied path.
            destination=safe/"windows_pilot.txt"
            receipt=safe/"one_effect_unknown.json"
            # State UNKNOWN before file, durable failure never auto retries.
            intent={"schema":"nf.windows.pilot.intent.v1",
                    "task_id":body["task_id"],
                    "operation_id":body["operation_id"],
                    "content_sha256":body["content_sha256"],
                    "state":"UNKNOWN_NO_AUTO_RETRY"}
            with open(receipt,"xb") as f:
                f.write(canon(intent));f.flush();os.fsync(f.fileno())
            with open(destination,"xb") as f:
                f.write(payload);f.flush();os.fsync(f.fileno())
            # Only on isolated disposable GitHub Windows CI: allow the test
            # supervisor to terminate THIS child process after durable fsync.
            # Never reachable in normal Windows service / user's machine.
            if (os.environ.get("GITHUB_ACTIONS")=="true" and
                os.environ.get("NF_WINDOWS_CI_POST_FSYNC_PAUSE")=="1"):
                import time
                time.sleep(20)
            response={"status":"ONE_INERT_WINDOWS_FILE_TEST_ONLY",
                      "content_sha256":body["content_sha256"],
                      "live_execution_allowed":False,
                      "auto_retry_allowed":False}
        except Exception:
            response={"status":"DENIED_OR_UNKNOWN_MANUAL_STOP",
                      "live_execution_allowed":False,
                      "auto_retry_allowed":False}
        win32file.WriteFile(pipe,canon(response))
        win32file.FlushFileBuffers(pipe)
        return response
    finally:
        if pipe is not None:
            try: win32pipe.DisconnectNamedPipe(pipe)
            except Exception: pass
            win32file.CloseHandle(pipe)


def core_pilot_send(pipe_path,proposal,task_claim,owner_private,*,core,worker_id,core_token):
    """CORE worker adapter, cannot write local file. TEST-ONLY signer injection.

    Real CORE must not hold owner_private; here it belongs solely to the CI
    fixture and tests the transport. Production owner signatures must arrive
    pre-signed from separately authorized owner.
    """
    import time
    import hmac
    import win32file
    import win32con
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if (os.name!="nt" or not isinstance(owner_private,Ed25519PrivateKey)
            or type(task_claim) is not dict or type(proposal) is not dict
            or proposal.get("mode")!="OFFLINE_TEST"
            or proposal.get("target")!=_ALLOWED_TARGET
            or task_claim.get("task_id") is None
            or task_claim.get("source_sha") is None):
        _deny()
    # Validate a REAL current CORE SQLite claimant. This token only
    # identifies a worker; it is never sufficient for receiver authorization.
    if (core is None or type(worker_id) is not str or
            type(core_token) is not str):
        _deny()
    try:
        with core._connect() as db:
            row=core._row(db)
            if (row is None or row["state"]!="CLAIMED" or
                    row["spec"]!=task_claim or row["owner"]!=worker_id or
                    row["lease_until"]<=int(time.time()) or
                    not hmac.compare_digest(row["token"],
                         hashlib.sha256(core_token.encode("utf8")).hexdigest())):
                _deny()
    except (ValueError,KeyError,TypeError,OSError):
        _deny()
    raw=proposal["content"].encode("utf8")
    body={"schema":"neurofactory.windows.single_file_pilot.v1",
          "task_id":task_claim["task_id"],
          "project_id":task_claim["project_id"],
          "source_sha40":task_claim["source_sha"],
          "operation_id":"pilot-" + task_claim["task_id"],
          "target":proposal["target"],
          "content_base64":base64.b64encode(raw).decode("ascii"),
          "content_sha256":hashlib.sha256(raw).hexdigest()}
    signature=owner_private.sign(b"NF_WINDOWS_PILOT_V1\x00"+canon(body))
    req={**body,"approved_owner_signature":base64.b64encode(signature).decode()}
    import win32pipe
    import pywintypes
    # Server is created by another thread/process; WaitNamedPipe may report
    # FILE_NOT_FOUND if called before CreateNamedPipe. Retry only for 3 s.
    deadline=time.monotonic()+3
    while True:
        try:
            win32pipe.WaitNamedPipe(pipe_path,1000)
            break
        except pywintypes.error as exc:
            if exc.winerror not in (2,231) or time.monotonic()>=deadline:
                _deny()
            time.sleep(0.04)
    pipe=win32file.CreateFile(pipe_path,win32con.GENERIC_READ|win32con.GENERIC_WRITE,
                             0,None,win32con.OPEN_EXISTING,0,None)
    try:
        import win32pipe
        win32pipe.SetNamedPipeHandleState(pipe,win32pipe.PIPE_READMODE_MESSAGE,None,None)
        win32file.WriteFile(pipe,canon(req))
        _,raw_answer=win32file.ReadFile(pipe,4096)
    finally:
        win32file.CloseHandle(pipe)
    response=json.loads(raw_answer.decode("ascii"))
    if (response.get("status")!="ONE_INERT_WINDOWS_FILE_TEST_ONLY" or
            response.get("content_sha256")!=body["content_sha256"] or
            response.get("live_execution_allowed") is not False):
        _deny()
    return {"status":"CORE_WINDOWS_ONE_INERT_PILOT_TEST_ONLY",
            "core_wrote_local_file":False,
            "live_execution_allowed":False,
            "auto_retry_allowed":False}
