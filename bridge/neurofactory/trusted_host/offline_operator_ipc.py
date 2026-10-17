"""Test-only signer-owned Unix-domain verification service (read-only).

The consumer never receives private key material. SO_PEERCRED is checked against
an independently configured permitted service UID and the socket is group-
restricted. Does NOT issue owner permissions, lease grants, or write files.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
from offline_operator_anchor import _guard, verify_current,OperatorAnchorDenied

class OperatorIPCError(ValueError): pass

def _deny(message):raise OperatorIPCError(message)

def serve_once(home, socket_path, *, allowed_peer_uid):
    root=_guard(home)
    if (os.name!="posix" or type(allowed_peer_uid) is not int or
        allowed_peer_uid<=0 or allowed_peer_uid==os.geteuid()):
        _deny("distinct pinned consumer UID required")
    sock_path=Path(socket_path)
    parent=sock_path.parent
    if (not sock_path.is_absolute() or sock_path.name!="nf-readonly-operator.sock"
        or parent.name!="nf-operator-api" or parent.is_symlink()
        or not parent.is_dir()):
        _deny("only disposable expected socket directory allowed")
    st=parent.stat()
    if (st.st_uid!=os.geteuid() or st.st_mode & 0o027 or
        not stat.S_ISDIR(st.st_mode)):
        _deny("socket directory owner/group restrictions invalid")
    if sock_path.exists() or sock_path.is_symlink():
        _deny("refuse existing socket")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as srv:
        srv.settimeout(12)
        srv.bind(str(sock_path))
        os.chmod(sock_path,0o660)
        srv.listen(1)
        try:
            conn,_=srv.accept()
            with conn:
                conn.settimeout(3)
                rawcreds=conn.getsockopt(
                    socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))
                pid,uid,gid=struct.unpack("3i",rawcreds)
                if uid!=allowed_peer_uid or pid<=0:
                    conn.sendall(b'{"status":"DENIED_PEER"}')
                    return
                raw=conn.recv(8193)
                if not raw or len(raw)>8192:
                    conn.sendall(b'{"status":"DENIED_INPUT"}')
                    return
                try:
                    req=json.loads(raw.decode("ascii"))
                    if type(req) is not dict or type(req.get("schema")) is not str:
                        _deny("invalid schema")
                    if (req["schema"]=="neurofactory.operator.readonly_current.v1"
                            and set(req)=={"schema","packet","public_sha","public_key"}):
                        result=verify_current(
                            root,req["packet"],req["public_sha"],req["public_key"])
                        ret={"status":"CURRENT_CHECK_ONLY_NOT_AUTHORITY",
                            "current_sequence":result["sequence"],
                            "head":result["head"],
                            "peer_uid_checked":True,"private_key_shared":False,
                            "owner_authenticated":False,"filesystem_write_allowed":False}
                    elif (req["schema"]=="neurofactory.operator.scope_check_fixture.v1"
                          and set(req)=={"schema","signed_permit","witness","public_sha","public_key"}):
                        from offline_signer_scope_guard import check_signer_owned_scope
                        result=check_signer_owned_scope(
                            root,signed_permit=req["signed_permit"],
                            witness=req["witness"],current_key_fingerprint=req["public_sha"],
                            current_public_b64=req["public_key"])
                        ret={"status":result["status"],
                             "signed_permit_sha256":result["signed_permit_sha256"],
                             "operation_id":result["operation_id"],
                             "current_signer_sequence":result["current_signer_sequence"],
                             "peer_uid_checked":True,"private_key_shared":False,
                             "owner_authenticated":False,"filesystem_write_allowed":False}
                    else:
                        _deny("invalid request shape")
                except (ValueError,UnicodeError,TypeError,OperatorAnchorDenied):
                    ret={"status":"DENIED_WITNESS","filesystem_write_allowed":False}
                conn.sendall(json.dumps(ret,sort_keys=True,separators=(",",":")).encode())
        finally:
            sock_path.unlink(missing_ok=True)

def client_send(socket_path,request,*,pinned_signer_uid=None):
    """Authenticate server UID from out-of-band operator configuration.

    Legacy read-only debug clients may omit pin, but the new scoped consumer
    MUST provide it and reject server impersonation or an absent signer.
    """
    if pinned_signer_uid is not None and (
        type(pinned_signer_uid) is not int or pinned_signer_uid<=0
        or not socket_path.endswith("/nf-readonly-operator.sock")):
        _deny("invalid externally pinned signer UID")
    raw=json.dumps(request,sort_keys=True,separators=(",",":")).encode("ascii")
    if len(raw)>8192:_deny("request too large")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(4)
        conn.connect(str(socket_path))
        if pinned_signer_uid is not None:
            creds=conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))
            pid,uid,gid=struct.unpack("3i",creds)
            if pid<=0 or uid!=pinned_signer_uid:
                _deny("UNTRUSTED_SIGNER_SERVER_UID")
        conn.sendall(raw)
        response=conn.recv(8192)
    if not response or len(response)>8191:
        _deny("signer unavailable or truncated reply")
    parsed=json.loads(response.decode("ascii"))
    if type(parsed) is not dict:
        _deny("invalid read-only signer response")
    return parsed

def cli(args):
    if len(args)!=6 or args[1]!="serve" or os.environ.get("NF_OPERATOR_ANCHOR_FIXTURE_ONLY")!="1":
        _deny("strict fixture-only serve arguments")
    serve_once(args[2],args[3],allowed_peer_uid=int(args[4]))
if __name__=="__main__":
    if len(sys.argv)!=5:
        print("OFFLINE_ONLY_DENIED",file=sys.stderr);sys.exit(3)
    try:
        if sys.argv[1]!="serve":_deny("not server command")
        serve_once(sys.argv[2],sys.argv[3],allowed_peer_uid=int(sys.argv[4]))
    except (OperatorIPCError,OperatorAnchorDenied,ValueError,OSError):
        print("OFFLINE_READONLY_OPERATOR_IPC_DENIED",file=sys.stderr)
        sys.exit(3)
