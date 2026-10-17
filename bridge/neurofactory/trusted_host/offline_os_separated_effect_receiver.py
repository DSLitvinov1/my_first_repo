"""ONE-SHOT OS-ISOLATED receiver prototype on disposable Linux runner ONLY.

Runs as distinct nf_effect UID. No worker/DB principal owns destination,
recipient configuration or Unix socket. Reject every unauthorized peer,
scope, stale signer head and PG lease before a single scratch file effect.
Config is preprovisioned as 0600 in recipient-owned 0700 directory and never
provided by the worker. Still a fixture; no real owner/root admission.
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

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from offline_fenced_file_receiver import OfflineFencedFileReceiver
from offline_operator_gated_receiver import OperatorGatedOfflineReceiver
from offline_recipient_protected_journal import RecipientProtectedJournal

_MAX=110000
_SCHEMA="neurofactory.os_separated_recipient.fixture.v1"
_DSN="postgresql://nf_test:nf_test_ephemeral_only@127.0.0.1:5432/nf_test"

class OSReceiverDenied(ValueError): pass

def _deny(message="not an authorized standalone recipient"):
    raise OSReceiverDenied(message)

def _private_file(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file():
        _deny("missing signer-pinned receiver config")
    st=p.lstat()
    if st.st_uid!=os.geteuid() or st.st_mode & 0o077:
        _deny("receiver config not private to protected OS UID")
    return p

def _read_config(config_dir):
    if (os.name!="posix" or not hasattr(os,"geteuid") or os.geteuid()==0 or
        os.environ.get("NF_RECEIVER_OS_FIXTURE_ONLY")!="1" or
        os.environ.get("NF_OPERATOR_ANCHOR_FIXTURE_ONLY")!="1" or
        os.environ.get("NF_HOST_RECEIVER_FIXTURE_ONLY")!="1"):
        _deny("test-only independent nonroot recipient required")
    directory=Path(config_dir)
    if (not directory.is_absolute() or directory.is_symlink() or
        directory.name!="nf-recipient-config" or not directory.is_dir()):
        _deny("not recipient-owned config directory")
    d=directory.lstat()
    if d.st_uid!=os.geteuid() or d.st_mode & 0o077:
        _deny("recipient-owned private directory required")
    cfg=json.loads(_private_file(directory/"receiver.json").read_text("ascii"))
    fields={"schema","receiver_root","recipient_socket","peer_worker_uid",
            "signer_socket","signer_uid","signer_public_sha","signer_public_base64",
            "issuer_public_base64"}
    if (type(cfg) is not dict or set(cfg)!=fields or
        cfg["schema"]!=_SCHEMA or
        type(cfg["peer_worker_uid"]) is not int or cfg["peer_worker_uid"]<=0 or
        type(cfg["signer_uid"]) is not int or cfg["signer_uid"]<=0 or
        cfg["signer_uid"] in (cfg["peer_worker_uid"],os.geteuid()) or
        cfg["peer_worker_uid"]==os.geteuid() or
        any(type(cfg[k]) is not str for k in fields-{"schema","peer_worker_uid","signer_uid"})):
        _deny("bad recipient configuration")
    sock=Path(cfg["recipient_socket"])
    if (not sock.is_absolute() or sock.name!="nf-recipient.sock" or
        sock.parent.name!="nf-recipient-ipc" or sock.parent.is_symlink() or
        not sock.parent.is_dir()):
        _deny("invalid protected listener")
    d=sock.parent.lstat()
    if d.st_uid!=os.geteuid() or d.st_mode & 0o027:
        _deny("worker must not replace protected socket")
    return cfg

def serve_once(config_dir):
    cfg=_read_config(config_dir)
    sock=Path(cfg["recipient_socket"])
    if sock.exists() or sock.is_symlink():
        _deny("no existing socket accepted")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.settimeout(10)
        server.bind(str(sock))
        os.chmod(sock,0o660)
        server.listen(1)
        try:
            conn,_=server.accept()
            with conn:
                conn.settimeout(8)
                pid,uid,gid=struct.unpack("3i",conn.getsockopt(
                    socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
                if uid!=cfg["peer_worker_uid"] or pid<=0:
                    conn.sendall(b'{"status":"DENIED_PEER","live_execution_allowed":false}')
                    return
                try:
                    raw=conn.recv(_MAX+1)
                    if not raw or len(raw)>_MAX:
                        _deny("oversized request")
                    req=json.loads(raw.decode("ascii"))
                    if type(req) is not dict or set(req)!={"schema","signed_packet","witness","signed_owner_grant","content_base64"} or req["schema"]!="neurofactory.recipient.request.fixture.v1":
                        _deny("malformed request")
                    content=base64.b64decode(req["content_base64"],validate=True)
                    if len(content)>65536:_deny("bounded one-file content only")
                    pub=base64.b64decode(cfg["issuer_public_base64"],validate=True)
                    if len(pub)!=32:_deny("invalid protected pinned issuer")
                    db=psycopg.connect(_DSN,autocommit=True,connect_timeout=3)
                    try:
                        db.execute("SET neurofactory.offline_fixture_mode TO 'on'")
                        receiver=OfflineFencedFileReceiver(
                            db,cfg["receiver_root"],
                            pinned_public_key=Ed25519PublicKey.from_public_bytes(pub))
                        gated=OperatorGatedOfflineReceiver(
                            receiver,socket_path=cfg["signer_socket"],
                            pinned_signer_uid=cfg["signer_uid"],
                            independently_pinned_public_sha=cfg["signer_public_sha"],
                            independently_pinned_public_b64=cfg["signer_public_base64"])
                        # This is protected by nf_effect, not DB or worker.
                        # It persists across one-shot daemon restarts and
                        # refuses a second effect even after PostgreSQL rollback.
                        protected=RecipientProtectedJournal(config_dir)
                        report=gated.apply_fixture_with_operator_witness_once(
                            signed_packet=req["signed_packet"],witness=req["witness"],
                            content=content,protected_journal=protected,
                            signed_owner_grant=req["signed_owner_grant"],
                            simulate_crash_after_fsync=(
                                os.environ.get("NF_RECEIVER_TEST_SIMULATE_POST_FSYNC_CRASH")
                                =="1"))
                        response={"status":"ONE_OS_RECIPIENT_TEST_EFFECT_ONLY",
                                  "file_sha256":report["content_sha256"],
                                  "live_execution_allowed":False}
                    finally:db.close()
                except Exception:
                    # Fail closed, do not emit secrets or permit recovery retry.
                    response={"status":"DENIED_OR_UNKNOWN_MANUAL_STOP",
                              "live_execution_allowed":False,"auto_retry_allowed":False}
                conn.sendall(json.dumps(response,separators=(",",":")).encode("ascii"))
        finally:
            sock.unlink(missing_ok=True)

if __name__=="__main__":
    if len(sys.argv)!=2:sys.exit(3)
    try:serve_once(sys.argv[1])
    except Exception:
        print("TEST_ONLY_OS_RECEIVER_NO_LIVE_START",file=sys.stderr)
        sys.exit(3)
