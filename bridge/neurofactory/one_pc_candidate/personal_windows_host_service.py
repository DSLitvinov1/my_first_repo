"""Personal, non-administrator Windows SCM service with real remote fencing.

Supported OS effect is ONLY creation of one owner-approved UTF-8 note inside
the independently ACL-protected Neurofactory output directory. NO arbitrary
shell, browser, installed SKILLS, registry/network modifications, source edits,
or automated execution of Qwen text. A one-use SQLite UNKNOWN is fsynced
BEFORE sending any SSH request to the physically separate Linux witness.

This mode needs no third-party reviewer or paid Authenticode certificate for
private use, but it is NOT independently operated/WORM-backed: the Windows
and Linux administrator can still override both roots.
"""
from __future__ import annotations

import base64
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import win32event
import win32service
import win32serviceutil

from personal_ssh_highwater import _canon, REQ_SCHEMA
from personal_ssh_highwater_client import reserve_personal_epoch,PersonalWitnessUnknown

SERVICE_NAME="NeurofactoryPersonalHost"
ROOT=Path(os.environ.get("ProgramData",r"C:\ProgramData"))/"NeurofactoryPersonalHost"
CONFIG=ROOT/"operator-config.json"
FENCE=ROOT/"intent-fence.sqlite3"
INBOX=ROOT/"inbox"
OUT=ROOT/"outputs"
OWNER_DOMAIN=b"NF_PERSONAL_OWNER_NOTE_APPROVAL_V1\x00"
HEX32=re.compile(r"[a-f0-9]{32}\Z")
HEX40=re.compile(r"[a-f0-9]{40}\Z")
HEX64=re.compile(r"[a-f0-9]{64}\Z")
PERMIT_SCHEMA="nf.personal.owner_signed_note.v1"
CONFIG_SCHEMA="nf.personal.host.operator_pinned.v1"
PERMIT_FIELDS=frozenset((
    "schema","task_id","project_id","nonce","external_epoch",
    "issued_unix","expires_unix","source_sha40","machine_sha256",
    "package_sha256","operation","text","owner_signature_base64",
))
CONFIG_FIELDS=frozenset((
    "schema","owner_public_base64","witness_public_base64",
    "source_sha40","machine_sha256","package_sha256",
))
DDL=("CREATE TABLE intents("
     "task_id TEXT PRIMARY KEY,nonce TEXT UNIQUE NOT NULL,"
     "external_epoch INTEGER UNIQUE NOT NULL,operation_sha256 TEXT UNIQUE NOT NULL,"
     "status TEXT NOT NULL CHECK(status IN ('UNKNOWN_NO_AUTO_RETRY','EXECUTED')), "
     "remote_head TEXT)")
ALLOWED_ACTION="write_note"

class PersonalHostDenied(ValueError):
    pass

def _deny(msg):
    raise PersonalHostDenied("Protected personal host refuses: "+msg)

def _unique(pairs):
    d={}
    for key,value in pairs:
        if key in d:
            _deny("duplicate input key")
        d[key]=value
    return d

def _plain(path:Path,*,max_size):
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        _deny("operator file absent or redirected")
    st=path.lstat()
    if (not stat.S_ISREG(st.st_mode) or not 1<=st.st_size<=max_size
            or os.name=="nt" and st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        _deny("unexpected operator file")
    return path

def _safe_dir(path:Path):
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        _deny("operator-owned directory unavailable")
    if os.name=="nt" and path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        _deny("NTFS junction/reparse point refused")
    return path

def _decode_pub(source):
    if type(source) is not str or len(source)!=44:
        _deny("Ed25519 owner/witness public key invalid")
    try:
        raw=base64.b64decode(source,validate=True)
        if len(raw)!=32:
            _deny("invalid Ed25519 raw key size")
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError,TypeError) as exc:
        raise PersonalHostDenied("Pinned public key not valid Ed25519") from exc

def _config():
    root=_safe_dir(ROOT)
    _safe_dir(INBOX)
    _safe_dir(OUT)
    data=json.loads(_plain(CONFIG,max_size=4096).read_text("ascii"),
                    object_pairs_hook=_unique)
    if (type(data) is not dict or set(data)!=CONFIG_FIELDS or
            data.get("schema")!=CONFIG_SCHEMA or
            type(data.get("source_sha40")) is not str or
            not HEX40.fullmatch(data["source_sha40"]) or
            any(type(data.get(k)) is not str or not HEX64.fullmatch(data[k])
                for k in ("machine_sha256","package_sha256"))):
        _deny("operator configuration not pinned")
    owner=_decode_pub(data["owner_public_base64"])
    witness=_decode_pub(data["witness_public_base64"])
    return data,owner,witness

def provision_empty_fence_offline():
    """Installer only. Never invoked by the running SCM service."""
    _safe_dir(ROOT)
    if FENCE.exists() or FENCE.is_symlink():
        _deny("existing durable fence can never be reset")
    fd=os.open(FENCE,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(fd)
    with closing(sqlite3.connect(FENCE.as_uri()+"?mode=rw",
                                 uri=True,isolation_level=None)) as con:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=FULL")
        con.execute(DDL)
    return "EMPTY_PERSONAL_HOST_FENCE_PROVISIONED_NO_ACTION"

def _connect_existing():
    path=_plain(FENCE,max_size=128_000_000)
    con=sqlite3.connect(path.as_uri()+"?mode=rw",uri=True,
                        timeout=5,isolation_level=None)
    try:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=FULL")
        found=con.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='intents'"
        ).fetchone()
        if found!=(DDL,) or con.execute("PRAGMA quick_check").fetchall()!=[("ok",)]:
            _deny("durable local intent ledger missing or corrupted")
    except Exception:
        con.close()
        raise
    return con

def _signed_body(packet,operator,owner,now):
    if (type(packet) is not dict or set(packet)!=PERMIT_FIELDS or
        packet.get("schema")!=PERMIT_SCHEMA or
        packet.get("operation")!=ALLOWED_ACTION or
        any(type(packet.get(k)) is not str or not HEX32.fullmatch(packet[k])
            for k in ("task_id","project_id","nonce")) or
        any(packet.get(k)!=operator[k] for k in
            ("source_sha40","machine_sha256","package_sha256")) or
        type(packet.get("external_epoch")) is not int or
        not 1<=packet["external_epoch"]<2**62 or
        type(packet.get("issued_unix")) is not int or
        type(packet.get("expires_unix")) is not int or
        not now-30<=packet["issued_unix"]<=now+2 or
        not now<packet["expires_unix"]<=now+90 or
        type(packet.get("text")) is not str or
        not 1<=len(packet["text"].encode("utf-8"))<=2048 or
        any(ord(c)<32 and c not in "\n\t" for c in packet["text"])
        or type(packet.get("owner_signature_base64")) is not str):
        _deny("exact allowed owner-approved note request required")
    body={k:v for k,v in packet.items() if k!="owner_signature_base64"}
    try:
        raw=base64.b64decode(packet["owner_signature_base64"],validate=True)
        if len(raw)!=64:
            _deny("bad owner signature")
        owner.verify(raw,OWNER_DOMAIN+_canon(body))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise PersonalHostDenied("operator owner signature verification denied") from exc
    return body

def _reserve_local_unknown(body,operation_hash):
    with closing(_connect_existing()) as con:
        con.execute("BEGIN IMMEDIATE")
        last=con.execute("SELECT MAX(external_epoch) FROM intents").fetchone()[0] or 0
        # No success/UNKNOWN retry, gap or epoch reuse, including after crash.
        if body["external_epoch"]!=last+1:
            _deny("local epoch gap or replay")
        con.execute(
            "INSERT INTO intents(task_id,nonce,external_epoch,"
            "operation_sha256,status,remote_head) VALUES(?,?,?,?,'UNKNOWN_NO_AUTO_RETRY',NULL)",
            (body["task_id"],body["nonce"],body["external_epoch"],operation_hash))
        con.execute("COMMIT")

def _mark_executed(body,head):
    with closing(_connect_existing()) as con:
        con.execute("BEGIN IMMEDIATE")
        updated=con.execute(
            "UPDATE intents SET status='EXECUTED',remote_head=? "
            "WHERE task_id=? AND external_epoch=? "
            "AND status='UNKNOWN_NO_AUTO_RETRY'",
            (head,body["task_id"],body["external_epoch"]))
        if updated.rowcount!=1:
            _deny("local UNKNOWN changed after effect")
        con.execute("COMMIT")

def perform_approved_safe_note(packet):
    """Single owner-signed permitted note. Never called directly by Qwen."""
    operator,owner,witness=_config()
    body=_signed_body(packet,operator,owner,int(time.time()))
    operation_sha256=sha256(_canon(body)).hexdigest()
    # Durable local UNKNOWN *before* first external network byte.
    _reserve_local_unknown(body,operation_sha256)
    claim={
        "schema":REQ_SCHEMA,
        "task_id":body["task_id"],
        "project_id":body["project_id"],
        "operation_sha256":operation_sha256,
        "nonce":body["nonce"],
        "external_epoch":body["external_epoch"],
        "issued_unix":body["issued_unix"],
        "expires_unix":body["expires_unix"],
        "source_sha40":body["source_sha40"],
        "machine_sha256":body["machine_sha256"],
        "package_sha256":body["package_sha256"],
    }
    try:
        witness_raw=witness.public_bytes_raw()
        ack=reserve_personal_epoch(
            trusted_service_root=ROOT,claim=claim,
            pinned_public_raw=witness_raw)
        if (ack.get("status")!="SIGNED_EXTERNAL_EPOCH_OBSERVED_NO_EFFECT_AUTHORITY"
                or ack.get("epoch")!=body["external_epoch"]
                or ack.get("signed_witness_verified") is not True
                or ack.get("automatic_retry_allowed") is not False):
            _deny("remote reservation not verified")
        # Ensure authenticated operation and fresh scope are still valid
        # after the remote signed reservation, before any file effect.
        if not int(time.time())<body["expires_unix"]:
            _deny("approval expired during remote request")
        _safe_dir(OUT)
        target=OUT/(body["task_id"]+".txt")
        if target.exists() or target.is_symlink():
            _deny("one-use safe output already exists")
        payload=body["text"].encode("utf-8")
        fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"wb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        if sha256(target.read_bytes()).hexdigest()!=sha256(payload).hexdigest():
            _deny("file readback mismatch; UNKNOWN state")
        _mark_executed(body,ack["ledger_head"])
        return {"status":"ONE_OWNER_APPROVED_SAFE_NOTE_CREATED",
                "task_id":body["task_id"],
                "external_epoch":body["external_epoch"]}
    except Exception as exc:
        # No file effect on SSH loss; possible UNKNOWN after remote commit.
        # Never release the local lock or retry an operation/epoch.
        raise PersonalHostDenied(
            "external witness, local output or completion UNKNOWN; no retry") from exc


class NeurofactoryPersonalHost(win32serviceutil.ServiceFramework):
    _svc_name_=SERVICE_NAME
    _svc_display_name_="Neurofactory personal protected host"
    _svc_description_=(
        "LocalService restricted SID; owner-signed notes only; remote SSH highwater; "
        "never executes Qwen instructions or arbitrary OS commands")

    def __init__(self,args):
        super().__init__(args)
        self.stopping=threading.Event()
        self.stop=win32event.CreateEvent(None,0,0,None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stopping.set()
        win32event.SetEvent(self.stop)

    def SvcDoRun(self):
        # No side effects at startup. A missing/altered owner/witness scope or
        # absent durable state aborts before any task can be considered.
        _config()
        with closing(_connect_existing()):
            pass
        seen=set()
        while not self.stopping.is_set():
            # Both inbox and operator-supplied config must have separately
            # provisioned immutable ACLs (enforced at installation/preflight).
            _safe_dir(INBOX)
            try:
                items=sorted(INBOX.glob("*.json"))
            except OSError:
                break
            for path in items[:32]:
                if self.stopping.is_set():
                    break
                if path.name in seen:
                    continue
                seen.add(path.name)
                try:
                    if (len(path.name)!=37 or not HEX32.fullmatch(path.stem)):
                        continue
                    raw=_plain(path,max_size=4096).read_text("utf-8")
                    packet=json.loads(raw,object_pairs_hook=_unique)
                    if packet.get("task_id")!=path.stem:
                        continue
                    perform_approved_safe_note(packet)
                except Exception:
                    # No automatic replay on ambiguous trust, SQLite or SSH.
                    # Ignore malformed/untrusted user-supplied requests; the
                    # durable local ledger permanently consumes signed ones.
                    continue
            win32event.WaitForSingleObject(self.stop,2000)

if __name__=="__main__":
    import sys
    if sys.argv[1:]==["--scm"]:
        import servicemanager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NeurofactoryPersonalHost)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        raise SystemExit("This file is only a protected Windows SCM receiver")
