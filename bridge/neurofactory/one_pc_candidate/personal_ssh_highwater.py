"""Single-user external rollback witness using an SSH *forced command*.

Separate physical Linux host, durable SQLite FULL, monotonically increasing
epochs, SHA256 hash-chain and Ed25519 signed receipts. Never executes commands
provided by clients, never resets the remote ledger, and never authorizes an
OS file effect by itself. The Linux account controls its own private key/DB:
this protects against Windows-only rollback, NOT malicious Linux-admin rollback
or a truly independent operator's hardware non-rollback guarantee.
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
import sys
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REQ_SCHEMA = "nf.personal.highwater.reserve.v1"
ACK_SCHEMA = "nf.personal.highwater.ack.v1"
STATUS_REQ_SCHEMA = "nf.personal.highwater.status_request.v1"
STATUS_ACK_SCHEMA = "nf.personal.highwater.status_ack.v1"
STATUS_DOMAIN = b"NF_PERSONAL_REMOTE_HIGHWATER_STATUS_V1\x00"
DOMAIN = b"NF_PERSONAL_REMOTE_HIGHWATER_ACK_V1\x00"
DB_NAME = "personal-highwater.sqlite3"
HEAD_ZERO = "0" * 64
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
FIELDS = frozenset(("schema","task_id","project_id","operation_sha256",
                    "nonce","external_epoch","issued_unix","expires_unix",
                    "source_sha40","machine_sha256","package_sha256"))
DDL = ("CREATE TABLE reservations("
       "external_epoch INTEGER PRIMARY KEY,task_id TEXT UNIQUE NOT NULL,"
       "operation_sha256 TEXT UNIQUE NOT NULL,nonce TEXT UNIQUE NOT NULL,"
       "claim_sha256 TEXT NOT NULL,previous_head TEXT NOT NULL,"
       "ledger_head TEXT NOT NULL,committed_unix INTEGER NOT NULL)")
FLOOR_DDL = ("CREATE TABLE monotonic_floor("
             "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
             "external_epoch INTEGER NOT NULL,ledger_head TEXT NOT NULL)")

class PersonalHighwaterDenied(ValueError):
    pass

def _fail(text):
    raise PersonalHighwaterDenied(text)

def _canon(data):
    return json.dumps(data,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")

def _unique(pairs):
    data={}
    for key,value in pairs:
        if key in data:
            _fail("duplicate field")
        data[key]=value
    return data

def _private_root(root):
    if (not isinstance(root,Path) or not root.is_absolute()
            or root.is_symlink() or not root.is_dir()):
        _fail("private witness root missing")
    mode=root.lstat()
    if (mode.st_uid!=os.geteuid() or mode.st_mode&0o077 or
            not stat.S_ISDIR(mode.st_mode)):
        _fail("unprivileged operator-owned private directory required")
    return root

def _private_file(root,name,*,max_size):
    path=_private_root(root)/name
    if path.is_symlink() or not path.is_file():
        _fail("operator private file missing")
    metadata=path.lstat()
    if (metadata.st_uid!=os.geteuid() or metadata.st_mode&0o077 or
        not stat.S_ISREG(metadata.st_mode) or
        not 1<=metadata.st_size<=max_size):
        _fail("operator private file ownership/mode/length invalid")
    return path

def validate_claim(claim, *, expected_source, expected_machine,expected_package,
                   now):
    if (type(claim) is not dict or set(claim)!=FIELDS or
        claim.get("schema")!=REQ_SCHEMA or
        any(type(claim.get(k)) is not str or not HEX32.fullmatch(claim[k])
            for k in ("task_id","project_id","nonce")) or
        any(type(claim.get(k)) is not str or not HEX64.fullmatch(claim[k])
            for k in ("operation_sha256","machine_sha256","package_sha256")) or
        type(claim.get("source_sha40")) is not str or
        not HEX40.fullmatch(claim["source_sha40"]) or
        claim["source_sha40"]!=expected_source or
        claim["machine_sha256"]!=expected_machine or
        claim["package_sha256"]!=expected_package or
        type(claim.get("external_epoch")) is not int or
        not 1<=claim["external_epoch"]<2**62 or
        type(claim.get("issued_unix")) is not int or
        type(claim.get("expires_unix")) is not int or
        not now-30<=claim["issued_unix"]<=now+2 or
        not now<claim["expires_unix"]<=now+90 or
        not 1<=claim["expires_unix"]-claim["issued_unix"]<=120):
        _fail("claim outside independently pinned one-use scope")
    return claim

def provision_new_offline(root):
    if os.name!="posix" or os.geteuid()==0:
        _fail("only unprivileged Linux operator")
    root=_private_root(root)
    db=root/DB_NAME
    if db.exists() or db.is_symlink():
        _fail("existing state NEVER reset")
    fd=os.open(db,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(fd)
    with closing(sqlite3.connect(db.as_uri()+"?mode=rw",uri=True,
                                 isolation_level=None)) as con:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=FULL")
        con.execute(DDL)
        con.execute(FLOOR_DDL)
        con.execute("INSERT INTO monotonic_floor VALUES(1,0,?)",(HEAD_ZERO,))
    return {"status":"NEW_EMPTY_WITNESS_PROVISIONED_OFFLINE","epoch":0}

def _existing_db(root):
    db=_private_file(root,DB_NAME,max_size=128_000_000)
    con=sqlite3.connect(db.as_uri()+"?mode=rw",uri=True,
                        isolation_level=None,timeout=5)
    try:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA busy_timeout=5000")
        for name,ddl in (("reservations",DDL),("monotonic_floor",FLOOR_DDL)):
            found=con.execute(
                "SELECT sql FROM sqlite_master WHERE name=? AND type='table'",
                (name,)).fetchone()
            if found!=(ddl,):
                _fail("remote ledger schema absent or changed")
        if con.execute("PRAGMA quick_check").fetchall()!=[("ok",)]:
            _fail("remote ledger integrity invalid")
        floor=con.execute(
            "SELECT external_epoch,ledger_head FROM monotonic_floor "
            "WHERE singleton=1").fetchone()
        tip=con.execute("SELECT external_epoch,ledger_head FROM reservations "
                        "ORDER BY external_epoch DESC LIMIT 1").fetchone()
        if floor is None or floor!=(tip if tip else (0,HEAD_ZERO)):
            _fail("highwater counter/reservation tip mismatch")
    except Exception:
        con.close()
        raise
    return con

def _signed_receipt(root, claim, *, expected_source, expected_machine,
                    expected_package):
    now=int(time.time())
    validate_claim(claim,expected_source=expected_source,
                   expected_machine=expected_machine,
                   expected_package=expected_package,now=now)
    signer_raw=_private_file(root,"ed25519-signing.key",max_size=32).read_bytes()
    if len(signer_raw)!=32:
        _fail("witness key is not 32 bytes")
    signer=Ed25519PrivateKey.from_private_bytes(signer_raw)
    digest=sha256(_canon(claim)).hexdigest()
    with closing(_existing_db(root)) as con:
        con.execute("BEGIN IMMEDIATE")
        floor=con.execute(
            "SELECT external_epoch,ledger_head FROM monotonic_floor "
            "WHERE singleton=1").fetchone()
        if claim["external_epoch"]!=floor[0]+1:
            _fail("epoch must increase exactly by one, no replay or skip")
        head=sha256(bytes.fromhex(floor[1])+bytes.fromhex(digest)).hexdigest()
        con.execute(
            "INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)",
            (claim["external_epoch"],claim["task_id"],
             claim["operation_sha256"],claim["nonce"],digest,
             floor[1],head,now))
        updated=con.execute(
            "UPDATE monotonic_floor SET external_epoch=?,ledger_head=? "
            "WHERE singleton=1 AND external_epoch=? AND ledger_head=?",
            (claim["external_epoch"],head,floor[0],floor[1]))
        if updated.rowcount!=1:
            _fail("concurrent remote epoch mismatch")
        con.execute("COMMIT")
    receipt={
        "schema":ACK_SCHEMA,
        "status":"DURABLE_REMOTE_RESERVATION_NO_OS_EFFECT_AUTHORITY",
        "task_id":claim["task_id"],
        "external_epoch":claim["external_epoch"],
        "claim_sha256":digest,
        "ledger_head":head,
        "committed_unix":now,
        "expires_unix":min(now+90,claim["expires_unix"]),
        "automatic_retry_allowed":False,
        "production_effect_authorized":False,
    }
    raw=_canon(receipt)
    return {"receipt":receipt,
            "signature_base64":base64.b64encode(
                signer.sign(DOMAIN+raw)).decode("ascii")}

def read_only_status(root):
    with closing(_existing_db(root)) as con:
        epoch,head=con.execute(
            "SELECT external_epoch,ledger_head FROM monotonic_floor "
            "WHERE singleton=1").fetchone()
        count=con.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
    return {"epoch":epoch,"ledger_head":head,"reservations":count}

def _signed_readonly_status(root, request, *, expected_source,
                            expected_machine, expected_package):
    if (type(request) is not dict or
            set(request)!={"schema","nonce"} or
            request.get("schema")!=STATUS_REQ_SCHEMA or
            type(request.get("nonce")) is not str or
            not HEX32.fullmatch(request["nonce"])):
        _fail("read-only status request invalid")
    state=read_only_status(root)
    signing_bytes=_private_file(
        root,"ed25519-signing.key",max_size=32).read_bytes()
    if len(signing_bytes)!=32:
        _fail("status signing key missing")
    now=int(time.time())
    receipt={
        "schema":STATUS_ACK_SCHEMA,
        "status":"SIGNED_REMOTE_READ_ONLY_HIGHWATER",
        "nonce":request["nonce"],
        "epoch":state["epoch"],
        "ledger_head":state["ledger_head"],
        "reservations":state["reservations"],
        "source_sha40":expected_source,
        "machine_sha256":expected_machine,
        "package_sha256":expected_package,
        "recorded_unix":now,
        "expires_unix":now+30,
        "production_release_attested":False,
    }
    signer=Ed25519PrivateKey.from_private_bytes(signing_bytes)
    return {
        "receipt":receipt,
        "signature_base64":base64.b64encode(
            signer.sign(STATUS_DOMAIN+_canon(receipt))
        ).decode("ascii")
    }


def forced_ssh_main(root,*,expected_source,expected_machine,expected_package):
    if (os.name!="posix" or os.geteuid()==0 or
            os.environ.get("SSH_ORIGINAL_COMMAND")):
        _fail("no shell and no arbitrary SSH commands permitted")
    incoming=sys.stdin.buffer.read(4097)
    if not 60<=len(incoming)<=4096:
        _fail("one bounded request required")
    claim=json.loads(incoming.decode("ascii"),object_pairs_hook=_unique)
    if type(claim) is dict and claim.get("schema")==STATUS_REQ_SCHEMA:
        return _signed_readonly_status(
            root,claim,expected_source=expected_source,
            expected_machine=expected_machine,
            expected_package=expected_package)
    return _signed_receipt(root,claim,
                           expected_source=expected_source,
                           expected_machine=expected_machine,
                           expected_package=expected_package)

if __name__=="__main__":
    # Exactly one operator-installed ASCII pin config. Do not derive signing
    # authority, machine, release or transport from SSH client JSON.
    if len(sys.argv)!=2:
        raise SystemExit("configured witness root required")
    try:
        base=Path(sys.argv[1])
        policy_path=_private_file(base,"operator-scope.json",max_size=4096)
        policy=json.loads(policy_path.read_text("ascii"),object_pairs_hook=_unique)
        if (type(policy) is not dict or set(policy)!=
            {"schema","source_sha40","machine_sha256","package_sha256"} or
            policy["schema"]!="nf.personal.highwater.pinned_scope.v1" or
            not HEX40.fullmatch(policy["source_sha40"]) or
            not HEX64.fullmatch(policy["machine_sha256"]) or
            not HEX64.fullmatch(policy["package_sha256"])):
            _fail("pinned operator scope invalid")
        ack=forced_ssh_main(base,expected_source=policy["source_sha40"],
            expected_machine=policy["machine_sha256"],
            expected_package=policy["package_sha256"])
        print(_canon(ack).decode("ascii"),flush=True)
    except (PersonalHighwaterDenied,ValueError,UnicodeError,OSError,
            sqlite3.Error,KeyError,TypeError):
        print('{"status":"UNKNOWN_NO_AUTO_RETRY"}',flush=True)
        raise SystemExit(1)
