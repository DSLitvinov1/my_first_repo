"""Local operator-only audit of signed restricted-SCM HOST checkpoints.

SQLite WAL + hash-chain detects incidental corruption / post-checkpoint edits.
It is not an externally anchored tamper-proof log or external high-water;
a privileged operator could replace the entire DB. A production deployment
MUST get a separate, fresh, independently stored witness acknowledgement.

Never records model text, raw owner/host private keys or live task effects.
Appending is allowed only *after* the trusted CORE has finalized a signed
HOST result, and only for a limited inert CI test on one disposable machine.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3

_HEX64=re.compile(r"[a-f0-9]{64}\Z")
_HEX40=re.compile(r"[a-f0-9]{40}\Z")
_TASK=re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_EVENT_FIELDS=frozenset({
    "schema","task_id","source_sha40","proposal_sha256",
    "result_sha256","receipt_sha256","operation_id","checkpoint_state",
})
_ZERO="0"*64
_DOMAIN=b"NF_ONEPC_LOCAL_SCM_AUDIT_CHAIN_V1\x00"

class LocalAuditDenied(ValueError):
    pass

def _deny(why):
    raise LocalAuditDenied("Local HOST audit refused: "+why)

def _canonical(body):
    try:
        return json.dumps(body,sort_keys=True,separators=(",",":"),
                          allow_nan=False,ensure_ascii=True).encode("ascii")
    except (TypeError,ValueError,RecursionError) as e:
        raise LocalAuditDenied("Local HOST audit invalid canonical JSON") from e

def _validate(event):
    if type(event) is not dict or set(event)!=_EVENT_FIELDS:
        _deny("event field set mismatch")
    if (event["schema"]!="nf.onepc.local_host_checkpoint.v1" or
        type(event["task_id"]) is not str or not _TASK.fullmatch(event["task_id"]) or
        type(event["source_sha40"]) is not str or not _HEX40.fullmatch(event["source_sha40"]) or
        any(type(event[k]) is not str or not _HEX64.fullmatch(event[k])
            for k in ("proposal_sha256","result_sha256","receipt_sha256")) or
        type(event["operation_id"]) is not str or
        event["operation_id"]!="pilot-"+event["task_id"] or
        event["checkpoint_state"]!="HOST_CHECKPOINTED_TEST"):
        _deny("only approved signed HOST test checkpoint is journalable")
    raw=_canonical(event)
    if len(raw)>1200:
        _deny("event too large")
    return raw

def _location(path):
    if not isinstance(path,Path) or not path.is_absolute() or path.is_symlink() or (
        path.exists() and (not path.is_file() or path.stat().st_size>1_000_000)
    ):
        _deny("unsafe journal filesystem location")
    return path

def _connect(path):
    db=sqlite3.connect(str(_location(path)),timeout=5,isolation_level=None)
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("""CREATE TABLE IF NOT EXISTS checkpoints (
        seq INTEGER PRIMARY KEY NOT NULL,
        task_id TEXT NOT NULL UNIQUE,
        previous_sha256 TEXT NOT NULL,
        record_json TEXT NOT NULL,
        record_sha256 TEXT NOT NULL UNIQUE
    )""")
    return db

def _rows(conn):
    return list(conn.execute("SELECT seq,task_id,previous_sha256,record_json,record_sha256 FROM checkpoints ORDER BY seq"))

def _verify(rows):
    prev=_ZERO
    seen=set()
    for seq,task,pre,body,h in rows:
        if type(seq) is not int or seq<=0 or seq!=len(seen)+1 or task in seen or pre!=prev:
            _deny("journal order/replay/previous digest invalid")
        try:
            value=json.loads(body)
        except (ValueError,TypeError) as e:
            raise LocalAuditDenied("Local HOST audit corrupt JSON") from e
        raw=_validate(value)
        if body!=raw.decode("ascii") or task!=value["task_id"]:
            _deny("noncanonical content")
        expected=sha256(_DOMAIN+seq.to_bytes(8,"big")+bytes.fromhex(prev)+raw).hexdigest()
        if h!=expected:
            _deny("hash chain mismatch")
        seen.add(task)
        prev=h
    return {"schema":"nf.onepc.local_scm_journal_audit.v1",
            "status":"LOCAL_CHAIN_VERIFIED_NOT_EXTERNALLY_ATTESTED",
            "entries":len(rows),"head_sha256":prev,
            "production_released":False,
            "external_highwater_attested":False,
            "physical_owner_machine_accepted":False}

def inspect(path):
    path=_location(path)
    if not path.is_file():
        _deny("existing journal required")
    db=_connect(path)
    try:
        return _verify(_rows(db))
    finally:
        db.close()

def append_after_core_checkpoint(path,event,*,actual_core_state):
    """Enforce already finalized state, atomic one-time per task insertion."""
    raw=_validate(event)
    if actual_core_state!="HOST_CHECKPOINTED_TEST":
        _deny("CORE did not actually durably verify signed HOST receipt")
    db=_connect(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        try:
            rows=_rows(db)
            prior=_verify(rows)
            if any(task==event["task_id"] for _,task,_,_,_ in rows):
                _deny("duplicate owner-approved task/receipt")
            seq=len(rows)+1
            prev=prior["head_sha256"]
            h=sha256(_DOMAIN+seq.to_bytes(8,"big")+bytes.fromhex(prev)+raw).hexdigest()
            db.execute(
                "INSERT INTO checkpoints (seq,task_id,previous_sha256,record_json,record_sha256) VALUES (?,?,?,?,?)",
                (seq,event["task_id"],prev,raw.decode("ascii"),h))
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
        result=inspect(path)
        if result["entries"]!=seq or result["head_sha256"]!=h:
            _deny("journal durability mismatch")
        return result
    finally:
        db.close()
