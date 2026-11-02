"""Durable NO-RETRY reservation barrier for the existing signed HOST witness bridge.

A reservation row is FULL-synced to a private SQLite file *before* the first
remote network request. Every reservation, including acknowledged requests,
remains permanently in UNKNOWN/NO_AUTO_RETRY state: a new process, crashed
service, lost TLS ACK or duplicate caller may never repeat the remote request.

IMPORTANT: the directory MUST be owned/ACL-sealed independently by a Windows
operator. This code alone does not attest SID, ACL, trusted directory,
physical witness independence, protected highwater, or service release.
The runtime NEVER creates or repairs a missing DB; an authorized operator
must explicitly provision it before running any bridge request.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from contextlib import closing

class AttemptLedgerDenied(ValueError):
    pass

def _deny():
    raise AttemptLedgerDenied("HOST durable attempt unavailable, ambiguous or replayed; NO AUTO RETRY")

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_DB_BYTES = 32 * 1024 * 1024
FILENAME = "signed-witness-attempts.sqlite3"
_SCHEMA_SQL = """CREATE TABLE attempts (
            task_id TEXT NOT NULL UNIQUE,
            operation_sha256 TEXT NOT NULL UNIQUE,
            nonce TEXT NOT NULL UNIQUE,
            source_sha40 TEXT NOT NULL,
            external_epoch INTEGER NOT NULL,
            scope_sha256 TEXT NOT NULL,
            disposition TEXT NOT NULL CHECK(disposition='UNKNOWN_NO_AUTO_RETRY'),
            UNIQUE(source_sha40,external_epoch)
        )"""

def _regular_unlinked(path, *, directory=False):
    try:
        if path.is_symlink():
            _deny()
        info = path.lstat()
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                _deny()
        elif not stat.S_ISREG(info.st_mode) or info.st_size > MAX_DB_BYTES:
            _deny()
        if os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            _deny()
    except (OSError, ValueError) as exc:
        raise AttemptLedgerDenied("HOST durable state path unavailable") from exc

def _check_folder(root):
    if not isinstance(root, Path) or not root.is_absolute():
        _deny()
    # A protected path is always pre-provisioned by the operator.
    # Do not auto-create directories that might be user-controlled.
    _regular_unlinked(root, directory=True)
    if root.parent == root:
        _deny()
    return root / FILENAME

def provision_empty_attempt_ledger_offline(operator_folder):
    """Operator-only, explicit one-time provisioning; NEVER call from HOST.

    An absent database is NOT automatically recreated by the service. An
    independently authorized operator must separately verify source, owner,
    ACL/DACL, and restore policy before calling this in a protected directory.
    After creation Windows operator must verify sealed DACL for the SQLite
    database and parent directory. This code does not grant OS privileges.
    """
    path = _check_folder(operator_folder)
    if path.exists() or path.is_symlink():
        _deny()
    try:
        flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os,"O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd=os.open(path,flags,0o600)
        os.close(fd)
        # The data file was created exclusively. On an ambiguous failure
        # leave it in place and refuse a second automatic provisioning.
        with closing(sqlite3.connect(path.as_uri()+"?mode=rw",uri=True,
                                     isolation_level=None,timeout=4.0)) as conn:
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(_SCHEMA_SQL)
        _regular_unlinked(path)
        return {"status":"OPERATOR_LEDGER_CREATED_NO_EXECUTION_AUTHORITY",
                "production_release_allowed":False}
    except (sqlite3.Error,OSError) as exc:
        raise AttemptLedgerDenied(
            "HOST ledger provisioning ambiguous; operator inspection required") from exc

def _connect(db_path):
    # Absolute fail-closed: a removed, truncated or reset SQLite file is
    # never silently recreated, even after a real Windows SCM restart.
    if not db_path.exists() or db_path.is_symlink():
        _deny()
    _regular_unlinked(db_path)
    if db_path.stat().st_size < 512:
        _deny()
    conn=None
    try:
        conn=sqlite3.connect(db_path.as_uri()+"?mode=rw",uri=True,
                             isolation_level=None,timeout=4.0)
        conn.execute("PRAGMA busy_timeout=4000")
        if conn.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            _deny()
        conn.execute("PRAGMA synchronous=FULL")
        definition=conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='attempts'"
        ).fetchone()
        if definition is None or definition[0] != _SCHEMA_SQL:
            _deny()
        extra=conn.execute(
            "SELECT type,name FROM sqlite_master "
            "WHERE type IN ('table','view','trigger') AND name!='attempts'"
        ).fetchall()
        if extra:
            _deny()
        status=conn.execute("PRAGMA quick_check").fetchall()
        if status!=[("ok",)]:
            _deny()
        return conn
    except (sqlite3.Error,OSError,AttemptLedgerDenied) as exc:
        if conn is not None:
            conn.close()
        raise AttemptLedgerDenied(
            "HOST durable journal absent, damaged, or not operator provisioned") from exc

def reserve_attempt_once(folder, *, claim):
    """Return digest of one persistently recorded attempt, never permission."""
    if (type(claim) is not dict or
        type(claim.get("schema")) is not str or
        claim["schema"]!="nf.host.one_effect_scope.v1" or
        type(claim.get("task_id")) is not str or
        not 3<=len(claim["task_id"])<=90 or
        any(type(claim.get(k)) is not str or not HEX64.fullmatch(claim[k])
            for k in ("operation_sha256","nonce")) or
        type(claim.get("source_sha40")) is not str or
        not HEX40.fullmatch(claim["source_sha40"]) or
        type(claim.get("external_epoch")) is not int or
        not 1<=claim["external_epoch"]<2**63):
        _deny()
    try:
        raw=json.dumps(
            claim,sort_keys=True,separators=(",",":"),ensure_ascii=True,
            allow_nan=False).encode("ascii")
        if len(raw)>2500:
            _deny()
    except (ValueError,TypeError,RecursionError,UnicodeError) as exc:
        raise AttemptLedgerDenied("HOST durable scope is noncanonical") from exc
    digest=hashlib.sha256(raw).hexdigest()
    path=_check_folder(folder)
    conn=_connect(path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""INSERT INTO attempts
            (task_id,operation_sha256,nonce,source_sha40,external_epoch,
             scope_sha256,disposition)
             VALUES (?,?,?,?,?,?,'UNKNOWN_NO_AUTO_RETRY')""",(
            claim["task_id"],claim["operation_sha256"],claim["nonce"],
            claim["source_sha40"],claim["external_epoch"],digest,
        ))
        conn.execute("COMMIT")
    except sqlite3.Error as exc:
        try: conn.execute("ROLLBACK")
        except sqlite3.Error: pass
        raise AttemptLedgerDenied(
            "HOST remote effect attempt uncertain or already reserved; NO RETRY") from exc
    finally:
        conn.close()
    return {"status":"DURABLY_MARKED_UNKNOWN_NO_AUTO_RETRY",
            "scope_sha256":digest,
            "remote_request_not_yet_sent":True}
