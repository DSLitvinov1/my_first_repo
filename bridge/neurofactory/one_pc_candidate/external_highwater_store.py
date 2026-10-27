"""Durable external witness reservation backend, for a SEPARATE trusted node.

This is a SQLite monotonic epoch + per-operation no-replay backend; it can
produce the exact signed evidence expected by independent_witness_receipt.
It never creates a signing key, installs a service, serves a network socket,
or claims the local disk is physically independent. Production deployment
MUST provide separate machine/storage custody, mTLS identity enforcement,
real owner/reviewer permits and signed operator-approved release scope.

A reservation is irreversible even when the client loses the reply: UNKNOWN,
NO AUTO RETRY. There is intentionally no rollback/reset/delete API.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
import stat
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from independent_witness_receipt import _claim, _canonical, _DOMAIN

class HighwaterStoreDenied(ValueError):
    pass

def _deny(reason):
    raise HighwaterStoreDenied("Independently operated witness denied: "+reason)

def _file(path):
    if not isinstance(path,Path) or not path.is_absolute() or path.is_symlink():
        _deny("operator-pinned absolute database path required")
    if not path.exists() or not path.is_file():
        _deny("database must already be provisioned by an independent administrator")
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode):
        _deny("nonregular witness database")
    if os.name=="posix" and (st.st_uid!=os.geteuid() or st.st_mode&0o077):
        _deny("untrusted ownership or broad permissions on witness state")
    if os.name=="nt" and st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        _deny("witness database reparse point")
    return path

def _parent(path):
    if path.parent.is_symlink() or not path.parent.is_dir():
        _deny("witness parent missing or linked")
    if os.name=="posix":
        st=path.parent.stat()
        if st.st_uid!=os.geteuid() or st.st_mode&0o077:
            _deny("witness directory not privately owned")

def provision_empty_database(path):
    """Independent operator action. Never called by receiver/CORE/model."""
    if not isinstance(path,Path) or not path.is_absolute() or path.exists():
        _deny("operator must provide new absolute empty state path")
    _parent(path)
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(fd)
    db=sqlite3.connect(path)
    try:
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.executescript("""
            CREATE TABLE counter(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
              highest_epoch INTEGER NOT NULL CHECK(highest_epoch>=0));
            INSERT INTO counter(singleton,highest_epoch) VALUES(1,0);
            CREATE TABLE reservations(
              claim_sha256 TEXT PRIMARY KEY,
              operation_sha256 TEXT NOT NULL UNIQUE,
              nonce TEXT NOT NULL UNIQUE,
              source_sha40 TEXT NOT NULL,
              machine_identity_sha256 TEXT NOT NULL,
              epoch INTEGER NOT NULL UNIQUE,
              reserved_unix INTEGER NOT NULL);
            """)
        db.commit()
    finally:
        db.close()
    os.chmod(path,0o600)
    return {"status":"EMPTY_EXTERNAL_NODE_DATABASE_CREATED_NO_TRUST_OR_AUTHORITY"}

def reserve_external_epoch(*, database:Path, claim:dict,
                            private_witness_signer,
                            operator_pinned_witness_id:str,
                            operator_pinned_machine_identity_sha256:str,
                            operator_pinned_package_sha256:str,
                            operator_pinned_source_sha40:str,
                            now_unix:int):
    """Durably reserve the next highwater epoch then independently sign ACK.

    This is callable ONLY by an authenticated remote witness server after
    separately verifying its mTLS client identity and authorized scope.
    The caller cannot furnish signing keys or pins from the same network
    request. Private signing key must come from trusted HSM/operator custody.
    """
    raw=_claim(claim)
    if (not isinstance(private_witness_signer,Ed25519PrivateKey) or
        type(operator_pinned_witness_id) is not str or
        not 3<=len(operator_pinned_witness_id)<=96 or
        any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
            for c in operator_pinned_witness_id) or
        claim["machine_identity_sha256"]!=operator_pinned_machine_identity_sha256 or
        claim["package_sha256"]!=operator_pinned_package_sha256 or
        claim["source_sha40"]!=operator_pinned_source_sha40 or
        type(now_unix) is not int or now_unix<=0):
        _deny("operator-provisioned release or machine identity mismatch")
    database=_file(database)
    _parent(database)
    con=sqlite3.connect(str(database),timeout=3,isolation_level=None)
    try:
        con.execute("PRAGMA busy_timeout=3000")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE")
        try:
            row=con.execute("SELECT highest_epoch FROM counter WHERE singleton=1").fetchone()
            if row is None or type(row[0]) is not int:
                _deny("missing independent monotonic counter")
            prior=row[0]
            if claim["external_epoch"]!=prior+1:
                _deny("remote monotonic epoch is not exactly next")
            h=sha256(raw).hexdigest()
            con.execute("""INSERT INTO reservations(
                  claim_sha256,operation_sha256,nonce,source_sha40,
                  machine_identity_sha256,epoch,reserved_unix)
                  VALUES(?,?,?,?,?,?,?)""",
                (h,claim["operation_sha256"],claim["nonce"],
                 claim["source_sha40"],claim["machine_identity_sha256"],
                 claim["external_epoch"],now_unix))
            if con.execute("UPDATE counter SET highest_epoch=? WHERE singleton=1 AND highest_epoch=?",
                           (claim["external_epoch"],prior)).rowcount!=1:
                _deny("monotonic fencing conflict")
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise
    except sqlite3.DatabaseError as exc:
        raise HighwaterStoreDenied("Witness state corruption or replay: refuse without retry") from exc
    finally:
        con.close()
    evidence={
        "schema":"nf.onepc.external_witness.highwater.v1",
        "claim_sha256":h,
        "source_sha40":claim["source_sha40"],
        "machine_identity_sha256":claim["machine_identity_sha256"],
        "witness_id":operator_pinned_witness_id,
        "highest_committed_epoch":claim["external_epoch"],
        "previous_accepted_epoch":prior,
        "recorded_unix":now_unix,
        "expires_unix":now_unix+60,
        "decision":"RECORDED_EXTERNALLY_NO_AUTO_RETRY",
        "separate_device_claimed":True,
    }
    raw_evidence=_canonical(evidence)
    signature=private_witness_signer.sign(_DOMAIN+raw_evidence)
    return {
        "evidence":evidence,
        "signature_base64":base64.b64encode(signature).decode("ascii"),
    }

def inspect_external_highwater(database:Path):
    database=_file(database)
    _parent(database)
    try:
        with sqlite3.connect(database.as_uri()+"?mode=ro",uri=True) as conn:
            row=conn.execute("SELECT highest_epoch FROM counter WHERE singleton=1").fetchone()
            count=conn.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
            if row is None or type(row[0]) is not int or type(count) is not int or count!=row[0]:
                _deny("counter and append-only entries disagree")
            return {
                "status":"REMOTE_OPERATOR_STORAGE_LOCAL_VIEW_NOT_HARDWARE_ATTESTED",
                "highest_committed_epoch":row[0],
                "reserved_operations":count,
                "remote_physical_independence_attested":False,
                "production_effects_authorized":False,
            }
    except sqlite3.DatabaseError as exc:
        raise HighwaterStoreDenied("Untrusted witness database") from exc
