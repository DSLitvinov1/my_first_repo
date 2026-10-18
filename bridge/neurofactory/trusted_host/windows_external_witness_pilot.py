"""Windows-compatible, TEST-ONLY, mTLS remote witness pilot, one call per process.

This module NEVER authorizes production file writes or starts a persistent
service. Requires disposable private test root and synthetic certificates/keys.
Its SQLite store is durable over server PROCESS restart, not independently
protected against local Administrator, disk cloning, or hardware rollback.
Production requires a separately managed physical trust domain and review.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import struct
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

class WitnessPilotDenied(ValueError):
    pass

def deny():
    raise WitnessPilotDenied("Windows external witness is unavailable or untrusted")

def canon(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        deny()

def digest(v):
    return hashlib.sha256(v).hexdigest()

HEX = re.compile(r"[0-9a-f]{64}\Z")
TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
OP = re.compile(r"[A-Za-z0-9_.:-]{3,90}\Z")
KEYS = frozenset(("schema", "scope_sha256", "task_id", "target_sha256",
                  "operation_id", "commit_sequence", "journal_root_sha256"))
LIMIT = 4096
DOMAIN = b"NF_WINDOWS_REMOTE_WITNESS_TEST_V1\x00"

def test_gate():
    if os.environ.get("NF_WINDOWS_WITNESS_TEST_ONLY") != "1":
        deny()

def check_claim(c):
    if (type(c) is not dict or set(c) != KEYS or
            c.get("schema") != "nf.windows.witness.reserve.test.v1" or
            type(c.get("commit_sequence")) is not int or
            not 1 <= c["commit_sequence"] <= 2**31 or
            type(c.get("task_id")) is not str or
            not TASK.fullmatch(c["task_id"]) or
            type(c.get("operation_id")) is not str or
            not OP.fullmatch(c["operation_id"]) or
            any(type(c.get(k)) is not str or not HEX.fullmatch(c[k])
                for k in ("scope_sha256", "target_sha256", "journal_root_sha256")) or
            len(canon(c)) > LIMIT):
        deny()
    return c

def require_test_root(root):
    root = Path(root)
    if (not root.is_absolute() or root.is_symlink() or
            root.parent.resolve() != Path(tempfile.gettempdir()).resolve() or
            not root.name.startswith("nf-witness-ci-") or not root.is_dir()):
        deny()
    if os.name == "nt" and root.stat().st_file_attributes & 0x400:
        deny()
    return root

def _database(root):
    db = sqlite3.connect(str(root / "reservations.sqlite3"), timeout=4,
                         isolation_level=None)
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("""CREATE TABLE IF NOT EXISTS witness_head(
        id INTEGER PRIMARY KEY CHECK(id=1),
        sequence INTEGER NOT NULL,
        root TEXT NOT NULL)""")
    db.execute("INSERT OR IGNORE INTO witness_head VALUES (1,0,?)", ("0"*64,))
    db.execute("""CREATE TABLE IF NOT EXISTS reservations(
        operation_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL UNIQUE,
        target_sha256 TEXT NOT NULL UNIQUE,
        scope_sha256 TEXT NOT NULL,
        sequence INTEGER NOT NULL UNIQUE,
        claim_sha256 TEXT NOT NULL,
        prior_root TEXT NOT NULL,
        next_root TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status='UNKNOWN_NO_AUTO_RETRY'))""")
    return db

def reserve_test_only(root, claim):
    test_gate()
    root = require_test_root(root)
    claim = check_claim(claim)
    db = _database(root)
    try:
        db.execute("BEGIN IMMEDIATE")
        seq, oldroot = db.execute(
            "SELECT sequence,root FROM witness_head WHERE id=1").fetchone()
        if (claim["commit_sequence"] <= seq or
                claim["journal_root_sha256"] != oldroot):
            deny()
        rawhash = digest(canon(claim))
        newroot = digest((oldroot + rawhash).encode("ascii"))
        db.execute("""INSERT INTO reservations(
            operation_id,task_id,target_sha256,scope_sha256,sequence,
            claim_sha256,prior_root,next_root,status)
            VALUES(?,?,?,?,?,?,?,?, 'UNKNOWN_NO_AUTO_RETRY')""",
            (claim["operation_id"],claim["task_id"],claim["target_sha256"],
             claim["scope_sha256"],claim["commit_sequence"],rawhash,oldroot,newroot))
        db.execute("UPDATE witness_head SET sequence=?,root=? WHERE id=1",
                   (claim["commit_sequence"],newroot))
        db.execute("COMMIT")   # FULL sync; cannot guarantee a physical power-cycle
    except (sqlite3.Error, WitnessPilotDenied) as e:
        try: db.execute("ROLLBACK")
        except sqlite3.Error: pass
        raise WitnessPilotDenied("duplicate, stale or uncertain witness reservation") from e
    finally:
        db.close()
    return {
        "status": "DURABLY_RESERVED_TEST_ONLY",
        "scope_sha256": claim["scope_sha256"],
        "operation_id": claim["operation_id"],
        "commit_sequence": claim["commit_sequence"],
        "journal_root_sha256": claim["journal_root_sha256"],
    }

def _recv_exact(s, count):
    result = bytearray()
    while len(result) < count:
        part = s.recv(count - len(result))
        if not part:
            deny()
        result.extend(part)
    return bytes(result)

def receive_frame(s):
    size = struct.unpack("!I", _recv_exact(s, 4))[0]
    if not 2 <= size <= LIMIT:
        deny()
    try:
        return json.loads(_recv_exact(s, size).decode("ascii"))
    except (ValueError, UnicodeError):
        deny()

def send_frame(s, value):
    raw = canon(value)
    if not 2 <= len(raw) <= LIMIT:
        deny()
    s.sendall(struct.pack("!I", len(raw)) + raw)

def fp(binary_cert):
    if type(binary_cert) is not bytes or len(binary_cert) < 128:
        deny()
    return digest(binary_cert)

def expected_fp(value):
    if type(value) is not str or not HEX.fullmatch(value):
        deny()

def tls_server_once(*, root, port, server_cert, server_key, ca_cert,
                    witness_key, pinned_client_cert_sha256, drop_ack=False):
    test_gate()
    require_test_root(root)
    if (type(port) is not int or not 1024 <= port <= 65535 or
            type(drop_ack) is not bool):
        deny()
    expected_fp(pinned_client_cert_sha256)
    key_data = Path(witness_key).read_bytes()
    if len(key_data) != 32:
        deny()
    signer = Ed25519PrivateKey.from_private_bytes(key_data)
    tlscontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tlscontext.minimum_version = ssl.TLSVersion.TLSv1_3
    tlscontext.load_cert_chain(server_cert, server_key)
    tlscontext.load_verify_locations(cafile=ca_cert)
    tlscontext.verify_mode = ssl.CERT_REQUIRED
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))  # never open a public network listener
        srv.listen(1)
        srv.settimeout(10)
        print("WITNESS_TEST_READY", flush=True)
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(5)
            with tlscontext.wrap_socket(conn, server_side=True) as tls:
                if fp(tls.getpeercert(binary_form=True)) != pinned_client_cert_sha256:
                    deny()
                request = receive_frame(tls)
                ack = reserve_test_only(root, request)
                if drop_ack:
                    return  # unknown reservation survived; forbid retry
                payload = {"ack": ack, "claim_sha256": digest(canon(request))}
                signature = signer.sign(DOMAIN + canon(payload))
                send_frame(tls, {"body": payload,
                                 "signature_base64": base64.b64encode(signature).decode("ascii")})

def request_test_once(*, port, claim, client_cert, client_key, ca_cert,
                      pinned_server_cert_sha256, pinned_witness_public_b64):
    test_gate()
    check_claim(claim)
    expected_fp(pinned_server_cert_sha256)
    if type(port) is not int or not 1024 <= port <= 65535:
        deny()
    try:
        key = base64.b64decode(pinned_witness_public_b64, validate=True)
        if len(key) != 32: deny()
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(client_cert, client_key)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            raw.settimeout(5)
            with context.wrap_socket(raw, server_hostname="nf-witness.test") as tls:
                if fp(tls.getpeercert(binary_form=True)) != pinned_server_cert_sha256:
                    deny()
                send_frame(tls, claim)
                response = receive_frame(tls)
        if type(response) is not dict or set(response) != {"body", "signature_base64"}:
            deny()
        body = response["body"]
        if (type(body) is not dict or
                set(body) != {"ack", "claim_sha256"} or
                body["claim_sha256"] != digest(canon(claim)) or
                type(body["ack"]) is not dict or
                set(body["ack"]) != {
                    "status","scope_sha256","operation_id",
                    "commit_sequence","journal_root_sha256"
                } or
                body["ack"] != {
                    "status": "DURABLY_RESERVED_TEST_ONLY",
                    "scope_sha256": claim["scope_sha256"],
                    "operation_id": claim["operation_id"],
                    "commit_sequence": claim["commit_sequence"],
                    "journal_root_sha256": claim["journal_root_sha256"]
                }):
            deny()
        sig = base64.b64decode(response["signature_base64"], validate=True)
        Ed25519PublicKey.from_public_bytes(key).verify(sig, DOMAIN+canon(body))
        return body["ack"]
    except (OSError, ssl.SSLError, ValueError, InvalidSignature, UnicodeError) as e:
        raise WitnessPilotDenied("mTLS witness failed; outcome unknown, NO RETRY") from e

def main():
    # Deliberately one-shot: no auto-start/installer or continuous service.
    if len(sys.argv) != 10 or sys.argv[1] != "serve-one-ci":
        return 3
    try:
        tls_server_once(
            root=sys.argv[2], port=int(sys.argv[3]),
            server_cert=sys.argv[4], server_key=sys.argv[5],
            ca_cert=sys.argv[6], witness_key=sys.argv[7],
            pinned_client_cert_sha256=sys.argv[8],
            drop_ack=sys.argv[9] == "drop")
        return 0
    except Exception:
        return 3

if __name__ == "__main__":
    sys.exit(main())
