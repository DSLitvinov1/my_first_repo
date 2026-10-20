"""Read-only, *unattested* projection of an EXISTING ONE-PC CORE SQLite checkpoint.

No CORE instance is created, no journal/backup is written, no owner keys or
worker tokens are returned. An explicit local CLI directory is the only input.
This is telemetry, NEVER proof that a HOST effect or Qwen output is approved.
"""
from __future__ import annotations

from contextlib import closing

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
_SHA40 = re.compile(r"[a-f0-9]{40}\Z")
_STATES = frozenset({
    "QUEUED", "CLAIMED", "APPLYING", "CHECKPOINTED_TEST",
    "HOST_CHECKPOINTED_TEST", "NEEDS_MANUAL_REVIEW",
})
_MODELS = frozenset((
    "qwen3:0.6b", "qwen3:4b", "qwen2.5-coder:7b",
    "qwen2.5-coder:1.5b",
))
_SPEC_FIELDS = frozenset((
    "schema", "task_id", "project_id", "target", "objective",
    "source_sha", "source_sha256", "model", "reserved_units",
    "approval_commit",
))
_COLUMNS = (
    "task_id", "spec", "spec_sha256", "state", "owner", "token_sha256",
    "attempts", "lease_until", "result_sha256", "receipt",
)


class CoreObservationDenied(ValueError):
    """Unavailable, invalid or untrusted CORE telemetry, no action authorized."""


def _private_dir(p):
    if not isinstance(p, Path) or not p.is_absolute() or p.is_symlink():
        raise CoreObservationDenied("Explicit absolute nonlinked CORE state directory required")
    if not p.is_dir():
        raise CoreObservationDenied("CORE directory unavailable")
    s = p.lstat()
    if not stat.S_ISDIR(s.st_mode):
        raise CoreObservationDenied("CORE directory invalid")
    if os.name == "nt":
        if s.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise CoreObservationDenied("CORE directory reparse point")
    elif s.st_mode & 0o077:
        raise CoreObservationDenied("CORE state directory not private")
    return p


def _unique(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise CoreObservationDenied("Duplicate CORE checkpoint field")
        obj[k] = v
    return obj


def _valid_spec(spec):
    return (
        type(spec) is dict
        and spec.keys() == _SPEC_FIELDS
        and spec.get("schema") == "neurofactory.core.task.v1"
        and type(spec.get("task_id")) is str and bool(_TASK.fullmatch(spec["task_id"]))
        and type(spec.get("project_id")) is str and bool(_PROJECT.fullmatch(spec["project_id"]))
        and type(spec.get("source_sha")) is str and bool(_SHA40.fullmatch(spec["source_sha"]))
        and type(spec.get("approval_commit")) is str and bool(_SHA40.fullmatch(spec["approval_commit"]))
        and type(spec.get("source_sha256")) is str and bool(_SHA.fullmatch(spec["source_sha256"]))
        and type(spec.get("model")) is str and spec["model"] in _MODELS
        and type(spec.get("target")) is str
        and spec["target"].startswith("bridge/neurofactory/development/core_owned/")
        and type(spec.get("objective")) is str and 25 <= len(spec["objective"]) <= 320
        and type(spec.get("reserved_units")) is int and 1 <= spec["reserved_units"] <= 100000
    )


def observe_core(state_dir):
    """Read SQLite using mode=ro; errors never imply permission to retry CORE work."""
    state_dir = _private_dir(Path(state_dir))
    db_file = state_dir / "queue.sqlite3"
    if db_file.is_symlink() or not db_file.is_file():
        raise CoreObservationDenied("CORE database unavailable")
    attr = db_file.lstat()
    if not stat.S_ISREG(attr.st_mode) or not 0 < attr.st_size <= 8_000_000:
        raise CoreObservationDenied("CORE checkpoint not a bounded regular file")
    if os.name == "nt":
        if attr.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise CoreObservationDenied("CORE database reparse point")
    elif attr.st_mode & 0o077:
        raise CoreObservationDenied("CORE database not private")
    # File URL is escaped, no caller-controlled query parameters or SQLite writes.
    uri = db_file.as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as conn:
            conn.execute("PRAGMA query_only=ON")
            info = conn.execute("PRAGMA table_info(single_job)").fetchall()
            columns = {row[1] for row in info}
            if not set(_COLUMNS).issubset(columns):
                raise CoreObservationDenied("CORE schema does not match")
            rows = conn.execute(
                "SELECT " + ",".join(_COLUMNS) +
                " FROM single_job WHERE singleton=1 LIMIT 2"
            ).fetchall()
            count = conn.execute("SELECT COUNT(*) FROM single_job").fetchone()[0]
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise CoreObservationDenied("Cannot safely observe CORE queue") from exc
    if count not in (0, 1) or len(rows) != count:
        raise CoreObservationDenied("Unexpected CORE queue cardinality")
    base = {
        "schema": "nf.core.readonly.local.v1",
        "configured": True,
        "available": True,
        "execution_allowed": False,
        "queue_mutation_allowed": False,
        "independently_verified": False,
        "core_result_attested": False,
        "source": "LOCAL_SQLITE_UNATTESTED",
    }
    if not rows:
        return {**base, "reported_state": "EMPTY", "task": None}
    (task_id, spec_json, spec_hash, state, owner, token, attempts,
     lease, result, receipt) = rows[0]
    if (type(spec_json) is not str or len(spec_json) > 4096
            or type(spec_hash) is not str or not _SHA.fullmatch(spec_hash)):
        raise CoreObservationDenied("Malformed CORE checkpoint")
    try:
        spec = json.loads(spec_json, object_pairs_hook=_unique)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise CoreObservationDenied("Unparseable CORE checkpoint") from exc
    canonical = json.dumps(spec, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
    if (not _valid_spec(spec)
            or task_id != spec["task_id"]
            or hashlib.sha256(canonical).hexdigest() != spec_hash
            or state not in _STATES
            or type(attempts) is not int or attempts not in (0, 1)):
        raise CoreObservationDenied("CORE snapshot identity or state invalid")
    if state == "QUEUED":
        if any(x is not None for x in (owner, token, lease, result, receipt)) or attempts != 0:
            raise CoreObservationDenied("CORE queued record has untrusted effect evidence")
    elif (attempts != 1 or type(owner) is not str or
          not re.fullmatch(r"[a-zA-Z0-9_-]{1,50}", owner) or
          type(token) is not str or not _SHA.fullmatch(token) or
          type(lease) is not int or lease < 0):
        raise CoreObservationDenied("CORE claimed record malformed")
    if result is not None and (type(result) is not str or not _SHA.fullmatch(result)):
        raise CoreObservationDenied("Invalid CORE result digest")
    if receipt is not None and (type(receipt) is not str or len(receipt) > 16384):
        raise CoreObservationDenied("Oversized or invalid CORE receipt")
    if state in ("CHECKPOINTED_TEST", "HOST_CHECKPOINTED_TEST") and (
            result is None or receipt is None):
        raise CoreObservationDenied("CORE checkpoint missing receipt")
    # NO TOKEN, OWNER, RAW SPEC, SIGNATURE, PATH OR RECEIPT bytes exposed.
    return {
        **base,
        "reported_state": state,
        "task": {
            "task_id": task_id,
            "project_id": spec["project_id"],
            "model": spec["model"],
            "attempts": attempts,
            "lease_until": lease,
            "local_spec_digest_consistent": True,
            "has_local_result_digest": result is not None,
            "has_local_receipt": receipt is not None,
        },
    }


def unavailable_core():
    return {
        "schema": "nf.core.readonly.local.v1",
        "configured": False,
        "available": False,
        "reported_state": "NOT_CONFIGURED",
        "task": None,
        "execution_allowed": False,
        "queue_mutation_allowed": False,
        "independently_verified": False,
        "core_result_attested": False,
        "source": "NO_EXPLICIT_CORE_STATE_DIRECTORY",
    }
