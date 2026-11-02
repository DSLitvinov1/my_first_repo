"""Recipient-side CORE CLAIMED scope guard for disposable restricted Windows SCM.

The OWNER signature and real Windows peer SID are validated by the existing
named-pipe receiver BEFORE this guard is called. This guard binds the payload
to a separately administrator-pinned exact live CORE SQLite checkpoint.

A local read-only snapshot is NOT a recipient-side atomic effect lease, remote
monotonic witness, physical reviewer approval, or production authority.
This guard MUST NOT be used as a production release decision.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import time

from core_readonly_observer import observe_core, CoreObservationDenied

_SHA64 = re.compile(r"[a-f0-9]{64}\Z")
_SHA40 = re.compile(r"[a-f0-9]{40}\Z")
_OWNER = re.compile(r"[A-Za-z0-9_-]{1,50}\Z")
_TARGET = "bridge/neurofactory/development/core_owned/windows_pilot.txt"


class ScmRecipientScopeDenied(ValueError):
    pass


def _deny():
    raise ScmRecipientScopeDenied(
        "SCM recipient CORE claimed scope unavailable; NO FILE EFFECT OR AUTO RETRY"
    )


def assert_recipient_core_claim(*, core_state: Path, body: dict,
                                expected_spec_sha256: str,
                                expected_payload_sha256: str,
                                expected_owner: str, now_unix: int | None = None):
    """CI-only, operator-pinned, fail-closed recipient-side readback.

    No request may provide or override any expected_* value or core_state.
    The actual effect receiver calls this both before a durable UNKNOWN marker
    and immediately before the fixed CREATE_NEW test file operation.
    """
    if (os.name != "nt" and os.environ.get("NF_RECIPIENT_CORE_GUARD_UNIT_TEST") != "1"):
        _deny()
    if (type(body) is not dict or not isinstance(core_state, Path)
            or not core_state.is_absolute() or core_state.is_symlink()
            or type(expected_spec_sha256) is not str
            or not _SHA64.fullmatch(expected_spec_sha256)
            or type(expected_payload_sha256) is not str
            or not _SHA64.fullmatch(expected_payload_sha256)
            or type(expected_owner) is not str
            or not _OWNER.fullmatch(expected_owner)):
        _deny()
    if (type(body.get("task_id")) is not str
            or type(body.get("project_id")) is not str
            or type(body.get("source_sha40")) is not str
            or not _SHA40.fullmatch(body["source_sha40"])
            or body.get("target") != _TARGET
            or body.get("operation_id") != "pilot-" + body["task_id"]
            or body.get("content_sha256") != expected_payload_sha256):
        _deny()
    current = int(time.time())
    # Never let a worker supply a stale clock to stretch a real lease.
    if now_unix is not None and (type(now_unix) is not int
                                 or abs(current - now_unix) > 5):
        _deny()
    if current <= 0:
        _deny()
    try:
        obs = observe_core(core_state)
    except (CoreObservationDenied, OSError, ValueError):
        _deny()
    task = obs.get("task")
    if (obs.get("configured") is not True
            or obs.get("reported_state") != "CLAIMED"
            or obs.get("execution_allowed") is not False
            or obs.get("independently_verified") is not False
            or type(task) is not dict
            or task.get("task_id") != body["task_id"]
            or task.get("project_id") != body["project_id"]
            or task.get("source_sha40") != body["source_sha40"]
            or task.get("core_spec_sha256") != expected_spec_sha256
            or task.get("attempts") != 1
            or task.get("local_spec_digest_consistent") is not True
            or task.get("has_local_result_digest") is not False
            or task.get("has_local_receipt") is not False
            or type(task.get("lease_until")) is not int
            or not current < task["lease_until"] <= current + 3600):
        _deny()
    # The observer deliberately does not expose the worker token or name.
    # The service may read only the preprovisioned persistent queue; it must
    # separately assert the operator-pinned claimant and cannot trust a caller.
    import sqlite3
    from contextlib import closing
    db = core_state / "queue.sqlite3"
    try:
        with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True,
                                     timeout=2)) as conn:
            conn.execute("PRAGMA query_only=ON")
            owner, state, task_id = conn.execute(
                "SELECT owner,state,task_id FROM single_job WHERE singleton=1"
            ).fetchone()
    except (sqlite3.Error, OSError, ValueError, TypeError):
        _deny()
    if owner != expected_owner or state != "CLAIMED" or task_id != body["task_id"]:
        _deny()
    return {
        "status": "SCM_CORE_SCOPE_MATCHES_ADMIN_PIN_TEST_ONLY",
        "signed_payload_digest_matched": True,
        "core_claim_observed_locally": True,
        "recipient_effect_transaction_attested": False,
        "external_witness_verified": False,
        "production_execution_allowed": False,
    }
