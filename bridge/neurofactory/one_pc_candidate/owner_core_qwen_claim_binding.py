"""Bind real owner-signed Qwen project file and owner-signed CORE admission to
the EXISTING OneTaskCore SQLite CLAIMED record. No execution authority.

This read-only observer is a PRECONDITION only: a Windows CORE SQLite snapshot
is NOT an atomic service-side fence or an authenticated HOST completion receipt.
Do not use this alone as authorization for a filesystem effect or Linux epoch.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core_readonly_observer import observe_core, CoreObservationDenied
from personal_approve_workspace_draft import owner_approvable_saved_draft
from personal_windows_host_service import _signed_body
from signed_owner_admission import (
    verify_owner_permit, prepare_draft_request, AdmissionDenied, _canon,
)

_CORE_TARGET = "bridge/neurofactory/development/core_owned/windows_pilot.txt"
_WORKER = re.compile(r"[A-Za-z0-9_-]{1,50}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")


class CoreQwenBindingDenied(ValueError):
    """One of the two owner approvals or real CORE CLAIMED snapshot is absent."""


def _deny(reason):
    raise CoreQwenBindingDenied("No CORE/Qwen/HOST precondition: " + reason)


class _ReadOnlyWorkspace:
    """Use SQLite mode=ro; never initialize an alternative user workspace."""

    def __init__(self, path):
        self.path = path

    @contextmanager
    def connect(self):
        file = self.path / "workspace.sqlite3"
        if file.is_symlink() or not file.is_file():
            _deny("existing SQLite workspace required")
        with closing(sqlite3.connect(file.as_uri() + "?mode=ro",
                                     uri=True, timeout=3)) as con:
            con.execute("PRAGMA query_only=ON")
            yield con


def check_signed_personal_core_claim(
    *, workspace_dir: Path, protected_core_state: Path,
    file_packet: dict, core_owner_permit: dict,
    owner_public_raw: bytes, expected_operator: dict,
    expected_core_worker: str,
):
    """Read-only exact cross-check. DO NOT use result as execution authority.

    All operator expectations come from protected non-HTTP configuration.
    The signed permits come from a human-owned Windows private key. An
    already admitted real OneTaskCore durable claim is mandatory.
    """
    if (not isinstance(workspace_dir, Path)
            or not workspace_dir.is_absolute() or workspace_dir.is_symlink()
            or not isinstance(protected_core_state, Path)
            or not protected_core_state.is_absolute()
            or protected_core_state.is_symlink()
            or type(owner_public_raw) is not bytes
            or len(owner_public_raw) != 32
            or type(expected_operator) is not dict
            or set(expected_operator) != {
                "source_sha40", "machine_sha256", "package_sha256"}
            or type(expected_core_worker) is not str
            or not _WORKER.fullmatch(expected_core_worker)):
        _deny("required operator-pinned principals absent")
    try:
        owner = Ed25519PublicKey.from_public_bytes(owner_public_raw)
        now = int(time.time())
        # Service validates the installed release and human file signature.
        file_body = _signed_body(file_packet, expected_operator, owner, now)
        qwen = owner_approvable_saved_draft(workspace_dir, file_body["task_id"])
        if (file_body["project_id"] != qwen["project_id"]
                or file_body["text"] != qwen["text"]
                or file_body["content_sha256"] != qwen["text_sha256"]
                or file_body["core_permission"]["draft_sha256"] != qwen["text_sha256"]):
            _deny("human-signed file differs from actual Qwen SQLite proposal")
        # Separately signed and independently replay-checked strict CORE
        # admission must bind the same draft, project, source, and model.
        snapshot = prepare_draft_request(
            _ReadOnlyWorkspace(workspace_dir), qwen["task_id"])
        spec = verify_owner_permit(
            core_owner_permit, owner_public_raw=owner_public_raw,
            expected_draft=snapshot, now=now)
        if (spec["project_id"] != "p-" + qwen["project_id"]
                or spec["objective"] != qwen["objective"]
                or spec["model"] != file_body["core_permission"]["model"]
                or spec["source_sha"] != file_body["source_sha40"]
                or spec["target"] != _CORE_TARGET):
            _deny("distinct OWNER signatures not bound to same Qwen and CORE scope")
        spec_sha = sha256(_canon(spec)).hexdigest()
        # Existing strict CORE observer validates actual SQLite schema,
        # canonical spec digest, task id, state and claim shape.
        first = observe_core(protected_core_state)
        task = first.get("task")
        if (first.get("reported_state") != "CLAIMED"
                or first.get("execution_allowed") is not False
                or first.get("independently_verified") is not False
                or type(task) is not dict
                or task.get("core_spec_sha256") != spec_sha
                or task.get("task_id") != spec["task_id"]
                or task.get("project_id") != spec["project_id"]
                or task.get("model") != spec["model"]
                or task.get("source_sha40") != spec["source_sha"]
                or task.get("attempts") != 1
                or task.get("has_local_receipt") is not False
                or task.get("has_local_result_digest") is not False
                or type(task.get("lease_until")) is not int
                or not now < task["lease_until"] <= now + 3600):
            _deny("CORE has no exact live CLAIMED one-task lease")
        # Worker ownership comes from protected operator config, not permit.
        db = protected_core_state / "queue.sqlite3"
        if db.is_symlink() or not db.is_file():
            _deny("CORE durable checkpoint missing")
        with closing(sqlite3.connect(db.as_uri() + "?mode=ro",
                                     uri=True, timeout=3)) as con:
            con.execute("PRAGMA query_only=ON")
            row = con.execute(
                "SELECT owner,state,task_id FROM single_job WHERE singleton=1"
            ).fetchone()
        if row != (expected_core_worker, "CLAIMED", spec["task_id"]):
            _deny("operator-pinned worker not lease claimant")
        # A second snapshot catches ordinary concurrent changes. This is NOT
        # an OS atomic lease or permission to execute a file.
        second = observe_core(protected_core_state)
        if second != first:
            _deny("CORE state changed during read-only verification")
        return {
            "schema": "nf.personal.owner_qwen_core_claim_readonly.v1",
            "core_task_id": spec["task_id"],
            "qwen_task_uuid": qwen["task_id"],
            "project_uuid": qwen["project_id"],
            "content_sha256": qwen["text_sha256"],
            "core_spec_sha256": spec_sha,
            "core_claimed_by_pinned_worker": True,
            "signed_owner_core_admission_verified": True,
            "signed_owner_file_permission_verified": True,
            "model": spec["model"],
            "execution_allowed": False,
            "external_witness_reserved": False,
            "recipient_atomic_completion_proven": False,
            "automatic_retry_allowed": False,
        }
    except (AdmissionDenied, CoreObservationDenied, sqlite3.Error,
            ValueError, TypeError, KeyError, OSError) as exc:
        raise CoreQwenBindingDenied(
            "Untrusted, expired or inconsistent CORE/Qwen permit; NO EFFECT"
        ) from exc
