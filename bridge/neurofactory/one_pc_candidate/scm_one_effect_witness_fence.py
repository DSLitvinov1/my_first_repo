"""Durable Windows-recipient CORE + three-role signed remote witness interlock.

CI-only integration candidate. An existing operator-sealed SQLite fence
irreversibly consumes task/operation/nonce/epoch BEFORE contacting the remote
witness. A lost ACK, crash or expired lease is UNKNOWN and NEVER retried.

No distributed atomic commit or physical rollback guarantee: the local state,
witness ledger and filesystem are distinct trust domains. No real production
Windows file operation is authorized by this module.
"""
from __future__ import annotations

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import json
import os
import re
import sqlite3
import stat
import time

from protected_host_core_witness_binding import (
    bind_core_and_reserve_witness_once, exact_core_effect_sha256,
)
from protected_host_remote_bridge import OneShotHostWitnessBridge
from scm_recipient_core_claim_guard import assert_recipient_core_claim

_DB = "recipient-one-effect-intents.sqlite3"
_SCHEMA = """CREATE TABLE one_effect_intents (
    task_id TEXT NOT NULL UNIQUE,
    operation_sha256 TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL UNIQUE,
    external_epoch INTEGER NOT NULL UNIQUE,
    core_spec_sha256 TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('UNKNOWN_NO_AUTO_RETRY','ACK_OBSERVED_NO_EFFECT_AUTHORITY')),
    ack_observation_sha256 TEXT
)"""
_SHA64 = re.compile(r"[a-f0-9]{64}\Z")
_STATUS = "LOCAL_INTENT_AND_SIGNED_WITNESS_ACK_OBSERVED_LAB_ONLY"


class RecipientFenceDenied(ValueError):
    pass


class RecipientFenceUnknown(RuntimeError):
    pass


def _deny(message):
    raise RecipientFenceDenied("SCM recipient fenced intent denied: " + message)


def _root(path):
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        _deny("operator-pinned absolute nonlinked directory required")
    try:
        s = path.lstat()
    except OSError as exc:
        raise RecipientFenceDenied("sealed directory absent") from exc
    if not stat.S_ISDIR(s.st_mode):
        _deny("not a directory")
    if os.name == "nt":
        if s.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            _deny("Windows reparse point")
    elif s.st_mode & 0o077:
        _deny("nonprivate directory")
    return path


def provision_empty_recipient_fence_offline(operator_dir: Path):
    """Explicit *offline* provisioning only; never invoked by SCM runtime."""
    root = _root(operator_dir)
    db = root / _DB
    if db.exists() or db.is_symlink():
        _deny("no reset/overwrite of existing or ambiguous fence")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        handle = os.open(db, flags, 0o600)
        os.close(handle)
        with closing(sqlite3.connect(db.as_uri() + "?mode=rw",
                                     uri=True, isolation_level=None)) as con:
            con.execute("PRAGMA journal_mode=DELETE")
            con.execute("PRAGMA synchronous=FULL")
            con.execute(_SCHEMA)
    except (OSError, sqlite3.Error) as exc:
        # Never delete ambiguous partly provisioned state automatically.
        raise RecipientFenceDenied("offline fence provisioning ambiguous") from exc
    return {"status": "EMPTY_OPERATOR_FENCE_PROVISIONED_NO_EXECUTION"}


def _open_existing(root):
    db = _root(root) / _DB
    if db.is_symlink() or not db.is_file():
        _deny("missing durable fence: NEVER recreate")
    info = db.lstat()
    if not stat.S_ISREG(info.st_mode) or not 512 <= info.st_size <= 16_000_000:
        _deny("truncated, oversized or invalid fence")
    if os.name == "nt":
        if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            _deny("fence reparse point")
    elif info.st_mode & 0o077:
        _deny("fence file permissions")
    try:
        con = sqlite3.connect(db.as_uri() + "?mode=rw", uri=True,
                              timeout=5, isolation_level=None)
    except sqlite3.Error as exc:
        raise RecipientFenceDenied("durable fence open failed; NO RETRY") from exc
    try:
        con.execute("PRAGMA busy_timeout=5000")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA journal_mode=DELETE")
        found = con.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='one_effect_intents'").fetchone()
        if found is None or found[0] != _SCHEMA:
            _deny("fence schema replaced")
        if con.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            _deny("fence corrupt")
    except Exception:
        con.close()
        raise
    return con


class OneShotScmRecipientFence:
    """Construct only from independently installed, administrator-pinned inputs.

    A service caller must validate real Windows token/ACL and owner signature
    before invocation. This class independently requires the actual signed
    OWNER+REVIEWER+WITNESS bridge and exact live CORE claim.
    """

    def __init__(self, *, operator_fence_dir: Path, core_state: Path,
                 expected_spec_sha256: str, expected_payload_sha256: str,
                 expected_owner: str, bridge: OneShotHostWitnessBridge):
        if (not isinstance(operator_fence_dir, Path)
                or not isinstance(core_state, Path)
                or type(expected_spec_sha256) is not str
                or not _SHA64.fullmatch(expected_spec_sha256)
                or type(expected_payload_sha256) is not str
                or not _SHA64.fullmatch(expected_payload_sha256)
                or type(expected_owner) is not str
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,50}", expected_owner)
                or not isinstance(bridge, OneShotHostWitnessBridge)):
            _deny("invalid operator-installed pins or cryptographic bridge")
        self._dir = operator_fence_dir
        self._state = core_state
        self._spec = expected_spec_sha256
        self._payload = expected_payload_sha256
        self._owner = expected_owner
        self._bridge = bridge
        self._spent = False

    def _live_claim(self, body):
        observed = assert_recipient_core_claim(
            core_state=self._state, body=body,
            expected_spec_sha256=self._spec,
            expected_payload_sha256=self._payload,
            expected_owner=self._owner)
        if (observed.get("status") != "SCM_CORE_SCOPE_MATCHES_ADMIN_PIN_TEST_ONLY"
                or observed.get("production_execution_allowed") is not False):
            _deny("recipient CORE authorization unexpectedly permissive")

    def reserve_once(self, *, body, claim, owner_signature,
                     reviewer_signature, witness_claim):
        if self._spent:
            raise RecipientFenceUnknown("one-shot instance already used; NO RETRY")
        if (type(body) is not dict or type(claim) is not dict
                or type(witness_claim) is not dict
                or claim.get("task_id") != body.get("task_id")
                or claim.get("project_id") != body.get("project_id")
                or claim.get("source_sha40") != body.get("source_sha40")
                or claim.get("payload_sha256") != self._payload
                or claim.get("operation_sha256") != exact_core_effect_sha256(
                    self._spec, self._payload)
                or type(claim.get("nonce")) is not str
                or not _SHA64.fullmatch(claim["nonce"])
                or type(claim.get("external_epoch")) is not int
                or not 1 <= claim["external_epoch"] < 2**63
                or any(witness_claim.get(k) != claim.get(k) for k in
                       ("operation_sha256", "external_epoch", "nonce",
                        "source_sha40", "package_sha256",
                        "machine_identity_sha256", "review_evidence_sha256"))):
            _deny("CORE, payload and signed remote witness scope not bound")
        self._live_claim(body)
        # This permanent local intent consumes the operation BEFORE network.
        # A failed COMMIT has UNKNOWN status, never retry or delete to repair.
        self._spent = True
        try:
            with closing(_open_existing(self._dir)) as con:
                con.execute("BEGIN IMMEDIATE")
                con.execute(
                    "INSERT INTO one_effect_intents (task_id,operation_sha256,"
                    "nonce,external_epoch,core_spec_sha256,payload_sha256,"
                    "disposition,ack_observation_sha256) VALUES (?,?,?,?,?,?,'UNKNOWN_NO_AUTO_RETRY',NULL)",
                    (claim["task_id"], claim["operation_sha256"],
                     claim["nonce"], claim["external_epoch"],
                     self._spec, self._payload))
                con.execute("COMMIT")
        except (sqlite3.Error, OSError, RecipientFenceDenied) as exc:
            raise RecipientFenceUnknown("local intent missing, replayed or ambiguous; NO RETRY") from exc
        # Existing bridge separately FULL-syncs its own attempt ledger
        # before one TLS request and verifies real Ed25519 OWNER/REVIEWER and
        # WITNESS signatures. An ACK is never accepted as production approval.
        try:
            now = int(time.time())
            verified = bind_core_and_reserve_witness_once(
                core_state_dir=self._state, bridge=self._bridge,
                claim=claim, owner_signature=owner_signature,
                reviewer_signature=reviewer_signature,
                witness_claim=witness_claim, now_unix=now)
            if (verified.get("status") !=
                    "LOCAL_CORE_SCOPE_MATCHED_AND_SIGNED_REMOTE_ACK_TEST_NO_EFFECT"
                    or verified.get("production_file_effects_allowed") is not False
                    or verified.get("automatic_retry_allowed") is not False
                    or verified.get("external_epoch") != claim["external_epoch"]):
                raise RecipientFenceUnknown("unexpected external scope observation")
            self._live_claim(body)
            # Evidence digest is only a local diagnostic: the cryptographic
            # signed ACK was verified inside the bridge, not this local DB.
            data = json.dumps(verified, sort_keys=True, separators=(",",":"),
                              allow_nan=False).encode("ascii")
            ack_digest = sha256(data).hexdigest()
            with closing(_open_existing(self._dir)) as con:
                con.execute("BEGIN IMMEDIATE")
                updated = con.execute(
                    "UPDATE one_effect_intents SET "
                    "disposition='ACK_OBSERVED_NO_EFFECT_AUTHORITY',"
                    "ack_observation_sha256=? WHERE task_id=? "
                    "AND operation_sha256=? AND disposition='UNKNOWN_NO_AUTO_RETRY'",
                    (ack_digest, claim["task_id"], claim["operation_sha256"]))
                if updated.rowcount != 1:
                    raise RecipientFenceUnknown("local fence changed after ACK")
                con.execute("COMMIT")
        except Exception as exc:
            raise RecipientFenceUnknown(
                "remote ACK, CORE or local fence UNKNOWN; NO EFFECT OR RETRY") from exc
        return {
            "status": _STATUS,
            "task_id": claim["task_id"],
            "operation_sha256": claim["operation_sha256"],
            "external_epoch": claim["external_epoch"],
            "local_attempt_durably_consumed": True,
            "owner_reviewer_witness_verified_in_bridge": True,
            "recipient_file_effect_granted_for_production": False,
            "physically_independent_witness_attested": False,
            "distributed_atomic_transaction_attested": False,
            "automatic_retry_allowed": False,
        }


    def execute_fixed_ci_file_once(self, *, file_root: Path, payload: bytes,
                                   body, claim, owner_signature,
                                   reviewer_signature, witness_claim,
                                   after_ack_test_hook=None):
        """One *real* inert CREATE_NEW file following verified signed witness.

        Only executable on disposable GitHub-hosted CI, never owner computer.
        This test proves order of local intent -> signed remote ACK ->
        CORE recheck -> fixed file. It does NOT grant a general SCM permission
        or production file effect. Crash after ACK burns the reservation.
        """
        runner = os.environ.get("RUNNER_TEMP")
        if (os.environ.get("GITHUB_ACTIONS") != "true"
                or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
                or not runner or not isinstance(file_root, Path)
                or type(payload) is not bytes or not 1 <= len(payload) <= 2048
                or sha256(payload).hexdigest() != self._payload
                or body.get("content_sha256") != self._payload
                or body.get("target") !=
                   "bridge/neurofactory/development/core_owned/windows_pilot.txt"):
            _deny("no production or arbitrary file operation")
        trusted_temp = Path(runner).resolve(strict=True)
        safe = _root(file_root)
        try:
            if (safe.resolve(strict=True) == trusted_temp or
                    not safe.resolve(strict=True).is_relative_to(trusted_temp)):
                _deny("fixture output must be isolated under disposable runner temp")
        except (OSError, ValueError) as exc:
            raise RecipientFenceDenied("disposable CI fixture unavailable") from exc
        # This irreversible local intent is committed before first TLS byte.
        proof = self.reserve_once(
            body=body, claim=claim, owner_signature=owner_signature,
            reviewer_signature=reviewer_signature, witness_claim=witness_claim)
        try:
            self._live_claim(body)
            if after_ack_test_hook is not None:
                # Adversarial fixture hook only; no on-disk config or worker
                # message may request a crash mode.
                after_ack_test_hook()
            target = safe / "windows_pilot.txt"
            if target.is_symlink() or target.exists():
                raise RecipientFenceUnknown("destination already exists; NO REPLAY")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target, flags, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as out:
                    out.write(payload)
                    out.flush()
                    os.fsync(out.fileno())
            except BaseException:
                raise
            if sha256(target.read_bytes()).hexdigest() != self._payload:
                raise RecipientFenceUnknown("file readback mismatch; manual review")
        except Exception as exc:
            raise RecipientFenceUnknown(
                "post-ACK FILE UNKNOWN; NO AUTOMATIC RETRY") from exc
        return {
            "status": "ONE_INERT_CI_FILE_AFTER_SIGNED_REMOTE_ACK",
            "payload_sha256": self._payload,
            "operator_signed_external_epoch": proof["external_epoch"],
            "production_execution_allowed": False,
            "distributed_atomic_transaction_attested": False,
            "automatic_retry_allowed": False,
        }
