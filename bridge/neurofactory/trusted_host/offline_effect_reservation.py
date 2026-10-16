"""Ephemeral HOST-side PRE_EFFECT reservation, TEST ONLY, not an effect permit.

This module handles only the same nf_test database/fixture_mode as OfflineCAS.
It DOES NOT write files, authenticate real owner, verify a protected signer,
prove remote worker identity, provide HTTPS, or atomically fence a filesystem
receiver. A positive TEST reservation MUST NOT be used by CORE as authority.
"""
from __future__ import annotations

import hashlib
import hmac
import re

_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
_WORKER = re.compile(r"[A-Za-z0-9_-]{3,60}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_TARGET = re.compile(
    r"bridge/neurofactory/development/core_owned/"
    r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.(?:py|md|txt|json)\Z"
)

class OfflineEffectBoundaryError(ValueError):
    pass


def _valid(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _safe_target(value):
    if not _valid(value, _TARGET):
        return False
    for part in value.split("/"):
        device = part.split(".", 1)[0].upper()
        if device in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(
            r"(COM|LPT)[1-9]", device
        ):
            return False
    return True


def _denied(reason):
    return {
        "status": "DENIED", "reason": reason, "execution_allowed": False,
        "publication_allowed": False, "automatic_retry_allowed": False,
        "release_approved": False, "real_owner_authenticated": False,
        "real_recipient_fencing": False
    }


class OfflineEffectReservation:
    """Reserve one synthetic pre-effect intent inside the existing HOST CAS DB."""

    def __init__(self, conn):
        if getattr(conn, "autocommit", None) is not True:
            raise OfflineEffectBoundaryError("autocommit connection required")
        found = conn.execute(
            "SELECT current_database(), "
            "current_setting('neurofactory.offline_fixture_mode',true)"
        ).fetchone()
        if found != ("nf_test", "on"):
            raise OfflineEffectBoundaryError("ephemeral nf_test boundary required")
        self.conn = conn

    def reserve_once(self, *, task_id, project_id, source_sha40,
                     source_file_sha256, input_task_sha256,
                     target, policy_sha256, worker_id, lease_epoch,
                     fencing_token, idempotency_key):
        """Reserve a durable test intent only; NEVER authorize external effects.

        Atomic PostgreSQL lock covers CAS lease plus scope fixture and intent
        uniqueness. Existing test fixture values are NOT authenticated claims.
        The actual filesystem/remote effect is outside this transaction.
        """
        if (not _valid(task_id, _TASK) or
            not _valid(project_id, _PROJECT) or
            not _valid(source_sha40, _SHA40) or
            not _valid(source_file_sha256, _SHA64) or
            not _valid(input_task_sha256, _SHA64) or
            not _safe_target(target) or
            not _valid(policy_sha256, _SHA64) or
            not _valid(worker_id, _WORKER) or
            type(lease_epoch) is not int or not 1 <= lease_epoch < 2**63 or
            type(fencing_token) is not str or
            not 32 <= len(fencing_token) <= 200 or
            not _valid(idempotency_key, _SHA64)):
            raise OfflineEffectBoundaryError("invalid bounded pre-effect inputs")

        token_digest = hashlib.sha256(fencing_token.encode("utf-8")).hexdigest()
        with self.conn.transaction():
            task = self.conn.execute(
                """SELECT phase,fixture_authorized,lease_epoch,holder_id,
                          lease_token_sha256,lease_deadline,
                          project_id,input_core_sha40,
                          source_file_sha256,input_task_sha256,
                          clock_timestamp()
                     FROM nf_task WHERE task_id=%s FOR UPDATE""",
                (task_id,)
            ).fetchone()
            if task is None or task[1] is not True:
                return _denied("HOST_FIXTURE_UNAUTHORIZED")
            if task[0] != "LEASED":
                return _denied("HOST_NOT_LEASED_OR_UNKNOWN")
            if (task[2] != lease_epoch or task[3] != worker_id or
                type(task[4]) is not str or
                not hmac.compare_digest(task[4], token_digest)):
                return _denied("STALE_OR_FORGED_LEASE")
            if task[5] is None or task[5] <= task[10]:
                return _denied("LEASE_EXPIRED")
            scope = self.conn.execute(
                """SELECT project_id,input_core_sha40,source_file_sha256,
                          input_task_sha256,target,policy_sha256,
                          fixture_authorized
                     FROM nf_effect_scope_fixture WHERE task_id=%s""",
                (task_id,)
            ).fetchone()
            wanted = (project_id, source_sha40, source_file_sha256,
                      input_task_sha256, target, policy_sha256)
            if (tuple(task[6:10]) != wanted[:4] or scope is None or
                tuple(scope[:6]) != wanted or scope[6] is not True):
                return _denied("SOURCE_OR_SCOPE_NOT_MATCHED")
            inserted = self.conn.execute(
                """INSERT INTO nf_effect_intent
                     (task_id,project_id,worker_id,lease_epoch,
                      fencing_token_sha256,idempotency_key,
                      source_sha40,source_file_sha256,input_task_sha256,
                      target,policy_sha256)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT DO NOTHING RETURNING task_id""",
                (task_id, project_id, worker_id, lease_epoch,
                 token_digest, idempotency_key, source_sha40,
                 source_file_sha256, input_task_sha256, target,
                 policy_sha256)
            ).fetchone()
            if inserted is None:
                return _denied("EFFECT_INTENT_ALREADY_CONSUMED")
        return {
            "status": "RESERVED_OFFLINE_TEST_ONLY",
            "task_id": task_id,
            "lease_epoch": lease_epoch,
            "idempotency_key": idempotency_key,
            "execution_allowed": False,
            "publication_allowed": False,
            "automatic_retry_allowed": False,
            "release_approved": False,
            "real_owner_authenticated": False,
            "real_recipient_fencing": False,
        }
