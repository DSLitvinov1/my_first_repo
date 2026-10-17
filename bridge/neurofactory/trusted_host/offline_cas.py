"""Offline, ephemeral multi-connection PostgreSQL lease CAS validation ONLY.

Safety gates:
- only nf_test database and explicit per-connection offline setting
- caller/test fixture must insert an authorized synthetic row via raw SQL
- no HTTP server, OS host setup, signer, model, filesystem writer or publisher
- expired/unknown claims are NEVER automatically reclaimed
- no claims about production exactly-once or protected authorization
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets

_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_WORKER = re.compile(r"[A-Za-z0-9_-]{3,60}\Z")
_REQ = re.compile(r"[0-9a-f]{32}\Z")


class OfflineBoundaryError(ValueError):
    pass


def _ident(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


class OfflineCAS:
    """Always-fail-closed experimental claim store. Never use for live tasks."""

    def __init__(self, conn):
        if getattr(conn, "autocommit", None) is not True:
            raise OfflineBoundaryError("requires autocommit connection")
        row = conn.execute(
            "SELECT current_database(), current_setting('neurofactory.offline_fixture_mode', true)"
        ).fetchone()
        if row != ("nf_test", "on"):
            raise OfflineBoundaryError("offline ephemeral PostgreSQL test boundary absent")
        self.conn = conn

    def claim(self, task_id, worker_id, request_id, *, lease_seconds=30):
        if (not _ident(task_id, _TASK) or
            not _ident(worker_id, _WORKER) or
            not _ident(request_id, _REQ) or
            type(lease_seconds) is not int or
            not 1 <= lease_seconds <= 300):
            raise OfflineBoundaryError("invalid task/worker/request/lease fields")
        with self.conn.transaction():
            row = self.conn.execute(
                """SELECT fixture_authorized, phase, lease_epoch, holder_id,
                          lease_request_id
                   FROM nf_task WHERE task_id = %s FOR UPDATE""",
                (task_id,)
            ).fetchone()
            if row is None or row[0] is not True:
                return {"status": "BLOCKED", "reason": "UNAUTHORIZED_OR_MISSING"}
            previous = self.conn.execute(
                "SELECT task_id, worker_id, lease_epoch FROM nf_claim_request WHERE request_id = %s",
                (request_id,)
            ).fetchone()
            if previous is not None:
                # Once a secret token is issued it MUST NEVER be replayed.
                return {"status": "BLOCKED", "reason": "REQUEST_ALREADY_CONSUMED"}
            if row[1] != "QUEUED":
                # Even an expired lease is NOT reclaimed without external proof.
                return {"status": "NOT_CLAIMED", "reason": "LEASED_OR_AMBIGUOUS"}
            token = secrets.token_urlsafe(32)
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            update = self.conn.execute(
                """UPDATE nf_task
                   SET phase='LEASED', lease_epoch=lease_epoch+1,
                       holder_id=%s, lease_request_id=%s,
                       lease_token_sha256=%s,
                       lease_deadline=clock_timestamp() + (%s * INTERVAL '1 second')
                   WHERE task_id=%s AND fixture_authorized IS TRUE AND phase='QUEUED'
                   RETURNING lease_epoch, lease_deadline""",
                (worker_id, request_id, digest, lease_seconds, task_id)
            ).fetchone()
            if update is None:
                return {"status": "NOT_CLAIMED", "reason": "LOST_CONDITIONAL_UPDATE"}
            self.conn.execute(
                """INSERT INTO nf_claim_request(request_id, task_id, worker_id, lease_epoch)
                   VALUES (%s,%s,%s,%s)""",
                (request_id, task_id, worker_id, update[0])
            )
            # This token is test-private, never for OPS/Issue/CI raw logs.
            return {"status": "CLAIMED", "task_id": task_id,
                    "lease_epoch": update[0], "fencing_token": token,
                    "lease_deadline": update[1]}

    def mark_unknown(self, task_id, worker_id, epoch, fencing_token):
        """Safety-only transition. This does NOT perform a task or release it."""
        if (not _ident(task_id, _TASK) or not _ident(worker_id, _WORKER) or
            type(epoch) is not int or epoch < 1 or
            type(fencing_token) is not str or not 1 <= len(fencing_token) <= 200):
            raise OfflineBoundaryError("malformed fenced stop request")
        with self.conn.transaction():
            row = self.conn.execute(
                """SELECT phase, holder_id, lease_epoch, lease_token_sha256
                   FROM nf_task WHERE task_id=%s FOR UPDATE""",
                (task_id,)
            ).fetchone()
            if row is None or row[0] != "LEASED" or row[1] != worker_id or row[2] != epoch:
                return False
            digest = hashlib.sha256(fencing_token.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(row[3], digest):
                return False
            self.conn.execute(
                "UPDATE nf_task SET phase='UNKNOWN' WHERE task_id=%s",
                (task_id,)
            )
            return True

    def public_state(self, task_id):
        if not _ident(task_id, _TASK):
            raise OfflineBoundaryError("malformed task id")
        row = self.conn.execute(
            "SELECT phase, lease_epoch FROM nf_task WHERE task_id=%s", (task_id,)
        ).fetchone()
        if row is None:
            return {"status": "UNKNOWN", "verified": False, "actions_allowed": False}
        return {"status": row[0], "epoch": row[1], "verified": False,
                "actions_allowed": False}
