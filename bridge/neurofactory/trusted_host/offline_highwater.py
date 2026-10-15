"""Offline PostgreSQL monotonic highwater candidate, NOT protected issuer storage.

Requires ephemeral nf_test database and explicit offline session setting.
Transactions serialize honest concurrent writers only. The database admin can
mutate history and head; externally verified antirollback and separate OS
principal are not implemented and never claimed by this module.
"""
from __future__ import annotations

import re


class OfflineHighwaterError(ValueError):
    pass


_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_GENESIS = "0" * 64


def _check_task(task_id):
    if type(task_id) is not str or _TASK.fullmatch(task_id) is None:
        raise OfflineHighwaterError("invalid checkpoint task")


def _check_hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise OfflineHighwaterError("invalid checkpoint digest")


class OfflineHighwater:
    def __init__(self, conn):
        if getattr(conn, "autocommit", None) is not True:
            raise OfflineHighwaterError("requires transaction-safe autocommit connection")
        row = conn.execute(
            "SELECT current_database(), current_setting('neurofactory.offline_fixture_mode', true)"
        ).fetchone()
        if row != ("nf_test", "on"):
            raise OfflineHighwaterError("no ephemeral fixture boundary")
        self.conn = conn

    def append(self, task_id, next_sequence, prior_digest_sha256, receipt_digest_sha256):
        _check_task(task_id)
        _check_hash(prior_digest_sha256)
        _check_hash(receipt_digest_sha256)
        if type(next_sequence) is not int or not 1 <= next_sequence <= 2**63-1:
            raise OfflineHighwaterError("invalid proposed sequence")
        if receipt_digest_sha256 == prior_digest_sha256:
            return {"status":"BLOCKED","reason":"DUPLICATE_PARENT_DIGEST"}
        with self.conn.transaction():
            # The row lock makes even concurrent first-event requests serialize.
            # Task row must have already been created in the isolated fixture.
            self.conn.execute(
                """INSERT INTO nf_offline_chain_head(task_id)
                   SELECT task_id FROM nf_task WHERE task_id=%s
                   ON CONFLICT(task_id) DO NOTHING""",
                (task_id,)
            )
            head = self.conn.execute(
                """SELECT last_sequence,last_digest_sha256
                   FROM nf_offline_chain_head WHERE task_id=%s FOR UPDATE""",
                (task_id,)
            ).fetchone()
            if head is None:
                return {"status":"BLOCKED","reason":"TASK_UNKNOWN"}
            if next_sequence != head[0]+1 or prior_digest_sha256 != head[1]:
                return {"status":"BLOCKED","reason":"STALE_OR_UNKNOWN_HEAD"}
            # Fences duplicates/replay through a UNIQUE per-task digest.
            existing = self.conn.execute(
                """SELECT sequence FROM nf_offline_chain_event
                   WHERE task_id=%s AND receipt_digest_sha256=%s""",
                (task_id,receipt_digest_sha256)
            ).fetchone()
            if existing is not None:
                return {"status":"BLOCKED","reason":"REPLAYED_RECEIPT"}
            self.conn.execute(
                """INSERT INTO nf_offline_chain_event(
                       task_id,sequence,prior_digest_sha256,receipt_digest_sha256)
                   VALUES(%s,%s,%s,%s)""",
                (task_id,next_sequence,prior_digest_sha256,receipt_digest_sha256)
            )
            self.conn.execute(
                """UPDATE nf_offline_chain_head
                   SET last_sequence=%s,last_digest_sha256=%s WHERE task_id=%s""",
                (next_sequence,receipt_digest_sha256,task_id)
            )
        return {"status":"RECORDED_TEST_ONLY","sequence":next_sequence,
                "external_provenance_verified":False,"live_authorization":False}

    def observe(self, task_id, externally_pinned_sequence, externally_pinned_digest):
        """Compares with a caller-supplied pin; DOES NOT authenticate that pin."""
        _check_task(task_id)
        _check_hash(externally_pinned_digest)
        if type(externally_pinned_sequence) is not int or externally_pinned_sequence < 0:
            raise OfflineHighwaterError("invalid external sequence")
        head = self.conn.execute(
            """SELECT last_sequence,last_digest_sha256 FROM nf_offline_chain_head
               WHERE task_id=%s""",(task_id,)
        ).fetchone()
        match = head is not None and head == (
            externally_pinned_sequence,externally_pinned_digest
        )
        return {"status":"MATCH_REPORTED" if match else "UNKNOWN_OR_MISMATCH",
                "reported_head_matches_supplied_pin":bool(match),
                "independent_pin_source_authenticated":False,
                "publisher_allowed":False,"automatic_retry_allowed":False}
