"""CORE test-only HOST pre-effect bridge. NEVER use as runtime authorization.

Requires disposable nf_test PostgreSQL, independently pre-pinned HOST source,
synthetic positive CORE admission and NF_CORE_FENCED_TEST_ONLY=1 on Linux.
HOST OfflineEffectReservation is not an authenticated signer or atomically
fenced filesystem receiver. The existing apply_offline_test remains a separate
legacy OFFLINE_TEST API and is NOT protected by this bridge. No production claim.
"""
from __future__ import annotations

import hashlib
import os
import re

class FencedOfflineBoundaryError(ValueError):
    pass

_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{3,60}\Z")

class FencedOfflineTestBridge:
    def __init__(self, core, host_effect_gate):
        if os.name != "posix" or os.environ.get("NF_CORE_FENCED_TEST_ONLY") != "1":
            raise FencedOfflineBoundaryError("isolated test-only Linux switch absent")
        if core is None or host_effect_gate is None:
            raise FencedOfflineBoundaryError("missing pinned test counterpart")
        self.core = core
        self.host = host_effect_gate

    def apply_once(self, *, task_id, core_token, proposal, worker_id,
                   host_claim, policy_sha256, idempotency_key, now):
        """Simulated test integration: HOST durable intent BEFORE CORE temp write.

        A caller-supplied positive HOST response is NOT a trusted identity.
        This wrapper is intentionally never exported as a production writer.
        A live implementation MUST enforce signer/key custody and fencing at the
        effect receiver, not this adapter's process-owned return values.
        """
        if (type(task_id) is not str or type(core_token) is not str
                or type(worker_id) is not str or _TOKEN.fullmatch(worker_id) is None
                or type(policy_sha256) is not str or _SHA64.fullmatch(policy_sha256) is None
                or type(idempotency_key) is not str or _SHA64.fullmatch(idempotency_key) is None
                or type(now) is not int or now < 0 or
                type(host_claim) is not dict or
                set(host_claim) != {"status","task_id","lease_epoch","fencing_token","lease_deadline"} or
                host_claim["status"] != "CLAIMED" or
                host_claim["task_id"] != task_id or
                type(host_claim["lease_epoch"]) is not int or host_claim["lease_epoch"] < 1 or
                type(host_claim["fencing_token"]) is not str or
                not 32 <= len(host_claim["fencing_token"]) <= 200):
            raise FencedOfflineBoundaryError("no valid synthetic HOST claim")
        if type(proposal) is not dict or proposal.get("mode") != "OFFLINE_TEST":
            raise FencedOfflineBoundaryError("no inert offline proposal")
        # Read the true local trusted checkpoint rather than accepting the
        # caller's task/project/source/target as a new authority.
        with self.core._connect() as con:
            con.execute("BEGIN")
            row = self.core._row(con)
            if (row is None or row["state"] != "CLAIMED" or
                    row["spec"]["task_id"] != task_id or
                    row["owner"] != worker_id or
                    row["lease_until"] <= now or
                    not hashlib.sha256(core_token.encode()).hexdigest() == row["token"] or
                    proposal.get("target") != row["spec"]["target"]):
                raise FencedOfflineBoundaryError("local CORE claim/scope mismatch")
            spec = dict(row["spec"])
        try:
            reservation = self.host.reserve_once(
                task_id=task_id, project_id=spec["project_id"],
                source_sha40=spec["source_sha"],
                source_file_sha256=spec["source_sha256"],
                input_task_sha256=hashlib.sha256(
                    self._canonical_core_spec(spec)).hexdigest(),
                target=spec["target"], policy_sha256=policy_sha256,
                worker_id=worker_id, lease_epoch=host_claim["lease_epoch"],
                fencing_token=host_claim["fencing_token"],
                idempotency_key=idempotency_key)
        except (ValueError, TypeError) as exc:
            raise FencedOfflineBoundaryError("HOST PRE_EFFECT test proof unavailable") from exc
        if (type(reservation) is not dict or
                reservation.get("status") != "RESERVED_OFFLINE_TEST_ONLY" or
                reservation.get("task_id") != task_id or
                reservation.get("lease_epoch") != host_claim["lease_epoch"] or
                reservation.get("idempotency_key") != idempotency_key or
                any(reservation.get(k) is not False for k in (
                    "execution_allowed","publication_allowed",
                    "automatic_retry_allowed","release_approved",
                    "real_owner_authenticated","real_recipient_fencing"))):
            raise FencedOfflineBoundaryError("central HOST denies synthetic pre-effect")
        # The only effect is genuine CORE's existing OFFLINE_TEST sandbox write.
        # This is NOT authorization for a live model, external file or publisher.
        return self.core.apply_fixture_offline_test(task_id, core_token, proposal, now=now)

    @staticmethod
    def _canonical_core_spec(spec):
        import json
        return json.dumps(spec, ensure_ascii=False, sort_keys=True,
                          separators=(",",":"), allow_nan=False).encode("utf8")
