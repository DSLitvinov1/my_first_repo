"""Read-only four-signature ↔ current permanent PostgreSQL effect preflight.

Verifies actual PostgreSQL16 lease row and UNKNOWN receipt with externally
pinned four-party signed scope in the SAME database transaction. This stage
does NOT create/modify a file, acquire a production execution capability,
durably verify witness storage, or enable retries. In a real receiver the
transaction must be retained through the final effect and receipt, and an
independently authenticated remote witness must first reserve off-host.
A DB admin, same-UID process, or local snapshot can forge/rollback DB state.
No fixture env flags or caller-supplied public keys accepted as authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from independent_four_party_scope import (
    ProductionScopeRejected, inspect_signed_four_party_scope,
)
from operator_installed_public_pins import (
    OperatorPinsDenied, load_operator_installed_public_pins,
)


class AdmissionRejected(ValueError):
    pass


def _deny():
    raise AdmissionRejected("no four-signature + live lease + UNKNOWN effect admission")


def inspect_current_lease_and_receipt(
    connection, *, expected_effect: dict[str, Any],
    signed_operator_acl: dict, signed_owner_grant: dict,
    signed_host_lease: dict, signed_external_witness: dict,
    now_unix: int,
) -> dict:
    """Operator-pinned, SQL-backed immutable source observation only.

    Enforces SQLite/worker local tokens never qualify as authorization.
    After this call returns, locks are released: caller MUST NOT use this
    diagnostic as permission for an effect. Live receiver integration must
    perform all fencing and witness operations in its protected boundary.
    """
    if os.name != "posix" or type(now_unix) is not int or now_unix <= 0:
        _deny()
    if (type(expected_effect) is not dict or
            type(signed_external_witness) is not dict or
            type(signed_host_lease) is not dict or
            type(signed_operator_acl) is not dict or
            type(signed_owner_grant) is not dict):
        _deny()
    try:
        pins = load_operator_installed_public_pins()
        metadata = pins["metadata"]
        if (metadata["repository"] != expected_effect["repository"] or
                metadata["github_user_id"] != expected_effect["github_user_id"] or
                metadata["repository_id"] != expected_effect["repository_id"] or
                metadata["live_execution_allowed"] is not False):
            _deny()
        verified = inspect_signed_four_party_scope(
            pinned_public_keys=pins["pinned_keys"],
            expected_effect=expected_effect,
            signed_operator_acl=signed_operator_acl,
            signed_owner_grant=signed_owner_grant,
            signed_host_lease=signed_host_lease,
            signed_external_witness=signed_external_witness,
            now_unix=now_unix,
        )
        if (verified["live_execution_allowed"] is not False or
                verified["release_approved"] is not False):
            _deny()
        if getattr(connection, "autocommit",None) is not True:
            _deny()
        scope_sha = verified["scope_sha256"]
        body = signed_external_witness["body"]
        with connection.transaction():
            lease = connection.execute(
                """SELECT owner_id, repository_full_name, project_id,
                          source_sha40, source_file_sha256, policy_sha256,
                          approved_scope_sha256, worker_id, lease_epoch,
                          fencing_token_sha256, state, lease_deadline,
                          clock_timestamp()
                   FROM nf_trusted_host.lease_register
                   WHERE task_id=%s FOR SHARE""",
                (expected_effect["task_id"],)
            ).fetchone()
            if (lease is None or
                lease[0] != expected_effect["owner_id"] or
                lease[1] != expected_effect["repository"] or
                lease[2] != expected_effect["project_id"] or
                lease[3] != expected_effect["source_sha40"] or
                lease[4] != expected_effect["source_file_sha256"] or
                lease[5] != expected_effect["policy_sha256"] or
                lease[6] != scope_sha or
                lease[7] != expected_effect["worker_id"] or
                type(lease[8]) is not int or
                lease[8] != expected_effect["lease_epoch"] or
                lease[9] != expected_effect["fencing_token_sha256"] or
                lease[10] != "CLAIMED" or
                lease[11] is None or lease[11] <= lease[12]):
                _deny()
            receipt = connection.execute(
                """SELECT operation_id,idempotency_key,signed_scope_sha256,
                          target_sha256,content_sha256,
                          external_witness_root_sha256,
                          external_witness_sequence,status,
                          receiver_file_sha256,completed_at
                   FROM nf_trusted_host.effect_receipt
                   WHERE task_id=%s FOR SHARE""",
                (expected_effect["task_id"],)
            ).fetchone()
            target_digest=hashlib.sha256(
                expected_effect["target"].encode("utf-8")
            ).hexdigest()
            if (receipt is None or
                receipt[0] != expected_effect["operation_id"] or
                receipt[1] != expected_effect["idempotency_key"] or
                receipt[2] != scope_sha or
                receipt[3] != target_digest or
                receipt[4] != expected_effect["content_sha256"] or
                receipt[5] != body["protected_journal_root_sha256"] or
                receipt[6] != body["commit_sequence"] or
                receipt[7] != "UNKNOWN" or
                receipt[8] is not None or receipt[9] is not None):
                _deny()
        return {
            "schema": "neurofactory.db_bound_four_party_diagnostic.v1",
            "status": "PINNED_SIGNATURES_AND_LIVE_SQL_MATCH_NO_EFFECT_AUTHORITY",
            "task_id": expected_effect["task_id"],
            "scope_sha256": scope_sha,
            "operation_id": expected_effect["operation_id"],
            "signed_roles_checked": 4,
            "durable_witness_actually_rechecked_out_of_band": False,
            "db_rollback_protection_confirmed": False,
            "hardware_signer_custody_attested": False,
            "receiver_effect_lock_still_held": False,
            "independent_review_approved": False,
            "production_effect_authorized": False,
            "live_execution_allowed": False,
            "automatic_retry_allowed": False,
            "release_approved": False,
        }
    except (ProductionScopeRejected, OperatorPinsDenied, KeyError,
            ValueError, TypeError, IndexError) as exc:
        raise AdmissionRejected("signed scope, operator trust or live DB denied") from exc
    except Exception as exc:
        # Including inaccessible PG, malicious schema, DB restart or timeout.
        raise AdmissionRejected("cannot prove fresh central DB lease and receipt") from exc
