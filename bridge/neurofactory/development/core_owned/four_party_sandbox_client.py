"""CORE-owned offline adapter to HOST's four-party sandbox effect contract.

NO I/O except reading the existing CORE claim through its read connection.
No host filesystem, PostgreSQL, witness, model, paid API or queue write access.
HOST owns validation of all four real Ed25519 signatures and central fencing.
Calling a supplied host_submit callback is allowed ONLY with explicit fixture
flags. This is NOT a production credential, client transport or writer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

class CoreFourPartyDenied(ValueError):
    pass

class CoreFourPartyUnknown(RuntimeError):
    pass

def _deny():
    raise CoreFourPartyDenied("CORE four-party sandbox proposal denied")

_SHA40 = frozenset("0123456789abcdef")

def _hex(v, length):
    return type(v) is str and len(v) == length and set(v) <= _SHA40

def _hash_scope(scope):
    try:
        raw = json.dumps(scope, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        _deny()
    if not 1 <= len(raw) <= 4096:
        _deny()
    return hashlib.sha256(raw).hexdigest()

class CoreFourPartySandboxClient:
    """Single-object, single-attempt callback client, NOT durable replay storage."""

    def __init__(self, core):
        if (os.name != "posix" or
                os.environ.get("NF_CORE_OFFLINE_RECEIVER_TEST_ONLY") != "1" or
                os.environ.get("NF_ATOMIC_TEST_ONLY") != "1" or
                core is None or not callable(getattr(core, "_connect", None)) or
                not callable(getattr(core, "_row", None))):
            _deny()
        self._core = core
        self._attempted = False

    def submit_once(self, *, task_id, worker_id, core_token, proposal,
                    expected_effect, signed_operator_acl, signed_owner_grant,
                    signed_host_lease, signed_external_witness, now_unix,
                    host_submit):
        if self._attempted:
            raise CoreFourPartyUnknown("previous dispatch outcome is unknown: no retry")
        if (type(task_id) is not str or type(worker_id) is not str or
                type(core_token) is not str or not 8 <= len(core_token) <= 512 or
                type(now_unix) is not int or now_unix < 1 or
                type(proposal) is not dict or
                set(proposal) != {"schema", "target", "content", "content_sha256", "mode"} or
                proposal.get("schema") != "neurofactory.core.proposal.v1" or
                proposal.get("mode") != "OFFLINE_TEST" or
                type(proposal.get("target")) is not str or
                type(proposal.get("content")) is not str or
                type(proposal.get("content_sha256")) is not str or
                type(expected_effect) is not dict or
                not callable(host_submit)):
            _deny()
        content = proposal["content"].encode("utf-8")
        if (not 1 <= len(content) <= 65536 or
                not _hex(proposal["content_sha256"], 64) or
                hashlib.sha256(content).hexdigest() != proposal["content_sha256"]):
            _deny()
        # The signed scope must agree with the local CORE lease. The HOST will
        # authenticate scope signatures independently; CORE never impersonates
        # operator, owner, protected HOST or witness.
        required = {
            "task_id": task_id, "worker_id": worker_id,
            "target": proposal["target"],
            "content_sha256": proposal["content_sha256"],
        }
        if any(expected_effect.get(k) != v or type(expected_effect.get(k)) is not str
               for k, v in required.items()):
            _deny()
        if (not _hex(expected_effect.get("source_sha40"), 40) or
                not _hex(expected_effect.get("source_file_sha256"), 64) or
                not _hex(expected_effect.get("policy_sha256"), 64) or
                type(expected_effect.get("lease_epoch")) is not int or
                expected_effect["lease_epoch"] <= 0 or
                not _hex(expected_effect.get("fencing_token_sha256"), 64) or
                not _hex(expected_effect.get("idempotency_key"), 64)):
            _deny()
        scope_digest = _hash_scope(expected_effect)
        signed = {
            "operator": signed_operator_acl,
            "owner": signed_owner_grant,
            "host": signed_host_lease,
            "witness": signed_external_witness,
        }
        for role, packet in signed.items():
            if (type(packet) is not dict or
                    set(packet) != {"body", "signature_base64"} or
                    type(packet["body"]) is not dict or
                    packet["body"].get("schema") !=
                    "neurofactory.attested." + role + ".v1" or
                    packet["body"].get("scope_sha256") != scope_digest or
                    type(packet["signature_base64"]) is not str or
                    len(packet["signature_base64"]) != 88):
                _deny()
        try:
            with self._core._connect() as connection:
                connection.execute("BEGIN")
                row = self._core._row(connection)
                if (type(row) is not dict or row.get("state") != "CLAIMED" or
                        row.get("owner") != worker_id or
                        type(row.get("lease_until")) is not int or
                        row["lease_until"] <= now_unix or
                        type(row.get("token")) is not str or
                        not hmac.compare_digest(
                            hashlib.sha256(core_token.encode()).hexdigest(),
                            row["token"]) or
                        type(row.get("spec")) is not dict):
                    _deny()
                spec = row["spec"]
                pinned = {
                    "task_id": task_id,
                    "project_id": expected_effect.get("project_id"),
                    "repository": expected_effect.get("repository"),
                    "owner_id": expected_effect.get("owner_id"),
                    "source_sha": expected_effect["source_sha40"],
                    "source_sha256": expected_effect["source_file_sha256"],
                    "policy_sha256": expected_effect["policy_sha256"],
                    "target": proposal["target"],
                }
                if any(type(spec.get(k)) is not str or spec[k] != v
                       for k, v in pinned.items()):
                    _deny()
                if (type(spec.get("lease_epoch")) is not int or
                        spec["lease_epoch"] != expected_effect["lease_epoch"] or
                        spec.get("fencing_token_sha256") !=
                        expected_effect["fencing_token_sha256"]):
                    _deny()
        except CoreFourPartyDenied:
            raise
        except (OSError, AttributeError, TypeError, KeyError, ValueError):
            _deny()
        # There is no durable CORE-side retry capability. Mark attempted BEFORE
        # invoking HOST; on loss of its reply the client becomes unusable.
        self._attempted = True
        try:
            receipt = host_submit(
                expected_effect=expected_effect,
                signed_operator_acl=signed_operator_acl,
                signed_owner_grant=signed_owner_grant,
                signed_host_lease=signed_host_lease,
                signed_external_witness=signed_external_witness,
                now_unix=now_unix, content=content,
            )
        except Exception as exc:
            raise CoreFourPartyUnknown("HOST may have reserved or written: STOP") from exc
        if (type(receipt) is not dict or
                receipt.get("status") != "SANDBOX_FILE_AND_SQL_COMPLETED_TEST_ONLY" or
                receipt.get("operation_id") != expected_effect.get("operation_id") or
                receipt.get("content_sha256") != proposal["content_sha256"] or
                receipt.get("live_execution_allowed") is not False or
                receipt.get("release_approved") is not False or
                receipt.get("automatic_retry_allowed") is not False or
                receipt.get("real_external_witness_attested") is not False):
            raise CoreFourPartyUnknown("unverifiable HOST result: do not retry")
        return {
            "status": "CORE_HOST_FOUR_PARTY_SANDBOX_COMPLETED_TEST_ONLY",
            "task_id": task_id,
            "content_sha256": proposal["content_sha256"],
            "core_wrote_local_file": False,
            "live_execution_allowed": False,
            "automatic_retry_allowed": False,
            "independent_review_approved": False,
        }
