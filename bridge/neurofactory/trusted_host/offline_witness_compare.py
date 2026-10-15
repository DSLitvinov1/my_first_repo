"""Read-only signed external witness vs PostgreSQL highwater, TEST-ONLY.

This verifies a signature *against externally supplied pins*. It does not
create/provision a protected issuer, protect private keys, anchor a witness
sequence outside the compromised DB, or authorize real execution.
The caller must obtain the pinned public key, prior witness SHA, expected
sequence, and exact task identity from an independently trusted source.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class OfflineWitnessError(ValueError):
    pass


_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
_ID = re.compile(r"[A-Za-z0-9_.-]{3,72}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_FIELDS = frozenset({
    "schema","task_id","project_id","input_core_sha40",
    "source_file_sha256","input_task_sha256","policy_sha256",
    "witness_identity","witness_key_id","witness_sequence",
    "previous_witness_sha256","checkpoint_sequence","checkpoint_sha256",
    "issued_at_utc","purpose"
})
_PURPOSE = "OFFLINE_CHECKPOINT_COMPARISON_ONLY"


def _matches(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _canonical(payload):
    if type(payload) is not dict or set(payload) != _FIELDS:
        raise OfflineWitnessError("unknown or missing witness fields")
    if (payload["schema"] != "neurofactory.trusted_host.offline_external_witness.v1" or
        payload["purpose"] != _PURPOSE or
        not _matches(payload["task_id"],_TASK) or
        not _matches(payload["project_id"],_NAME) or
        not _matches(payload["input_core_sha40"],_SHA40) or
        not _matches(payload["source_file_sha256"],_SHA64) or
        not _matches(payload["input_task_sha256"],_SHA64) or
        not _matches(payload["policy_sha256"],_SHA64) or
        not _matches(payload["witness_identity"],_ID) or
        not _matches(payload["witness_key_id"],_ID) or
        type(payload["witness_sequence"]) is not int or
        payload["witness_sequence"] < 1 or
        type(payload["checkpoint_sequence"]) is not int or
        payload["checkpoint_sequence"] < 1 or
        not _matches(payload["previous_witness_sha256"],_SHA64) or
        not _matches(payload["checkpoint_sha256"],_SHA64) or
        not _matches(payload["issued_at_utc"],_UTC)):
        raise OfflineWitnessError("invalid signed witness payload")
    return json.dumps(payload,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")


def compare_signed_witness_to_ephemeral_postgres(
    conn, trusted_public_key, signed_witness, *,
    expected_task_id, expected_project_id, expected_core_sha40,
    expected_source_file_sha256, expected_input_task_sha256,
    expected_policy_sha256, expected_witness_identity, expected_witness_key_id,
    externally_pinned_next_witness_sequence, externally_pinned_previous_witness_sha256
):
    """Fail closed on forged signature, stale signed anchor and DB rollback.

    Result deliberately never grants permission to run, retry or publish.
    A cryptographically correct comparison does NOT attest that inputs were
    independently sourced or that highwater/key are durable out of band.
    """
    expected = {
        "task_id":(expected_task_id,_TASK),
        "project_id":(expected_project_id,_NAME),
        "input_core_sha40":(expected_core_sha40,_SHA40),
        "source_file_sha256":(expected_source_file_sha256,_SHA64),
        "input_task_sha256":(expected_input_task_sha256,_SHA64),
        "policy_sha256":(expected_policy_sha256,_SHA64),
        "witness_identity":(expected_witness_identity,_ID),
        "witness_key_id":(expected_witness_key_id,_ID),
        "previous_witness_sha256":(externally_pinned_previous_witness_sha256,_SHA64)
    }
    if (type(trusted_public_key) is not Ed25519PublicKey or
        any(not _matches(value,pattern) for value,pattern in expected.values()) or
        type(externally_pinned_next_witness_sequence) is not int or
        externally_pinned_next_witness_sequence < 1 or
        type(signed_witness) is not dict or
        set(signed_witness) != {"payload","signature_base64"}):
        raise OfflineWitnessError("invalid external trust inputs")
    payload=signed_witness["payload"]
    signed_bytes=_canonical(payload)
    for key,(value,_) in expected.items():
        if payload[key] != value:
            raise OfflineWitnessError("witness does not match pinned external task")
    if payload["witness_sequence"] != externally_pinned_next_witness_sequence:
        raise OfflineWitnessError("witness sequence rollback or replay")
    encoded=signed_witness["signature_base64"]
    if type(encoded) is not str or len(encoded)>128:
        raise OfflineWitnessError("bad signature encoding")
    try:
        signature=base64.b64decode(encoded,validate=True)
        if len(signature)!=64:
            raise OfflineWitnessError("bad signature length")
        trusted_public_key.verify(signature,signed_bytes)
    except (InvalidSignature,ValueError,binascii.Error) as exc:
        raise OfflineWitnessError("untrusted witness signature") from exc
    if getattr(conn,"autocommit",None) is not True:
        raise OfflineWitnessError("test-only autocommit required")
    probe=conn.execute(
        "SELECT current_database(), current_setting('neurofactory.offline_fixture_mode',true)"
    ).fetchone()
    if probe != ("nf_test","on"):
        raise OfflineWitnessError("database is not isolated fixture")
    # One consistent read transaction, never a write or an approval path.
    with conn.transaction():
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        row=conn.execute(
            """SELECT last_sequence,last_digest_sha256
               FROM nf_offline_chain_head WHERE task_id=%s""",
            (expected_task_id,)
        ).fetchone()
    matches=(row is not None and
             type(row[0]) is int and row[0]==payload["checkpoint_sequence"] and
             row[1]==payload["checkpoint_sha256"])
    receipt_sha=hashlib.sha256(json.dumps(
        signed_witness,sort_keys=True,separators=(",",":"),
        ensure_ascii=True,allow_nan=False).encode("ascii")).hexdigest()
    return {
        "schema":"neurofactory.trusted_host.offline_witness_comparison.v1",
        "task_id":expected_task_id,
        "status":"SIGNED_WITNESS_MATCHES_TEST_DB" if matches else "UNKNOWN_OR_ROLLBACK",
        "witness_receipt_sha256":receipt_sha,
        "checkpoint_matches_signed_witness":bool(matches),
        "externally_pinned_key_provenance_attested":False,
        "externally_pinned_witness_sequence_durably_protected":False,
        "independent_host_operator_approval":False,
        "live_execution_allowed":False,
        "publication_allowed":False,
        "automatic_retry_allowed":False,
        "handoff":"PAUSED_BY_USER"
    }
