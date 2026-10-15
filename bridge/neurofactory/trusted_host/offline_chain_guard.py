"""Offline-only strict chain verifier, NOT a deployed immutable issuer.

A single verified signed link does not prove an anti-rollback ledger. This
validator validates ordered links against a trusted external genesis and an
externally pinned FINAL sequence+digest; it cannot provide those pins itself.
"""
from __future__ import annotations

from offline_issuer import IssuerBoundaryError, verify_with_externally_pinned_state


def verify_pinned_chain(trusted_public_key, signed_events, *,
                        expected_task_id, expected_core_sha40,
                        expected_issuer_identity, expected_key_id,
                        externally_pinned_genesis_digest,
                        externally_pinned_start_sequence,
                        externally_pinned_final_sequence,
                        externally_pinned_final_digest,
                        expected_project_id, expected_source_file_sha256,
                        expected_input_task_sha256, expected_policy_sha256,
                        expected_target,
                        externally_pinned_lease_epoch=None,
                        externally_pinned_worker_id=None,
                        externally_pinned_fencing_token_sha256=None,
                        externally_pinned_idempotency_key=None):
    """Fail closed on truncation, replay, reorder, tamper, or wrong external head.

    All externally_pinned_* and expected_* values MUST originate from a
    separate authenticated principal. This is test-only format verification.
    """
    if (type(signed_events) is not list or not signed_events or
        len(signed_events) > 64 or
        type(externally_pinned_start_sequence) is not int or
        type(externally_pinned_final_sequence) is not int or
        externally_pinned_start_sequence < 1 or
        externally_pinned_final_sequence < externally_pinned_start_sequence or
        len(signed_events) !=
            externally_pinned_final_sequence - externally_pinned_start_sequence + 1):
        raise IssuerBoundaryError("missing/reordered/replayed event span")
    if (type(externally_pinned_final_digest) is not str or
        len(externally_pinned_final_digest) != 64 or
        any(c not in "0123456789abcdef" for c in externally_pinned_final_digest)):
        raise IssuerBoundaryError("untrusted external final digest")

    parent = externally_pinned_genesis_digest
    current = externally_pinned_start_sequence
    for signed in signed_events:
        result = verify_with_externally_pinned_state(
            trusted_public_key, signed,
            expected_task_id=expected_task_id,
            expected_core_sha40=expected_core_sha40,
            expected_issuer_identity=expected_issuer_identity,
            expected_key_id=expected_key_id,
            externally_pinned_prev_digest=parent,
            externally_pinned_next_sequence=current,
            expected_project_id=expected_project_id,
            expected_source_file_sha256=expected_source_file_sha256,
            expected_input_task_sha256=expected_input_task_sha256,
            expected_policy_sha256=expected_policy_sha256,
            expected_target=expected_target,
            externally_pinned_lease_epoch=externally_pinned_lease_epoch,
            externally_pinned_worker_id=externally_pinned_worker_id,
            externally_pinned_fencing_token_sha256=externally_pinned_fencing_token_sha256,
            externally_pinned_idempotency_key=externally_pinned_idempotency_key,
        )
        parent = result["reported_receipt_digest_sha256"]
        current += 1

    if parent != externally_pinned_final_digest:
        raise IssuerBoundaryError("checkpoint rollback or unpinned final receipt")
    return {
        "schema": "neurofactory.trusted_host.offline_chain_guard.v1",
        "task_id": expected_task_id,
        "verified_links": len(signed_events),
        "reported_final_digest_sha256": parent,
        "external_issuer_deployed": False,
        "independent_external_pin_attested": False,
        "antirollback_storage_implemented": False,
        "live_execution_allowed": False,
        "automatic_retry_allowed": False,
        "publication_allowed": False,
        "handoff": "PAUSED_BY_USER",
    }
