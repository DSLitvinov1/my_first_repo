"""REVIEW-owned minimal signed source-context binding negatives.
Pinned HOST source SHA 3724dda83f7b352cb535c87e95687ae9b12957f2.
In-memory ephemeral Ed25519 key only; no live signer or model.
"""
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
from offline_issuer import IssuerBoundaryError,sign_offline_fixture,verify_with_externally_pinned_state

private=Ed25519PrivateKey.generate()
payload={
 "schema":"neurofactory.trusted_checkpoint_event.v1",
 "task_id":"NF-DEV-05-Q987",
 "project_id":"review-sandbox",
 "input_core_sha40":"a"*40,
 "source_file_sha256":"b"*64,
 "input_task_sha256":"c"*64,
 "policy_sha256":"9"*64,
 "target":"docs/synthetic_review.txt",
 "event_kind":"EFFECT_READBACK",
 "event_sequence":2,
 "prior_event_digest_sha256":"0"*64,
 "core_checkpoint_digest_sha256":"d"*64,
 "issuer_identity":"review-test-issuer",
 "issuer_key_id":"review-key-01",
 "issued_at_utc":"2026-10-15T11:00:00Z",
 "lease_epoch":7,
 "worker_id":"review-test-worker",
 "fencing_token_sha256":"f"*64,
 "idempotency_key":"e"*64
}
baseline={
 "expected_task_id":payload["task_id"],
 "expected_core_sha40":payload["input_core_sha40"],
 "expected_project_id":payload["project_id"],
 "expected_source_file_sha256":payload["source_file_sha256"],
 "expected_input_task_sha256":payload["input_task_sha256"],
 "expected_policy_sha256":payload["policy_sha256"],
 "expected_target":payload["target"],
 "expected_issuer_identity":payload["issuer_identity"],
 "expected_key_id":payload["issuer_key_id"],
 "externally_pinned_prev_digest":payload["prior_event_digest_sha256"],
 "externally_pinned_next_sequence":2,
 "externally_pinned_lease_epoch":7,
 "externally_pinned_worker_id":payload["worker_id"],
 "externally_pinned_fencing_token_sha256":payload["fencing_token_sha256"],
 "externally_pinned_idempotency_key":payload["idempotency_key"]
}
signed=sign_offline_fixture(private,payload)
def verify(**changes):
    supplied=dict(baseline)
    supplied.update(changes)
    return verify_with_externally_pinned_state(private.public_key(),signed,**supplied)

normal=verify()
assert normal["matches_supplied_external_anchor"] is True
assert normal["live_execution_allowed"] is False
assert normal["separate_signer_host_attested"] is False
print("REVIEW_CORRECT_SIGNED_SOURCE_CONTEXT=VERIFIED_NONLIVE")

wrong={
 "expected_project_id":"other-sandbox",
 "expected_source_file_sha256":"1"*64,
 "expected_input_task_sha256":"2"*64,
 "expected_policy_sha256":"3"*64,
 "expected_target":"docs/other_review.txt"
}
for field,incorrect in wrong.items():
    assert incorrect != baseline[field]
    try:
        verify(**{field:incorrect})
    except IssuerBoundaryError:
        print("REVIEW_WRONG_"+field.upper()+"=REJECTED_WITH_VALID_SIGNATURE")
    else:
        raise AssertionError("Signed link was accepted with wrong externally pinned "+field)
print("REVIEW_SOURCE_TASK_POLICY_TARGET_BINDING=FIVE_NEGATIVES_REJECTED")
print("REVIEW_INDEPENDENT_SIGNER_DEPLOYED=FALSE")
print("REVIEW_SCOPE=OFFLINE_TEST_KEY_CONTEXT_CHECK_ONLY")
