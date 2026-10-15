"""REVIEW-only exact-SHA Ed25519 signed-effect binding negative.
Ephemeral in-memory key; never authorizes real work or stores secrets.
A positive test demonstrates an incomplete signed *schema*, not a live bypass.
"""
import importlib
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HOST_DIR=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(HOST_DIR))
from offline_issuer import sign_offline_fixture, verify_with_externally_pinned_state

private=Ed25519PrivateKey.generate()
payload={
 "schema":"neurofactory.trusted_checkpoint_event.v1",
 "task_id":"NF-DEV-05-Q987",
 "project_id":"review-only",
 "input_core_sha40":"a"*40,
 "source_file_sha256":"b"*64,
 "input_task_sha256":"c"*64,
 "event_kind":"EFFECT_READBACK",
 "event_sequence":1,
 "prior_event_digest_sha256":"0"*64,
 "core_checkpoint_digest_sha256":"d"*64,
 "issuer_identity":"test-independent-issuer",
 "issuer_key_id":"isolated-review-key",
 "issued_at_utc":"2026-10-15T11:00:00Z"
}
assert "lease_epoch" not in payload
assert "idempotency_key" not in payload
signed=sign_offline_fixture(private,payload)
verified=verify_with_externally_pinned_state(
 private.public_key(),signed,
 expected_task_id=payload["task_id"],
 expected_core_sha40=payload["input_core_sha40"],
 expected_issuer_identity=payload["issuer_identity"],
 expected_key_id=payload["issuer_key_id"],
 externally_pinned_prev_digest=payload["prior_event_digest_sha256"],
 externally_pinned_next_sequence=1
)
assert verified["matches_supplied_external_anchor"] is True
assert verified["external_anchor_provenance_supplied_by_host"] is False
assert verified["separate_signer_host_attested"] is False
assert verified["live_execution_allowed"] is False
assert verified["publication_allowed"] is False
print("REVIEW_CRYPTO_SIGNATURE=VALID_ON_EPHEMERAL_TEST_KEY")
print("REVIEW_EFFECT_EPOCH_BINDING=ABSENT_YET_VERIFIED_LINK")
print("REVIEW_EFFECT_IDEMPOTENCY_BINDING=ABSENT_YET_VERIFIED_LINK")
print("REVIEW_LIVE_PERMISSION=FALSE")
print("REVIEW_TRUST_HOST_DEPLOYED=NOT_ESTABLISHED")
print("REVIEW_SCOPE=SIGNED_EVENT_SCHEMA_INCOMPLETE_NOT_LIVE_AUTH_BYPASS")
