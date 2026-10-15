"""REVIEW-only one signed effect test against exact HOST source e249...
Independently pinned expected context is simulated in memory, never a live signer.
Test validates epoch/key blocking and probes missing external task/source pins.
"""
from __future__ import annotations
import copy
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
from offline_issuer import (
    IssuerBoundaryError, sign_offline_fixture,
    verify_with_externally_pinned_state
)

key=Ed25519PrivateKey.generate()
common={
 "schema":"neurofactory.trusted_checkpoint_event.v1",
 "task_id":"NF-DEV-05-Q987",
 "project_id":"review-sandbox",
 "input_core_sha40":"a"*40,
 "source_file_sha256":"b"*64,
 "input_task_sha256":"c"*64,
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
externally_authorized_project="review-sandbox"
externally_authorized_source="b"*64
externally_authorized_task="c"*64

def check(signed,**changes):
    vals={
     "expected_task_id":common["task_id"],
     "expected_core_sha40":common["input_core_sha40"],
     "expected_issuer_identity":common["issuer_identity"],
     "expected_key_id":common["issuer_key_id"],
     "externally_pinned_prev_digest":common["prior_event_digest_sha256"],
     "externally_pinned_next_sequence":common["event_sequence"],
     "externally_pinned_lease_epoch":common["lease_epoch"],
     "externally_pinned_worker_id":common["worker_id"],
     "externally_pinned_fencing_token_sha256":common["fencing_token_sha256"],
     "externally_pinned_idempotency_key":common["idempotency_key"]
    }
    vals.update(changes)
    return verify_with_externally_pinned_state(key.public_key(),signed,**vals)

valid=sign_offline_fixture(key,common)
verified=check(valid)
assert verified["matches_supplied_external_anchor"] is True
assert verified["live_execution_allowed"] is False
print("REVIEW_VALID_CURRENT_EPOCH_EFFECT=NONLIVE_LINK_VERIFIED")

for field in ("lease_epoch","idempotency_key"):
    bad=copy.deepcopy(common)
    del bad[field]
    try:
        sign_offline_fixture(key,bad)
    except IssuerBoundaryError:
        print("REVIEW_MISSING_"+field.upper()+"=REJECTED")
    else:
        raise AssertionError("Missing required signed effect field accepted")

for keyname,value in (("externally_pinned_lease_epoch",8),
                      ("externally_pinned_idempotency_key","9"*64)):
    try:
        check(valid,**{keyname:value})
    except IssuerBoundaryError:
        print("REVIEW_STALE_OR_WRONG_"+keyname.upper()+"=REJECTED")
    else:
        raise AssertionError("Pinned effect identity mismatch accepted")

# New semantic gap: externally authoritative source SHA, input snapshot SHA and
# project ID cannot be passed to this verifier. Validly signed wrong fields
# therefore pass link verification under *unchanged* independently supplied
# task/core/issuer/current lease+effect-key values.
for field,expected,replacement in (
  ("source_file_sha256",externally_authorized_source,"1"*64),
  ("input_task_sha256",externally_authorized_task,"2"*64),
  ("project_id",externally_authorized_project,"other-sandbox")
):
    forged=copy.deepcopy(common)
    assert forged[field]==expected and expected!=replacement
    forged[field]=replacement
    signed=sign_offline_fixture(key,forged)
    answer=check(signed)
    assert answer["matches_supplied_external_anchor"] is True
    assert answer["live_execution_allowed"] is False
    print("REVIEW_MISMATCHED_"+field.upper()+"_WITH_VALID_TEST_SIGNATURE=UNBOUND_BUT_NONLIVE")

print("REVIEW_VERIFIER_CANNOT_ACCEPT_EXPECTED_SOURCE_TASK_PROJECT_CONTEXT=CONFIRMED")
print("REVIEW_NO_EXTERNAL_PROVENANCE_OR_DEPLOYED_ISSUER=TRUE")
