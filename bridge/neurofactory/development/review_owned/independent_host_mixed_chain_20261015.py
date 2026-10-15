"""REVIEW-only mixed-kind signed chain negative pinned HOST 8a7b5b...
An AUTHORIZATION, LEASE_CLAIM and EFFECT_READBACK are all individually
validly signed and independently verifiable with event-specific pins.
Probe that full-chain validator can / cannot check those same events.
No deployed issuer, external account, model or production DB.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pathlib import Path
import sys
sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
from offline_issuer import IssuerBoundaryError,sign_offline_fixture,verify_with_externally_pinned_state
from offline_chain_guard import verify_pinned_chain

private=Ed25519PrivateKey.generate()
context=dict(
    expected_task_id="NF-DEV-05-Q981",
    expected_core_sha40="a"*40,
    expected_project_id="review-case",
    expected_source_file_sha256="b"*64,
    expected_input_task_sha256="c"*64,
    expected_policy_sha256="9"*64,
    expected_target="src/review_synthetic.py",
    expected_issuer_identity="review-test-issuer",
    expected_key_id="review-test-key",
)
pins=dict(
    externally_pinned_lease_epoch=9,
    externally_pinned_worker_id="review-worker",
    externally_pinned_fencing_token_sha256="f"*64,
)
effectkey="e"*64
genesis="0"*64
prev=genesis
signed_events=[]
for sequence,kind in ((1,"AUTHORIZE_TASK"),(2,"LEASE_CLAIM"),(3,"EFFECT_READBACK")):
    payload=dict(
        schema="neurofactory.trusted_checkpoint_event.v1",
        task_id=context["expected_task_id"],
        project_id=context["expected_project_id"],
        input_core_sha40=context["expected_core_sha40"],
        source_file_sha256=context["expected_source_file_sha256"],
        input_task_sha256=context["expected_input_task_sha256"],
        policy_sha256=context["expected_policy_sha256"],
        target=context["expected_target"],
        event_kind=kind,
        event_sequence=sequence,
        prior_event_digest_sha256=prev,
        core_checkpoint_digest_sha256="d"*64,
        issuer_identity=context["expected_issuer_identity"],
        issuer_key_id=context["expected_key_id"],
        issued_at_utc="2026-10-15T12:00:00Z",
    )
    expected=dict(context)
    if kind!="AUTHORIZE_TASK":
        payload.update(lease_epoch=9,worker_id="review-worker",fencing_token_sha256="f"*64)
        expected.update(pins)
    if kind=="EFFECT_READBACK":
        payload["idempotency_key"]=effectkey
        expected["externally_pinned_idempotency_key"]=effectkey
    record=sign_offline_fixture(private,payload)
    link=verify_with_externally_pinned_state(
        private.public_key(),record,
        externally_pinned_prev_digest=prev,
        externally_pinned_next_sequence=sequence,**expected)
    assert link["matches_supplied_external_anchor"] is True
    assert link["live_execution_allowed"] is False
    prev=link["reported_receipt_digest_sha256"]
    signed_events.append(record)
print("REVIEW_THREE_DISTINCT_EVENT_KIND_LINKS=INDIVIDUALLY_VERIFIED")

params=dict(
    trusted_public_key=private.public_key(),
    signed_events=signed_events,
    externally_pinned_genesis_digest=genesis,
    externally_pinned_start_sequence=1,
    externally_pinned_final_sequence=3,
    externally_pinned_final_digest=prev,
    **context
)
try:
    outcome=verify_pinned_chain(**params,**pins,
        externally_pinned_idempotency_key=effectkey)
except IssuerBoundaryError as exc:
    print("REVIEW_FULL_VALID_MIXED_CHAIN_WITH_CURRENT_EFFECT_PINS=REJECTED")
    print("REVIEW_MIXED_CHAIN_LIMIT=PER_EVENT_PIN_SCOPE_UNSUPPORTED")
    print("REVIEW_MIXED_CHAIN_ERROR="+str(exc))
else:
    print("REVIEW_FULL_VALID_MIXED_CHAIN_WITH_CURRENT_EFFECT_PINS=ACCEPTED_NONLIVE")
    assert outcome["live_execution_allowed"] is False

try:
    verify_pinned_chain(**params)
except IssuerBoundaryError:
    print("REVIEW_FULL_VALID_MIXED_CHAIN_WITHOUT_PINS=REJECTED")
else:
    raise AssertionError("Chain inexplicably verified lease events without independently pinned lease context")
print("REVIEW_NO_DEPLOYED_PROVENANCE=TRUE")
print("REVIEW_SCOPE=MIXED_KIND_CHAIN_COMPOSABILITY_NOT_LIVE_AUTH_BYPASS")
