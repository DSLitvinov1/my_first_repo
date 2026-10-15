"""Independent exact-SHA REVIEW negative: mixed Ed25519 lifecycle chain.
Ephemeral in-memory signing key, never a live issuer.
"""
import copy
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
from offline_issuer import IssuerBoundaryError,sign_offline_fixture,verify_with_externally_pinned_state
from offline_chain_guard import verify_pinned_chain

key=Ed25519PrivateKey.generate()
expected=dict(expected_task_id="NF-DEV-05-Q981",expected_core_sha40="a"*40,
 expected_project_id="review-case",expected_source_file_sha256="b"*64,
 expected_input_task_sha256="c"*64,expected_policy_sha256="9"*64,
 expected_target="src/review_synthetic.py",expected_issuer_identity="review-test-issuer",
 expected_key_id="review-test-key")
lease={"lease_epoch":9,"worker_id":"review-worker","fencing_token_sha256":"f"*64}
effect="e"*64
contexts=[{"event_kind":"AUTHORIZE_TASK"},
 {"event_kind":"LEASE_CLAIM",**lease},
 {"event_kind":"EFFECT_READBACK",**lease,"idempotency_key":effect}]
parent="0"*64
signed=[]
for seq,context in enumerate(contexts,1):
 kind=context["event_kind"]
 p=dict(schema="neurofactory.trusted_checkpoint_event.v1",
  task_id=expected["expected_task_id"],project_id=expected["expected_project_id"],
  input_core_sha40=expected["expected_core_sha40"],
  source_file_sha256=expected["expected_source_file_sha256"],
  input_task_sha256=expected["expected_input_task_sha256"],
  policy_sha256=expected["expected_policy_sha256"],target=expected["expected_target"],
  event_kind=kind,event_sequence=seq,prior_event_digest_sha256=parent,
  core_checkpoint_digest_sha256="d"*64,
  issuer_identity=expected["expected_issuer_identity"],
  issuer_key_id=expected["expected_key_id"],
  issued_at_utc="2026-10-15T12:00:00Z")
 for f in ("lease_epoch","worker_id","fencing_token_sha256","idempotency_key"):
  if f in context:p[f]=context[f]
 signature=sign_offline_fixture(key,p)
 pins={("externally_pinned_"+f):context[f] for f in
       ("lease_epoch","worker_id","fencing_token_sha256","idempotency_key") if f in context}
 single=verify_with_externally_pinned_state(key.public_key(),signature,
  externally_pinned_prev_digest=parent,externally_pinned_next_sequence=seq,
  **expected,**pins)
 assert single["matches_supplied_external_anchor"] is True
 parent=single["reported_receipt_digest_sha256"]
 signed.append(signature)
base=dict(trusted_public_key=key.public_key(),signed_events=signed,
 externally_pinned_genesis_digest="0"*64,externally_pinned_start_sequence=1,
 externally_pinned_final_sequence=3,externally_pinned_final_digest=parent,
 externally_pinned_event_contexts=contexts,**expected)
def verify(**different):
 q=dict(base);q.update(different);return verify_pinned_chain(**q)
good=verify()
assert good["verified_links"]==3
assert good["live_execution_allowed"] is False
assert good["independent_external_pin_attested"] is False
assert good["antirollback_storage_implemented"] is False
print("REVIEW_VALID_MIXED_KIND_CHAIN=VERIFIED_NONLIVE")
def reject(label,**kw):
 try:verify(**kw)
 except IssuerBoundaryError:print("REVIEW_"+label+"=REJECTED")
 else:raise AssertionError("Not rejected: "+label)
for label,eventidx,field,val in [
 ("STALE_LEASE_EPOCH",1,"lease_epoch",8),
 ("WRONG_WORKER",2,"worker_id","foreign-worker"),
 ("WRONG_FENCE",2,"fencing_token_sha256","1"*64),
 ("WRONG_IDEMPOTENCY",2,"idempotency_key","2"*64),
 ("FALSE_BOOL_EPOCH",1,"lease_epoch",True),
 ("EXTRA_AUTH_EFFECT_PIN",0,"idempotency_key",effect)]:
 items=copy.deepcopy(contexts);items[eventidx][field]=val
 reject(label,externally_pinned_event_contexts=items)
reject("REORDER",signed_events=list(reversed(signed)))
reject("DUPLICATE",signed_events=[signed[0],signed[0],signed[2]])
reject("TRUNCATION",signed_events=signed[:2])
reject("WRONG_FINAL_PIN",externally_pinned_final_digest="3"*64)
reject("NO_CONTEXTS",externally_pinned_event_contexts=None)
reject("FORGED_SIGNER",trusted_public_key=Ed25519PrivateKey.generate().public_key())
print("REVIEW_TOTAL_VALID_CHAIN=1;REVIEW_NEGATIVE_CASES=12")
print("REVIEW_REAL_ISSUER_OR_LIVE_PERMISSION=NOT_PROVEN")
