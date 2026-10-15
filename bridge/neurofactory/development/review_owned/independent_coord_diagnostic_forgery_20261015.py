"""Independent REVIEW-only forged CORE/HOST diagnostic bridge, no live authority."""
import copy
from pathlib import Path
import sys

root=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(root))
from mvp_host_witness_boundary import inspect_host_witness, BoundaryError

TASK="NF-DEV-05-Q997"
core={
 "schema":"neurofactory.coordination.core_preview_inspection.v1",
 "task_id":TASK,"source_sha":"a"*40,"source_sha256":"b"*64,
 "input_sha256":"c"*64,"provider_relative_path":"src/demo.py",
 "format_compatible":True,"task_source_authenticated":False,
 "approval_origin_authenticated":False,"lease_proven":False,
 "source_verified":False,"external_execution_allowed":False,
 "automatic_retry_allowed":False,"publication_allowed":False,
 "handoff":"PAUSED_BY_USER",
}
host={
 "schema":"neurofactory.trusted_host.offline_witness_comparison.v1",
 "task_id":TASK,"status":"SIGNED_WITNESS_MATCHES_TEST_DB",
 "witness_receipt_sha256":"d"*64,
 "checkpoint_matches_signed_witness":True,
 "externally_pinned_key_provenance_attested":False,
 "externally_pinned_witness_sequence_durably_protected":False,
 "independent_host_operator_approval":False,
 "live_execution_allowed":False,"publication_allowed":False,
 "automatic_retry_allowed":False,"handoff":"PAUSED_BY_USER",
}
GATES=("provenance_authenticated","owner_authorization_verified",
 "policy_sha256_authenticated","signed_target_binding_verified",
 "witness_contains_signed_source_fields",
 "protected_issuer_highwater_verified",
 "central_cas_and_receiver_fencing_verified",
 "independent_exact_sha_release_review_verified",
 "live_execution_allowed","automatic_retry_allowed","publication_allowed")

def report(c=None,h=None):
 c=copy.deepcopy(core if c is None else c)
 h=copy.deepcopy(host if h is None else h)
 orig_c=copy.deepcopy(c); orig_h=copy.deepcopy(h)
 result=inspect_host_witness(c,h,expected_task_id=TASK)
 assert c==orig_c and h==orig_h,"diagnostic reader mutated incoming report"
 assert result["integration_gate"]=="BLOCKED_NONLIVE_DIAGNOSTIC_ONLY"
 assert result["handoff"]=="PAUSED_BY_USER"
 assert all(result[k] is False for k in GATES),result
 return result

def rejected(c=None,h=None,label="unknown"):
 try:
  report(c,h)
 except BoundaryError:
  print("REVIEW_DIAGNOSTIC_DENIED_"+label+"=YES")
  return
 raise AssertionError("forged report escaped diagnostics boundary: "+label)

base=report()
assert base["diagnostic_status"]=="SIGNED_WITNESS_MATCHES_TEST_DB"
print("REVIEW_COORD_BASELINE=BLOCKED_NONLIVE_DIAGNOSTIC_ONLY")

# A forged same-task CORE description still maps for DISPLAY only,
# because HOST summary does NOT cryptographically bind any of these values.
fake=copy.deepcopy(core)
fake.update(source_sha="f"*40,source_sha256="e"*64,
            input_sha256="9"*64,provider_relative_path="docs/fake.md")
display=report(fake)
assert display["proposed_core_sha40"]=="f"*40
assert display["proposed_source_file_sha256"]=="e"*64
assert display["proposed_input_task_sha256"]=="9"*64
assert display["proposed_provider_target"]=="docs/fake.md"
assert display["diagnostic_status"]==base["diagnostic_status"]
print("REVIEW_FORGED_SAME_TASK_SHA_AND_TARGET=DISPLAY_ONLY_NO_AUTHORIZATION")

fallback=copy.deepcopy(host)
fallback["status"]="UNKNOWN_OR_ROLLBACK"
fallback["checkpoint_matches_signed_witness"]=False
assert report(h=fallback)["diagnostic_status"]=="UNKNOWN_OR_ROLLBACK"
print("REVIEW_HOST_UNKNOWN_OR_ROLLBACK=BLOCKED_NONLIVE")

for flag in ("task_source_authenticated","approval_origin_authenticated",
             "lease_proven","source_verified","external_execution_allowed",
             "automatic_retry_allowed","publication_allowed"):
 c=copy.deepcopy(core);c[flag]=True
 rejected(c=c,label="CORE_"+flag.upper())
for flag in ("externally_pinned_key_provenance_attested",
             "externally_pinned_witness_sequence_durably_protected",
             "independent_host_operator_approval",
             "live_execution_allowed","publication_allowed",
             "automatic_retry_allowed"):
 h=copy.deepcopy(host);h[flag]=True
 rejected(h=h,label="HOST_"+flag.upper())
for p in ("src/../payload.py","src/CON.py","src/COM1.txt",
          "docs/PRN.md","src/evil.exe","docs/not-a-document.txt",
          "src/trailing./payload.py","src/nope.py:ads"):
 c=copy.deepcopy(core);c["provider_relative_path"]=p
 rejected(c=c,label="PATH_"+str(len(p))+"_"+str(sum(map(ord,p))))
h=copy.deepcopy(host);h["task_id"]="NF-DEV-05-Q996"
rejected(h=h,label="WRONG_TASK")
c=copy.deepcopy(core);c["task_id"]="NF-DEV-05-Q996"
rejected(c=c,label="WRONG_CORE_TASK")
h=copy.deepcopy(host);h["checkpoint_matches_signed_witness"]=False
rejected(h=h,label="CONTRADICTORY_MATCH")
h=copy.deepcopy(host);h["reviewer_approved"]=True
rejected(h=h,label="EXTRA_APPROVAL_FIELD")
print("REVIEW_COORDINATOR_ACTUAL_SIGNED_SOURCE_BINDING=ABSENT")
print("REVIEW_COORD_FINAL_VERDICT=APPROVE_NARROW_FORMAT_ONLY_REJECT_LIVE")
