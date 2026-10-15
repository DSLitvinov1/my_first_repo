"""Independent REVIEW contract-gap reproducer. Coordination documentation only.
No CORE/host execution, credentials, live DB, model or user files.
A successful run is a *negative contract observation*, NOT a runtime exploit.
"""
import json
import pathlib
import sys

EXPECTED_COORD_SHA = "5bb7bb860f5064237951afd722b360abb71e5d61"
source = pathlib.Path(sys.argv[1])
contract = json.loads(source.read_text(encoding="utf-8"))
assert contract["schema"] == "neurofactory.coordination.central_dispatch.v1"
assert contract["status"] == "TARGET_ARCHITECTURE_APPROVED_ON_PAPER_NOT_IMPLEMENTED"
assert contract["topology"]["central_host_deployed"] is False
assert contract["topology"]["issuer_deployed"] is False
required = set(contract["events"]["required_fields"])
assert "event_kind" in required and "signature" in required
assert contract["claim"]["lease_epoch"] == "MONOTONIC_INTEGER_PER_TASK"
assert "EFFECT_READBACK" in contract["events"]["kinds"]
must_bind = {"lease_epoch", "idempotency_key"}
missing = sorted(must_bind - required)
assert missing == ["idempotency_key", "lease_epoch"], (
    "Contract changed; rerun review based on the updated exact SHA"
)
# This event is complete according to the *static listed* fields, but has no
# lease epoch or effect-idempotency key. There is no actual issuer verifier yet.
synthetic = {k: "review-only-synthetic" for k in sorted(required)}
synthetic["event_kind"] = "EFFECT_READBACK"
assert required <= synthetic.keys()
assert "lease_epoch" not in synthetic and "idempotency_key" not in synthetic
assert contract["exactly_once_limitations"]["requires"] == (
    "FENCING_AT_SIDE_EFFECT_RECEIVER_OR_IDEMPOTENT_RECEIVER_PLUS_SIGNED_OUTCOME"
)
print("REVIEW_CONTRACT_REQUIRED_FIELD_GAP=CONFIRMED")
print("REVIEW_MISSING_EFFECT_BINDINGS=lease_epoch,idempotency_key")
print("REVIEW_MINIMAL_EVENT_SHAPE=MATCHES_DECLARED_REQUIRED_FIELDS_ONLY")
print("REVIEW_RUNTIME_ISSUER=NOT_IMPLEMENTED")
print("REVIEW_IMPACT=PREIMPLEMENTATION_SPEC_INCOMPLETE_NOT_LIVE_BYPASS")
