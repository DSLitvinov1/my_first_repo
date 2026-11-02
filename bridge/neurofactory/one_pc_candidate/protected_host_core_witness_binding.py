"""Real CORE SQLite read-only lease scope -> signed remote witness, no effects.

The missing integration boundary:
* use existing OneTaskCore's actual durable SQLite through core_readonly_observer,
* require a single live CLAIMED task matching signed owner+reviewer operation scope
  BEFORE even reserving on the externally pinned witness,
* reserve exactly once via existing protected_host_remote_bridge with durable
  local UNKNOWN journal and authenticated mTLS/Ed25519 remote acknowledgement,
* reread CORE afterwards; if it changed, fail UNKNOWN without another call.

This is an AUDITABLE PRECONDITION, not permission to execute CORE files:
the underlying SQLite observation is untrusted local telemetry, not an
OS-trusted transactional lease or independently attested machine identity.
"""
from __future__ import annotations

from pathlib import Path
from hashlib import sha256
import re
import time

from core_readonly_observer import observe_core, CoreObservationDenied
from protected_host_remote_bridge import OneShotHostWitnessBridge, BridgeUnknown

# Binds the complete immutable CORE task specification and the separately
# approved output payload to exactly ONE signed HOST operation identifier.
# Signed role envelopes and operator-pinned operation_sha256 already exist.
_CORE_EFFECT_DOMAIN = b"NF_CORE_FULL_SPEC_AND_PAYLOAD_OPERATION_V1\x00"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

def exact_core_effect_sha256(core_spec_sha256, payload_sha256):
    """Stable domain-separated commitment: verified full CORE spec + payload.

    Only sha256 digests enter this function. The CORE observer checks the
    canonical task spec hash against the durable queue; OWNER/REVIEWER must
    independently sign the derived operation hash and pinned payload hash.
    This helper never grants execution authority.
    """
    if (type(core_spec_sha256) is not str or
        type(payload_sha256) is not str or
        not _HEX64.fullmatch(core_spec_sha256) or
        not _HEX64.fullmatch(payload_sha256)):
        _deny("invalid full CORE spec or payload SHA")
    return sha256(_CORE_EFFECT_DOMAIN +
                  bytes.fromhex(core_spec_sha256) +
                  bytes.fromhex(payload_sha256)).hexdigest()

class CoreWitnessBindingDenied(ValueError):
    pass

class CoreWitnessBindingUnknown(RuntimeError):
    pass

def _deny(why):
    raise CoreWitnessBindingDenied("CORE signed witness boundary refused: "+why)

def _observed_local_time(requested_now):
    """Reject a caller-supplied stale clock before any remote reservation.

    The local OS clock is NOT a remotely attested clock or production authority.
    This guard only closes the avoidable caller-time substitution in this
    no-effect preflight; independent witness epoch/fencing is still required.
    """
    if type(requested_now) is not int or requested_now <= 0:
        _deny("invalid caller clock")
    observed_now = int(time.time())
    if observed_now <= 0 or abs(requested_now - observed_now) > 5:
        _deny("caller clock differs from locally observed OS time")
    return observed_now


def _validate_observation(obs, claim, now_unix):
    if (type(claim) is not dict or
        type(now_unix) is not int or now_unix <= 0 or
        obs.get("schema") != "nf.core.readonly.local.v1" or
        obs.get("configured") is not True or
        obs.get("available") is not True or
        obs.get("independently_verified") is not False or
        obs.get("execution_allowed") is not False or
        obs.get("queue_mutation_allowed") is not False or
        obs.get("source") != "LOCAL_SQLITE_UNATTESTED" or
        obs.get("reported_state") != "CLAIMED"):
        _deny("CORE has no single read-only CLAIMED task checkpoint")
    task=obs.get("task")
    if (type(task) is not dict or
        task.get("task_id") != claim.get("task_id") or
        task.get("project_id") != claim.get("project_id") or
        type(task.get("lease_until")) is not int or
        task["lease_until"] <= now_unix or
        task["lease_until"] - now_unix > 3600 or
        task.get("attempts") != 1 or
        task.get("local_spec_digest_consistent") is not True or
        task.get("has_local_result_digest") is not False or
        task.get("has_local_receipt") is not False):
        _deny("CORE source/task/project lease or claimed state do not match signed scope")
    # Critically bind *all* CORE spec bytes (already canonical-hashed from
    # SQLite) and the approved payload to the Ed25519-signed operation hash.
    # An alternate target, objective, model, source blob or approval commit
    # MUST fail before the network or reservation ledger is touched.
    expected_operation = exact_core_effect_sha256(
        task.get("core_spec_sha256"), claim.get("payload_sha256"))
    if claim.get("operation_sha256") != expected_operation:
        _deny("signed operation not bound to full CORE spec and payload")
    return task

def bind_core_and_reserve_witness_once(*, core_state_dir: Path,
    bridge: OneShotHostWitnessBridge, claim, owner_signature,
    reviewer_signature, witness_claim, now_unix: int):
    if (not isinstance(core_state_dir, Path) or
        not core_state_dir.is_absolute() or
        not isinstance(bridge, OneShotHostWitnessBridge)):
        _deny("independently provisioned absolute CORE state and signed bridge required")
    # No network, and no durable reservation, until local claim/state check.
    try:
        observed_before=_observed_local_time(now_unix)
        before=observe_core(core_state_dir)
        task=_validate_observation(before,claim,observed_before)
    except CoreObservationDenied as exc:
        raise CoreWitnessBindingDenied("CORE state unavailable before reservation") from exc

    # Irreversible reservation, exactly once; caller must not retry when lost.
    verified=bridge.reserve_and_verify_once(
        claim=claim, owner_signature=owner_signature,
        reviewer_signature=reviewer_signature, witness_claim=witness_claim,
        now_unix=observed_before)
    if (verified.get("status") != "SIGNED_TASK_AND_REMOTE_ACK_VERIFIED_TEST_NO_EFFECT" or
        verified.get("production_release_approved") is not False or
        verified.get("production_task_effect_allowed") is not False or
        verified.get("actual_core_lease_attested") is not False):
        raise CoreWitnessBindingUnknown("remote reservation scope unexpected; NO RETRY")
    try:
        observed_after=_observed_local_time(now_unix)
        if (observed_after < observed_before or
            type(claim.get("expires_unix")) is not int or
            observed_after >= claim["expires_unix"]):
            _deny("local time moved backwards or signed scope expired after ACK")
        after=observe_core(core_state_dir)
        updated=_validate_observation(after,claim,observed_after)
    except (CoreObservationDenied,CoreWitnessBindingDenied) as exc:
        raise CoreWitnessBindingUnknown(
            "CORE changed after signed witness reservation; NO RETRY") from exc
    if updated!=task or after["reported_state"]!=before["reported_state"]:
        raise CoreWitnessBindingUnknown(
            "CORE snapshot changed during external reservation; NO RETRY")
    return {
        "schema":"nf.core_host_witness.readonly_scope.v1",
        "status":"LOCAL_CORE_SCOPE_MATCHED_AND_SIGNED_REMOTE_ACK_TEST_NO_EFFECT",
        "task_id":task["task_id"],
        "project_id":task["project_id"],
        "source_sha40":task["source_sha40"],
        "external_epoch":verified["external_epoch"],
        "local_core_lease_observed":True,
        "cryptographic_owner_reviewer_witness_verified":True,
        "actual_core_lease_transaction_attested":False,
        "windows_scm_sid_acl_attested":False,
        "physically_independent_witness_attested":False,
        "production_file_effects_allowed":False,
        "queue_mutation_allowed":False,
        "automatic_retry_allowed":False,
        "production_release_approved":False,
    }
