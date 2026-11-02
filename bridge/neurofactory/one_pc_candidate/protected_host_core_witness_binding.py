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

from core_readonly_observer import observe_core, CoreObservationDenied
from protected_host_remote_bridge import OneShotHostWitnessBridge, BridgeUnknown

class CoreWitnessBindingDenied(ValueError):
    pass

class CoreWitnessBindingUnknown(RuntimeError):
    pass

def _deny(why):
    raise CoreWitnessBindingDenied("CORE signed witness boundary refused: "+why)

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
        task.get("source_sha40") != claim.get("source_sha40") or
        type(task.get("lease_until")) is not int or
        task["lease_until"] <= now_unix or
        task["lease_until"] - now_unix > 3600 or
        task.get("attempts") != 1 or
        task.get("local_spec_digest_consistent") is not True or
        task.get("has_local_result_digest") is not False or
        task.get("has_local_receipt") is not False):
        _deny("CORE source/task/project lease or claimed state do not match signed scope")
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
        before=observe_core(core_state_dir)
        task=_validate_observation(before,claim,now_unix)
    except CoreObservationDenied as exc:
        raise CoreWitnessBindingDenied("CORE state unavailable before reservation") from exc

    # Irreversible reservation, exactly once; caller must not retry when lost.
    verified=bridge.reserve_and_verify_once(
        claim=claim, owner_signature=owner_signature,
        reviewer_signature=reviewer_signature, witness_claim=witness_claim,
        now_unix=now_unix)
    if (verified.get("status") != "SIGNED_TASK_AND_REMOTE_ACK_VERIFIED_TEST_NO_EFFECT" or
        verified.get("production_release_approved") is not False or
        verified.get("production_task_effect_allowed") is not False or
        verified.get("actual_core_lease_attested") is not False):
        raise CoreWitnessBindingUnknown("remote reservation scope unexpected; NO RETRY")
    try:
        after=observe_core(core_state_dir)
        updated=_validate_observation(after,claim,now_unix)
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
