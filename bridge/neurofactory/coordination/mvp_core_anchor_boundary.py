"""Read-only safety boundary for actual CORE checkpoint_anchor.v1 output.

A self-reported matching SHA-256 is NOT an external immutable checkpoint,
independent reviewer attestation, source-origin proof, lease or release right.
No IO, network, queue, retries, side effects or reviewer impersonation.
"""
from __future__ import annotations
import re


class AnchorBoundaryError(ValueError):
    pass


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_RESULT_KEYS = {
    "schema", "task_id", "anchor_sha256", "matches_supplied_external_digest",
    "external_origin_attested", "model_invoked", "review_approved",
    "published", "execution_allowed",
}
_REVIEW_KEYS = {"audited_sha", "review_commit", "verdict", "run_id", "reviewer"}
_ALLOWED_VERDICTS = frozenset({"APPROVE", "REJECT", "INCONCLUSIVE"})


def inspect_anchor(core_sha, match_result, *, expected_task_id,
                   expected_anchor_sha256, review_observation=None):
    """Describe metadata only; cannot certify the supplied external hash.

    review_observation is untrusted metadata and does not become authenticated
    even if its SHA matches. A trusted host must independently verify GitHub
    actor, exact checkout, code/runner provenance and signed evidence.
    """
    if (type(core_sha) is not str or _SHA40.fullmatch(core_sha) is None or
        type(expected_task_id) is not str or _TASK.fullmatch(expected_task_id) is None or
        type(expected_anchor_sha256) is not str or
        _SHA64.fullmatch(expected_anchor_sha256) is None or
        type(match_result) is not dict or set(match_result) != _RESULT_KEYS):
        raise AnchorBoundaryError("invalid CORE source or anchor-match fields")
    r = match_result
    if (r["schema"] != "neurofactory.core.anchor_match.v1" or
        r["task_id"] != expected_task_id or
        type(r["anchor_sha256"]) is not str or
        r["anchor_sha256"] != expected_anchor_sha256 or
        r["matches_supplied_external_digest"] is not True or
        r["external_origin_attested"] is not False or
        r["model_invoked"] is not False or
        r["review_approved"] is not False or
        r["published"] is not False or
        r["execution_allowed"] is not False):
        raise AnchorBoundaryError("mismatched, escalated or forged CORE anchor metadata")
    observation = "NONE"
    observed_sha = None
    if review_observation is not None:
        if (type(review_observation) is not dict or set(review_observation) != _REVIEW_KEYS or
            type(review_observation["audited_sha"]) is not str or
            _SHA40.fullmatch(review_observation["audited_sha"]) is None or
            type(review_observation["review_commit"]) is not str or
            _SHA40.fullmatch(review_observation["review_commit"]) is None or
            type(review_observation["verdict"]) is not str or
            review_observation["verdict"] not in _ALLOWED_VERDICTS or
            type(review_observation["run_id"]) is not int or
            review_observation["run_id"] <= 0 or
            type(review_observation["reviewer"]) is not str or
            not 1 <= len(review_observation["reviewer"]) <= 80 or
            any(ord(c) < 33 or ord(c) > 126 for c in review_observation["reviewer"])):
            raise AnchorBoundaryError("invalid reviewer observation, not provenance")
        observed_sha = review_observation["audited_sha"]
        if observed_sha != core_sha:
            observation = "OTHER_CORE_SHA_NOT_APPLICABLE"
        elif review_observation["verdict"] == "REJECT":
            observation = "REJECT_REPORTED_SOURCE_NOT_AUTHENTICATED"
        elif review_observation["verdict"] == "APPROVE":
            observation = "APPROVE_REPORTED_NOT_TRUSTED"
        else:
            observation = "INCONCLUSIVE_REPORTED"
    return {
        "schema": "neurofactory.coordination.core_anchor_boundary.v1",
        "task_id": expected_task_id,
        "candidate_core_sha": core_sha,
        "reported_anchor_sha256": expected_anchor_sha256,
        "local_checksum_match_reported": True,
        "external_anchor_provenance_verified": False,
        "review_observation": observation,
        "review_applies_to_core_sha": observed_sha == core_sha if observed_sha else False,
        "independent_review_origin_verified": False,
        "source_writer_isolated_from_same_uid": False,
        "cross_host_lease_verified": False,
        "real_qwen_proven": False,
        "live_execution_allowed": False,
        "automatic_retry_allowed": False,
        "publication_allowed": False,
        "handoff": "PAUSED_BY_USER",
        "integration_gate": "BLOCKED",
    }
