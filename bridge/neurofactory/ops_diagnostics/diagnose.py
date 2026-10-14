"""Offline Neurofactory operations diagnostics.

This module is an isolated, read-only observer.  It never talks to GitHub,
executes model output, changes an agent queue, verifies signatures, or grants
publication. All supplied snapshots are UNTRUSTED until authenticated by the
independent reviewer and coordinator.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from secure_input import SafeInputError, read_snapshot

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TASK = re.compile(r"NF-[A-Z0-9-]{3,48}\Z")
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,150}\Z")
ROLES = {"unit_tests", "linux_tests", "windows_tests", "model_writer",
         "model_reviewer", "independent_review", "checkpoint_recovery", "publisher"}
STATUS = {"queued", "waiting", "pending", "in_progress", "completed"}
CONCLUSIONS = {None, "success", "failure", "cancelled", "timed_out",
               "skipped", "action_required", "neutral"}
MAX_RUNS = 120
MAX_BYTES = 500000

class SnapshotError(ValueError):
    pass

def _required_dict(obj, name):
    if not isinstance(obj, dict):
        raise SnapshotError(name + " must be a dictionary")
    return obj

def _sha(obj, name):
    if not isinstance(obj, str) or SHA40.fullmatch(obj) is None:
        raise SnapshotError(name + " requires an exact lowercase git commit SHA")
    return obj

def _int(obj, name):
    if type(obj) is not int or obj <= 0:
        raise SnapshotError(name + " must be a positive integer")
    return obj

def _reason_list(snapshot):
    target = _required_dict(snapshot.get("target"), "target")
    branch = _required_dict(snapshot.get("branch"), "branch")
    task = target.get("task_id")
    if not isinstance(task, str) or TASK.fullmatch(task) is None:
        raise SnapshotError("Invalid task identity")
    if not isinstance(target.get("branch"), str) or BRANCH.fullmatch(target["branch"]) is None:
        raise SnapshotError("Invalid target branch")
    expected = _sha(target.get("head_sha"), "target head_sha")
    if not isinstance(branch.get("name"), str) or BRANCH.fullmatch(branch["name"]) is None:
        raise SnapshotError("Invalid actual branch")
    _sha(branch.get("head_sha"), "actual head_sha")
    if type(branch.get("protected")) is not bool:
        raise SnapshotError("Branch protection must be explicitly true or false")

    runs = snapshot.get("runs")
    if not isinstance(runs, list) or len(runs) > MAX_RUNS:
        raise SnapshotError("Invalid or too many GitHub Actions run records")
    ids = set()
    result = []
    reasons = set()
    def block(code):
        reasons.add(code)
    if branch["name"] != target["branch"]:
        block("WRONG_BRANCH")
    if branch["head_sha"] != expected:
        block("STALE_BRANCH_HEAD")
    if not branch["protected"]:
        block("BRANCH_PROTECTION_MISSING")
    found = {}
    for ix, run in enumerate(runs):
        _required_dict(run, "run")
        run_id = _int(run.get("id"), "run id")
        if run_id in ids:
            raise SnapshotError("Duplicate GitHub Actions run ID")
        ids.add(run_id)
        role = run.get("role")
        if role not in ROLES:
            raise SnapshotError("Unknown run role")
        status = run.get("status")
        conclusion = run.get("conclusion")
        _sha(run.get("head_sha"), "run head")
        if status not in STATUS or conclusion not in CONCLUSIONS:
            raise SnapshotError("Unknown run status/conclusion")
        if status != "completed" and conclusion is not None:
            raise SnapshotError("Nonterminal run cannot claim a conclusion")
        if status == "completed" and conclusion is None:
            raise SnapshotError("Completed run requires conclusion")
        found.setdefault(role, []).append(run)
        if run["head_sha"] != expected:
            block("OUTDATED_RUN")
        if status != "completed":
            block("RUN_NOT_FINISHED")
        elif conclusion not in ("success", "skipped"):
            block("RUN_FAILED")
        result.append({"id": run_id, "role": role, "status": status,
                       "conclusion": conclusion,
                       "same_head": run["head_sha"] == expected})
    for key in ("unit_tests", "independent_review"):
        if not found.get(key):
            block(key.upper() + "_MISSING")
    if not found.get("model_writer") or not found.get("model_reviewer"):
        block("TWO_MODEL_EVIDENCE_MISSING")

    review = snapshot.get("review")
    if review is None:
        block("INDEPENDENT_REVIEW_MISSING")
    else:
        _required_dict(review, "review")
        verdict = review.get("verdict")
        if verdict not in ("APPROVE", "REJECT", "PENDING"):
            raise SnapshotError("Unknown independent review verdict")
        _sha(review.get("head_sha"), "review head")
        if review["head_sha"] != expected:
            block("REVIEW_NOT_FOR_CURRENT_HEAD")
        if verdict == "REJECT":
            block("INDEPENDENT_REVIEW_REJECTED")
        if verdict == "PENDING":
            block("INDEPENDENT_REVIEW_PENDING")
        if not isinstance(review.get("artifact_sha256"), str) or not SHA256.fullmatch(review["artifact_sha256"]):
            raise SnapshotError("Review artifact digest missing")
        # Even APPROVE in this input is only a claim; it must be verified outside.
        block("REVIEW_PROVENANCE_UNVERIFIED")

    checkpoint = snapshot.get("checkpoint")
    if checkpoint is None:
        block("CHECKPOINT_MISSING")
    else:
        _required_dict(checkpoint, "checkpoint")
        state = checkpoint.get("state")
        if state not in ("sealed", "partial", "missing", "conflict", "unknown"):
            raise SnapshotError("Unknown checkpoint state")
        if state != "sealed":
            block("CHECKPOINT_" + state.upper())
        if checkpoint.get("task_id") != task:
            block("CHECKPOINT_WRONG_TASK")
        if checkpoint.get("head_sha") != expected:
            block("CHECKPOINT_DIFFERENT_HEAD")
        if checkpoint.get("durable_readback") is not True:
            block("DURABLE_READBACK_UNVERIFIED")
        # local user-supplied "durable" flags are not cross-run authentication
        block("CROSS_RUN_DURABILITY_UNVERIFIED")

    receipt = snapshot.get("publisher_receipt")
    if receipt is None:
        block("PUBLISHER_RECEIPT_MISSING")
    else:
        _required_dict(receipt, "publisher_receipt")
        state = receipt.get("state")
        if state not in ("not_attempted", "uncertain", "externally_verified"):
            raise SnapshotError("Unknown publisher receipt state")
        if state == "uncertain":
            block("UNCERTAIN_PUBLISH_STOP")
        if state == "not_attempted":
            block("PUBLISHER_NOT_ATTEMPTED")
        if state == "externally_verified":
            _sha(receipt.get("commit_sha"), "publisher receipt commit_sha")
            if receipt.get("task_id") != task:
                block("RECEIPT_WRONG_TASK")
            block("PUBLISHER_RECEIPT_PROVENANCE_UNVERIFIED")
        # no scheduler or publisher code is ever invoked here

    ownership = snapshot.get("ownership")
    if ownership is None:
        block("OWNERSHIP_EVIDENCE_MISSING")
    else:
        _required_dict(ownership, "ownership")
        if ownership.get("same_owner_paths") is not True:
            block("POSSIBLE_FOREIGN_FILE_CHANGE")
        if ownership.get("lane") not in ("core", "handoff", "review", "providers",
                                         "coordinator", "skills", "ops_candidate"):
            raise SnapshotError("Unknown lane")
    return result, sorted(reasons)

EXPLANATIONS = {
    "INDEPENDENT_REVIEW_REJECTED": "Independent owner rejected this exact source; do not integrate.",
    "REVIEW_PROVENANCE_UNVERIFIED": "Snapshot is not a trusted signature or REVIEW-owner decision.",
    "UNCERTAIN_PUBLISH_STOP": "Unknown publication outcome: stop replay until GitHub receipt read-back.",
    "BRANCH_PROTECTION_MISSING": "Require repository admin to configure mandatory ruleset/status checks.",
    "CHECKPOINT_PARTIAL": "Partial checkpoint: do not treat it as a completed task.",
    "CROSS_RUN_DURABILITY_UNVERIFIED": "An input flag does not prove independent cross-run restoration.",
    "TWO_MODEL_EVIDENCE_MISSING": "A unit test cannot replace two genuine model calls."
}

def diagnose(snapshot):
    if not isinstance(snapshot, dict) or set(snapshot) != {
            "schema", "scope", "target", "branch", "runs",
            "review", "checkpoint", "publisher_receipt", "ownership"}:
        raise SnapshotError("Unexpected snapshot keys")
    if snapshot["schema"] != 1 or snapshot["scope"] != "neurofactory-ops-candidate":
        raise SnapshotError("Foreign or unsupported snapshot schema")
    runs, blockers = _reason_list(snapshot)
    return {
        "schema": 1, "tool": "neurofactory-ops-diagnostics",
        "task_id": snapshot["target"]["task_id"],
        "target_head": snapshot["target"]["head_sha"],
        "diagnosis": "BLOCKED" if blockers else "EXTERNAL_REVIEW_REQUIRED",
        "release_authorized": False,
        "writes_performed": 0,
        "model_calls_performed": 0,
        "runs": runs,
        "blockers": blockers,
        "explanations": {key: EXPLANATIONS[key] for key in blockers
                         if key in EXPLANATIONS},
        "limitations": [
            "All snapshot values are untrusted caller-supplied data.",
            "This tool neither authenticates GitHub nor verifies model provenance.",
            "No result from this tool permits a merge, a repeat publication, or task scheduling."
        ]
    }

def _parse_unique(raw):
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise SnapshotError("Duplicate input JSON key")
            obj[k] = v
        return obj
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(SnapshotError("Nonfinite number")))
    except (ValueError, UnicodeError, TypeError) as exc:
        if isinstance(exc, SnapshotError):
            raise
        raise SnapshotError("Invalid JSON snapshot") from exc

def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only offline Neurofactory diagnosis")
    parser.add_argument("snapshot", help="Input JSON snapshot; never production checkpoint files")
    args = parser.parse_args(argv)
    try:
        result = diagnose(_parse_unique(read_snapshot(args.snapshot, MAX_BYTES)))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    except (SnapshotError, SafeInputError, OSError) as exc:
        print("DIAGNOSIS_REFUSED: " + str(exc), file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
