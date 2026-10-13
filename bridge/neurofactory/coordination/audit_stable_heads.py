"""Coordinator-only, read-only, race-aware audit of five Neurofactory branches.

Pin every lane to its immutable Git commit before retrieving diffs. Compare
only the pinned commits against the approved bootstrap, then re-read all branch
heads. A branch advanced during the audit invalidates the whole report; no
inconsistent mixture of snapshots can ever be marked as conflict-free.
"""
import argparse
import json
import pathlib
import re
import urllib.parse

from audit_lane_heads import (
    API, BOOTSTRAP, LANES, github_get, scan as scan_lane_deltas,
    LaneAuditError,
)
from check_lanes import load_policy

SHA = re.compile(r"[a-f0-9]{40}\Z")


def read_head(branch, getter):
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", branch):
        raise LaneAuditError("Invalid owned branch name")
    path = API + "branches/" + urllib.parse.quote(branch, safe="-_.")
    response = getter(path)
    if not isinstance(response, dict):
        raise LaneAuditError("Missing branch metadata")
    commit = response.get("commit")
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise LaneAuditError("Branch head is not an exact immutable commit SHA")
    return sha


def frozen_scan(policy=None, getter=github_get):
    p = load_policy() if policy is None else policy
    branches = {entry["id"]: entry["branch"] for entry in p["chat_lanes"]}
    if set(branches) != set(LANES):
        raise LaneAuditError("Missing, duplicate or unexpected branch owner")

    # First phase: snapshot every live ref before looking at any changed file.
    heads = {lane: read_head(branches[lane], getter) for lane in LANES}
    reverse = {branches[lane]: lane for lane in LANES}
    prefix = API + "compare/" + BOOTSTRAP + "..."

    def pinned_compare(url):
        if not isinstance(url, str) or not url.startswith(prefix):
            raise LaneAuditError("Unapproved mutable compare URL")
        branch = urllib.parse.unquote(url[len(prefix):])
        if branch not in reverse:
            raise LaneAuditError("Unapproved compare target")
        desired = heads[reverse[branch]]
        endpoint = prefix + desired
        data = getter(endpoint)
        if not isinstance(data, dict):
            raise LaneAuditError("No pinned comparison data")
        actual = data.get("head_commit")
        actual_sha = actual.get("sha") if isinstance(actual, dict) else None
        if actual_sha is None:
            # The public connector can omit GitHub's head_commit wrapper.
            # Require the COMPLETE commit array and derive the last commit,
            # never trust an incomplete paginated comparison.
            commits = data.get("commits")
            count = data.get("total_commits")
            if not isinstance(commits, list) or type(count) is not int:
                raise LaneAuditError("Pinned comparison lacks complete commit history")
            if len(commits) != count:
                raise LaneAuditError("Truncated pinned comparison history")
            if count:
                last = commits[-1]
                actual_sha = last.get("sha") if isinstance(last, dict) else None
            elif data.get("status") == "identical":
                base = data.get("base_commit")
                actual_sha = base.get("sha") if isinstance(base, dict) else None
        if actual_sha != desired:
            raise LaneAuditError("Pinned comparison did not include expected exact head")
        return data

    result = scan_lane_deltas(p, pinned_compare)

    # Last phase: if ANY branch moved, refuse the aggregate report. This keeps
    # concurrent chats' states from being confused with one stable snapshot.
    after = {lane: read_head(branches[lane], getter) for lane in LANES}
    changed = [lane for lane in LANES if after[lane] != heads[lane]]
    if changed:
        raise LaneAuditError("Concurrent branch changes; fresh full audit required: "
                             + ", ".join(changed))

    for report in result["lanes"]:
        report["immutable_head_sha"] = heads[report["lane"]]
    result["read_consistency"] = "all_five_heads_pinned_and_rechecked"
    result["heads_verified_unchanged"] = True
    result["audit_mutation_operations"] = 0
    result["reference_limitation"] = (
        "Snapshot valid at audit check; new pushes require a new check."
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", help="Coordinator-only local audit artifact")
    args = parser.parse_args()
    report = frozen_scan()
    print("NEUROFACTORY_STABLE_HEADS_VERIFIED " + json.dumps({
        "lanes": len(report["lanes"]),
        "changed_files": sum(x["file_count"] for x in report["lanes"]),
        "overlaps": len(report["cross_chat_file_conflicts"]),
        "unchanged": report["heads_verified_unchanged"],
    }, sort_keys=True))
    if args.output:
        p = pathlib.Path(args.output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                     encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except LaneAuditError as error:
        raise SystemExit("NEUROFACTORY_STABLE_HEADS_DENIED: " + str(error))
