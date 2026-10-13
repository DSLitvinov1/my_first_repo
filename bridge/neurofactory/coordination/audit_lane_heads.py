"""Read-only overlap audit for the five isolated Neurofactory chat branches.

Anchored to the approved lane bootstrap commit. Fails closed if a branch diverged,
a compare is incomplete, an unowned file changed or two chats changed the same
file. Never modifies branches, issues, reviewers, ChatGPT, or billing.
"""
import argparse
import datetime as dt
import json
import os
import pathlib
import urllib.parse
import urllib.request

from check_lanes import check_change_set, load_policy, OwnershipError

ROOT = pathlib.Path(__file__).resolve().parent
BOOTSTRAP = "13bc0df6368472c45a34fc412f927dca7d2fd44e"
REPO = "DSLitvinov1/my_first_repo"
API = "https://api.github.com/repos/" + REPO + "/"
LANES = ("core", "handoff", "review", "providers", "coordinator")
MAX_FILES = 300

class LaneAuditError(ValueError):
    pass


def github_get(endpoint):
    if not isinstance(endpoint, str) or not endpoint.startswith(API):
        raise LaneAuditError("Outside allowed Neurofactory repository")
    request = urllib.request.Request(endpoint, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "Neurofactory-Chat-Lane-ReadOnly-Head-Audit"
    })
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response)


def inspect_branch(lane, policy, getter=github_get):
    if lane not in LANES:
        raise LaneAuditError("Unrecognized lane")
    owner = next((x for x in policy["chat_lanes"] if x["id"] == lane), None)
    if owner is None:
        raise LaneAuditError("Missing owner in immutable policy")
    branch = owner["branch"]
    endpoint = API + "compare/" + BOOTSTRAP + "..." + urllib.parse.quote(branch, safe="-")
    result = getter(endpoint)
    if not isinstance(result, dict):
        raise LaneAuditError("Non-object GitHub compare reply")
    status = result.get("status")
    ahead = result.get("ahead_by")
    behind = result.get("behind_by")
    count = result.get("total_commits")
    files = result.get("files")
    if (status not in ("ahead", "identical") or type(ahead) is not int
        or type(behind) is not int or behind != 0
        or type(count) is not int or ahead != count
        or not isinstance(files, list)
        or len(files) >= MAX_FILES):
        raise LaneAuditError("Diverged or incomplete compare for " + lane)
    paths = []
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
            raise LaneAuditError("Invalid file metadata for " + lane)
        if item.get("status") == "renamed":
            previous = item.get("previous_filename")
            if not isinstance(previous, str):
                raise LaneAuditError("Rename origin unavailable for " + lane)
            paths.append(previous)
        paths.append(item["filename"])
    if len(paths) != len(set(paths)):
        raise LaneAuditError("Duplicate file paths in compare result")
    if status == "identical" and (ahead != 0 or paths):
        raise LaneAuditError("Inconsistent identical branch state")
    if status == "ahead" and (ahead < 1 or not paths):
        raise LaneAuditError("Unverifiable commits or empty change list")
    try:
        if paths:
            check_change_set(lane, paths, policy)
    except OwnershipError as error:
        raise LaneAuditError(f"Wrong lane file change in {lane}: {error}") from error
    return {"lane": lane, "branch": branch, "commit_count": count,
            "file_count": len(paths), "files": sorted(paths),
            "ownership_verified": True}


def scan(policy=None, getter=github_get):
    p = load_policy() if policy is None else policy
    if p.get("canonical_repo") != REPO or p.get("reference_branch") != "neurofactory-public-lab-20261012":
        raise LaneAuditError("Wrong repository or unapproved production branch")
    if p.get("gates", {}).get("chatgpt_delivery") != "paused":
        raise LaneAuditError("Paused ChatGPT delivery was modified")
    if p.get("gates", {}).get("paid_api") != "forbidden":
        raise LaneAuditError("Free-only policy changed")
    audits = [inspect_branch(lane, p, getter) for lane in LANES]
    seen = {}
    conflicts = []
    for report in audits:
        for filename in report["files"]:
            if filename in seen:
                conflicts.append({"path": filename, "lanes": [seen[filename], report["lane"]]})
            seen[filename] = report["lane"]
    if conflicts:
        raise LaneAuditError("Two independent chats changed same file: " + json.dumps(conflicts))
    return {
        "schema": 1, "project": "НЕЙРОЗАВОД",
        "source_repo": REPO, "baseline": BOOTSTRAP,
        "scope": "read_only_five_approved_branches",
        "chatgpt_delivery_paused": True,
        "paid_model_calls": 0, "mutation_operations": 0,
        "lanes": audits, "cross_chat_file_conflicts": []
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", help="Local report file, never writes to GitHub")
    args = parser.parse_args()
    report = scan()
    print("NEUROFACTORY_FIVE_LANE_AUDIT_OK " + json.dumps(
        {"branches": len(report["lanes"]), "files": sum(x["file_count"] for x in report["lanes"]),
         "conflicts": len(report["cross_chat_file_conflicts"])}, sort_keys=True))
    if args.output:
        destination = pathlib.Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except (LaneAuditError, OwnershipError) as error:
        raise SystemExit("NEUROFACTORY_LANE_HEAD_AUDIT_DENIED: " + str(error))
