"""Read-only GitHub PR ownership and test-namespace audit for Neurofactory.

Only the coordinator's isolated branch owns this file. The audit does not
modify pull requests or stop actions. A mixed PR remains unmergeable by
policy even if independent tests have passed.
"""
import argparse
import json
import pathlib
import urllib.parse
import urllib.request

from check_lanes import load_policy, owners_for, OwnershipError

REPO = "DSLitvinov1/my_first_repo"
URL_ROOT = "https://api.github.com/repos/" + REPO + "/"
POLICY = pathlib.Path(__file__).with_name("lanes.json")
BRANCHES = {
    "core": "neurofactory-core-queue-owned-20261013",
    "handoff": "neurofactory-model-handoff-owned-20261013",
    "review": "neurofactory-review-owned-20261013",
    "providers": "neurofactory-providers-free-20261013",
    "coordinator": "neurofactory-chat-coordination-20261013",
}

class AuditError(ValueError):
    pass


def classify_pr(number, branch, paths, policy, draft):
    if not isinstance(number, int) or number < 1:
        raise AuditError("PR number invalid")
    if not isinstance(paths, list) or not paths:
        return {"number": number, "approved": False, "reason": "empty_pr",
                "draft": bool(draft), "owners": []}
    owners = set()
    problems = []
    for path in paths:
        try:
            candidates = owners_for(path, policy)
        except OwnershipError:
            candidates = []
        if len(candidates) != 1:
            problems.append({"path": path, "owners": candidates})
        else:
            owners.add(candidates[0])
    allowed = len(owners) == 1 and not problems
    owner = next(iter(owners)) if len(owners) == 1 else None
    if allowed and BRANCHES.get(owner) != branch:
        allowed = False
        problems.append({"path": "*", "error": "branch_must_match_owner",
                         "expected_branch": BRANCHES[owner]})
    if len(owners) > 1:
        allowed = False
        problems.append({"error": "mixed_chat_ownership"})
    return {"number": number, "approved": allowed, "draft": bool(draft),
            "owners": sorted(owners), "owner": owner, "problems": problems,
            "files_checked": len(paths),
            "reason": "approved" if allowed else "ownership_or_branch_violation"}


def _fetch_json(endpoint):
    if not isinstance(endpoint, str) or not endpoint.startswith(URL_ROOT):
        raise AuditError("Unapproved GitHub endpoint")
    req = urllib.request.Request(endpoint, headers={
        "User-Agent": "Neurofactory-ReadOnly-Lane-Audit",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=25) as stream:
        return json.load(stream)


def live_prs(fetch=None):
    getter = fetch or _fetch_json
    prs = []
    page = 1
    while page <= 5:
        endpoint = URL_ROOT + "pulls?" + urllib.parse.urlencode(
            {"state": "open", "per_page": 100, "page": page})
        data = getter(endpoint)
        if not isinstance(data, list):
            raise AuditError("Malformed PR listing")
        prs.extend(data)
        if len(data) < 100:
            break
        page += 1
    if len(prs) >= 500:
        raise AuditError("PR pagination potentially incomplete")
    return prs


def scan(fetch=None):
    getter = fetch or _fetch_json
    policy = load_policy(POLICY)
    result = []
    for pr in live_prs(getter):
        number = pr["number"]
        branch = pr["head"]["ref"]
        paths = []
        for page in range(1, 21):
            endpoint = URL_ROOT + "pulls/" + str(number) + "/files?" + (
                urllib.parse.urlencode({"per_page": 100, "page": page}))
            rows = getter(endpoint)
            if not isinstance(rows, list):
                raise AuditError("Invalid PR file listing")
            paths.extend(row["filename"] for row in rows)
            if len(rows) < 100:
                break
        else:
            raise AuditError("Changed file list too large to verify")
        result.append(classify_pr(
            number, branch, paths, policy, pr.get("draft", False)))
    return {"schema": 1, "scope": "neurofactory_only",
            "active_chats": 3,
            "active_ownership_lanes": ["core", "handoff", "coordinator"],
            "support_functions": ["review", "providers"],
            "open_pr_checks": result,
            "unsafe_ready_prs": [x["number"] for x in result
                                 if not x["approved"] and not x["draft"]],
            "drafts_requiring_split": [x["number"] for x in result
                                       if not x["approved"] and x["draft"]]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", help="Write audit metadata to an isolated JSON file")
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    report = scan()
    output = json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2)
    print("NEUROFACTORY_PR_OWNERSHIP_AUDIT " + output)
    if args.report:
        destination = pathlib.Path(args.report)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output + "\n", encoding="utf-8")
    if args.enforce and report["unsafe_ready_prs"]:
        raise AuditError("Unsafe non-draft pull request detected; no merge permitted")


if __name__ == "__main__":
    main()
