"""Coordinator-only read-only integration gate.

A green unit test is not an independent approval. A PR is ready to be *considered*
only if ownership, branch identity, immutable head SHA, clean CI and a fresh
independent review all match. This script never merges or edits GitHub.
"""
import argparse
import json
import pathlib
import re
import urllib.parse
import urllib.request

from audit_pr_ownership import classify_pr
from check_lanes import load_policy

REPO = "DSLitvinov1/my_first_repo"
BASE_BRANCH = "neurofactory-public-lab-20261012"
URL = "https://api.github.com/repos/" + REPO + "/"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
EXPECTED_OWNER_CHECK = "Neurofactory Parallel Chat Ownership Gate"
REVIEW_GATE = "Neurofactory Independent Qwen3 Accepted Source"
MAX_PAGES = 10

class MergeGateError(ValueError):
    pass


def get_json(endpoint):
    if not isinstance(endpoint, str) or not endpoint.startswith(URL):
        raise MergeGateError("Refused an external project API request")
    request = urllib.request.Request(endpoint, headers={
        "User-Agent": "Neurofactory-Coordinator-ReadOnly-PreMerge-Gate",
        "Accept": "application/vnd.github+json"
    })
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response)


def fetch_pages(getter, path, *, max_pages=MAX_PAGES):
    result = []
    for page in range(1, max_pages + 1):
        endpoint = URL + path + ("&" if "?" in path else "?") + urllib.parse.urlencode(
            {"per_page": 100, "page": page}
        )
        batch = getter(endpoint)
        if not isinstance(batch, list):
            raise MergeGateError("GitHub pagination is invalid")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise MergeGateError("Cannot prove pagination was complete")


def pr_head(pr):
    if not isinstance(pr, dict):
        raise MergeGateError("Missing GitHub PR")
    number = pr.get("number")
    if type(number) is not int or number < 1:
        raise MergeGateError("Invalid pull request number")
    head = pr.get("head") or {}
    sha = head.get("sha")
    if not isinstance(sha, str) or not HEX40.fullmatch(sha):
        raise MergeGateError("Invalid pinned head commit")
    return number, sha


def independent_github_review(pr, reviews):
    """Require an APPROVED review tied to the current exact head, by another account.

    Approval is not a Qwen3 verdict: the separate trusted independent model
    check is also required.
    """
    number, sha = pr_head(pr)
    author = (pr.get("user") or {}).get("login")
    if not isinstance(author, str) or not author:
        return False
    latest = {}
    for review in reviews:
        if not isinstance(review, dict):
            raise MergeGateError("Malformed GitHub review record")
        reviewer = (review.get("user") or {}).get("login")
        state = review.get("state")
        if reviewer and state in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[reviewer] = review
    # An unresolved changes-requested review blocks adoption even if another
    # reviewer approved. Dismissal or a new approval by the same reviewer
    # replaces that reviewer's previous verdict.
    if any(record.get("state") == "CHANGES_REQUESTED" for record in latest.values()):
        return False
    for reviewer, review in latest.items():
        if (reviewer != author and review.get("state") == "APPROVED"
                and review.get("commit_id") == sha):
            return True
    return False


def required_checks(pr, check_runs):
    """Checks must refer to exact current SHA and be completed successfully.

    External reports not carrying an exact SHA are intentionally insufficient.
    """
    _, sha = pr_head(pr)
    if not isinstance(check_runs, list):
        raise MergeGateError("Missing GitHub check runs")
    successful = {}
    for item in check_runs:
        if not isinstance(item, dict):
            raise MergeGateError("Invalid check record")
        name = item.get("name")
        if not isinstance(name, str):
            continue
        run_id = item.get("id")
        if type(run_id) is not int or run_id < 1:
            raise MergeGateError("Cannot order check runs without GitHub IDs")
        current = successful.get(name)
        # Select the newest check by its real GitHub ID rather than trusting
        # response ordering, which can otherwise hide a newer failure.
        if current is None or run_id > current["id"]:
            successful[name] = item
    for name in (EXPECTED_OWNER_CHECK, REVIEW_GATE):
        run = successful.get(name)
        details = "" if run is None else run.get("details_url", "")
        app = {} if run is None else (run.get("app") or {})
        if (run is None or run.get("head_sha") != sha or
                run.get("status") != "completed" or
                run.get("conclusion") != "success" or
                app.get("slug") != "github-actions" or
                not isinstance(details, str) or
                not details.startswith(
                    "https://github.com/DSLitvinov1/my_first_repo/actions/runs/")):
            return False
    return True


def evaluate(pr, files, reviews, checks, policy):
    number, sha = pr_head(pr)
    blocks = []
    if pr.get("state") != "open" or pr.get("draft") is not False:
        blocks.append("draft_or_not_open")
    base = (pr.get("base") or {}).get("ref")
    head = (pr.get("head") or {})
    head_repo = (head.get("repo") or {}).get("full_name")
    base_repo = ((pr.get("base") or {}).get("repo") or {}).get("full_name")
    if base != BASE_BRANCH or base_repo != REPO or head_repo != REPO:
        blocks.append("wrong_base_or_external_fork")
    if pr.get("mergeable") is not True or pr.get("mergeable_state") not in ("clean",):
        blocks.append("mergeability_not_confirmed")
    if not isinstance(files, list) or not files:
        blocks.append("missing_changed_files")
        paths = []
    else:
        paths = []
        for f in files:
            if not isinstance(f, dict) or not isinstance(f.get("filename"), str):
                raise MergeGateError("Unverifiable changed-file metadata")
            if f.get("status") == "renamed":
                before = f.get("previous_filename")
                if not isinstance(before, str) or not before:
                    raise MergeGateError("Rename old path missing")
                paths.append(before)
            paths.append(f["filename"])
    if len(paths) != len(set(paths)):
        blocks.append("duplicate_changed_paths")
    ownership = classify_pr(number, head.get("ref"), paths, policy, bool(pr.get("draft")))
    if not ownership.get("approved"):
        blocks.append("mixed_or_unowned_changes")
    if not independent_github_review(pr, reviews):
        blocks.append("no_fresh_independent_git_review")
    if not required_checks(pr, checks):
        blocks.append("missing_current_owner_or_qwen3_check")
    if policy["gates"].get("chatgpt_delivery") != "paused":
        blocks.append("user_paused_delivery_violation")
    if policy["gates"].get("paid_api") != "forbidden":
        blocks.append("free_only_policy_violation")
    return {
        "number": number, "head_sha": sha, "head_branch": head.get("ref"),
        "owner": ownership.get("owner"), "files": len(paths),
        "read_only": True, "automerge": False,
        "integration_consideration_allowed": not blocks,
        "blocking_reasons": sorted(set(blocks))
    }


def verify_pr(number, getter=get_json, policy=None):
    if type(number) is not int or number < 1:
        raise MergeGateError("Invalid PR target")
    p = load_policy() if policy is None else policy
    pr = getter(URL + "pulls/" + str(number))
    _, sha = pr_head(pr)
    files = fetch_pages(getter, "pulls/" + str(number) + "/files")
    reviews = fetch_pages(getter, "pulls/" + str(number) + "/reviews")
    check_response = getter(URL + "commits/" + sha + "/check-runs?per_page=100")
    if (not isinstance(check_response, dict) or
            not isinstance(check_response.get("total_count"), int) or
            check_response["total_count"] >= 100):
        raise MergeGateError("Missing/truncated check run evidence")
    checks = check_response.get("check_runs")
    result = evaluate(pr, files, reviews, checks, p)
    # Guard against a PR changing between fetches by re-reading the exact
    # head after all checks. Never let an old reviewed SHA approve a new head.
    updated = getter(URL + "pulls/" + str(number))
    if pr_head(updated)[1] != sha or updated.get("updated_at") != pr.get("updated_at"):
        raise MergeGateError("PR changed during audit; rerun")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--number", type=int, required=True)
    parser.add_argument("--out", help="Read-only local report, not a GitHub publication")
    arguments = parser.parse_args()
    result = verify_pr(arguments.number)
    print("NEUROFACTORY_PREMERGE " + json.dumps(result, sort_keys=True))
    if arguments.out:
        f = pathlib.Path(arguments.out)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", "utf-8")
    if not result["integration_consideration_allowed"]:
        raise SystemExit("NEUROFACTORY_INTEGRATION_BLOCKED: " + ",".join(result["blocking_reasons"]))


if __name__ == "__main__":
    try:
        main()
    except MergeGateError as exc:
        raise SystemExit("NEUROFACTORY_INTEGRATION_BLOCKED: " + str(exc))
