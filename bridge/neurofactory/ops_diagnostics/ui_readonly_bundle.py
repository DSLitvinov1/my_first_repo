"""UI handoff: two distinct read-only layers with provenance preserved.

Coordinator lane board and OPS project detail are NOT interchangeable truth
sources. Inputs are snapshots, never run authorization. No network or writes.
"""
import argparse
import json
import re
import sys

from diagnose import SnapshotError, _parse_unique
from secure_input import SafeInputError, read_snapshot
from status_adapter import snapshot_to_status, concise_text
from ops_projection_guard import guard_project_view

LANES = ("CORE", "PROVIDERS", "COORDINATOR", "REVIEW", "OPS",
         "SKILLS", "UI", "HANDOFF", "GODMODE")
BOARD_PHASE = {"unknown", "candidate", "implementation", "testing",
               "waiting_dependency", "waiting_review", "blocked", "paused"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"DSLitvinov1/(?:my_first_repo|lesson3\.1)\Z")
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,180}\Z")
GITHUB = re.compile(r"https://github\.com/DSLitvinov1/(?:my_first_repo|lesson3\.1)/(?:issues|pull)/[1-9][0-9]{0,8}\Z")


def _validate_board(board):
    if board is None:
        return None
    required = {"schema", "kind", "provenance", "cost_authorized_usd",
                "external_execution_allowed", "external_publication_allowed",
                "automatic_retry_allowed", "lanes"}
    if type(board) is not dict or set(board) != required:
        raise SnapshotError("Unknown coordination board fields")
    if (type(board["schema"]) is not int or board["schema"] != 1 or
        board["kind"] != "read_only_coordination_board" or
        board["provenance"] != "self_reported_git_refs_not_attested" or
        type(board["cost_authorized_usd"]) is not int or
        board["cost_authorized_usd"] != 0 or
        any(board[k] is not False for k in (
            "external_execution_allowed", "external_publication_allowed",
            "automatic_retry_allowed"))):
        raise SnapshotError("Unsafe coordination board")
    entries = board["lanes"]
    if type(entries) is not list or len(entries) != len(LANES):
        raise SnapshotError("Incomplete coordination board")
    seen = set()
    clean = []
    for row in entries:
        if type(row) is not dict or set(row) != {
                "lane", "reported_phase", "evidence_status",
                "release_allowed", "commit", "issue_url", "source"}:
            raise SnapshotError("Invalid lane entry")
        lane = row["lane"]
        if type(lane) is not str or lane not in LANES or lane in seen:
            raise SnapshotError("Duplicate or foreign lane")
        seen.add(lane)
        phase = row["reported_phase"]
        if (type(phase) is not str or phase not in BOARD_PHASE or
                row["evidence_status"] != "not_verified" or
                row["release_allowed"] is not False):
            raise SnapshotError("Forged phase or approval")
        sha, url, source = row["commit"], row["issue_url"], row["source"]
        if phase == "unknown":
            if (sha, url, source) != (None, None, None):
                raise SnapshotError("Unknown lane carries fabricated evidence")
        else:
            if (type(sha) is not str or not SHA.fullmatch(sha) or
                    type(url) is not str or not GITHUB.fullmatch(url) or
                    type(source) is not dict or set(source) != {
                        "repository", "branch"}):
                raise SnapshotError("Invalid lane evidence")
            repo, branch = source["repository"], source["branch"]
            if (type(repo) is not str or not REPO.fullmatch(repo) or
                    type(branch) is not str or not BRANCH.fullmatch(branch) or
                    ".." in branch or "//" in branch or
                    url.split("/")[4] != repo.split("/")[1]):
                raise SnapshotError("Inconsistent lane evidence")
        if lane == "HANDOFF" and phase not in ("paused", "unknown"):
            raise SnapshotError("HANDOFF must remain paused")
        clean.append({
            "lane": lane, "reported_phase": phase, "evidence_status": "not_verified",
            "commit": sha, "issue_url": url, "source": source,
            "release_allowed": False
        })
    if seen != set(LANES):
        raise SnapshotError("Missing coordination lanes")
    return clean


def join_readonly_views(lane_board=None, project_status=None):
    """Construct an interface payload, NEVER an authorization or live status."""
    lanes = _validate_board(lane_board)
    if project_status is not None:
        project_status = guard_project_view(project_status)
        if (type(project_status) is not dict or
                project_status.get("schema") != 1 or
                project_status.get("type") != "neurofactory.ops.status_view" or
                project_status.get("source", {}).get("verified") is not False or
                project_status.get("integrity", {}).get("snapshot_authenticated") is not False or
                type(project_status.get("actions_allowed")) is not dict or
                not project_status["actions_allowed"] or
                any(val is not False for val in project_status["actions_allowed"].values())):
            raise SnapshotError("Untrusted or release-capable OPS detail")
        p = project_status["project"]
        if type(p) is not dict or any(type(p.get(k)) is not str for k in
               ("repository", "branch", "head_sha", "id")):
            raise SnapshotError("Invalid OPS project")
        if type(project_status.get("run_highlights")) is not dict:
            raise SnapshotError("Missing OPS run summary")
        bridge = project_status["bridge"]
        workers = project_status["workers"]
        tasks = project_status["queue"]
        checkpoints = project_status["checkpoint_counts"]
        problems = project_status["problems"]
        if (type(bridge) is not dict or type(workers) is not list or
            type(tasks) is not list or type(checkpoints) is not dict or
            type(problems) is not list):
            raise SnapshotError("Invalid OPS lists")
        report = {
            "project": p,
            "source_verified": False,
            "observed_at": project_status["source"]["observed_at"],
            "bridge": {
                "reported_state": bridge["reported_state"],
                "display_state": "UNKNOWN",  # supplied heartbeat is not authenticated
                "seconds_since_reported_heartbeat":
                    bridge["seconds_since_heartbeat"]},
            "workers": [{
                "id": w["id"], "role": w["role"],
                "reported_state": w["reported_state"],
                "display_state": "UNKNOWN",
                "seconds_since_reported_heartbeat":
                    w["seconds_since_heartbeat"]
            } for w in workers],
            "queue": [{
                "task_id": t["task_id"], "reported_state": t["reported_state"],
                "display_state": "BLOCKED" if t["display_state"] == "BLOCKED"
                                      else "UNKNOWN",
                "possibly_stalled": t["possibly_stalled"],
                "checkpoint": {
                    "reported_state": t["checkpoint"]["state"],
                    "externally_verified": False}
            } for t in tasks],
            "checkpoint_counts": checkpoints,
            "problems": problems,
            "stopped_tasks": project_status["stopped_tasks"],
            "possibly_stalled_tasks": project_status["possibly_stalled_tasks"],
            "last_reported_success":
                project_status["run_highlights"]["last_reported_success"],
            "last_reported_failure":
                project_status["run_highlights"]["last_reported_failure"],
            "last_reported_run":
                project_status["run_highlights"]["latest_reported"],
            "last_run_sort": "HIGHEST_REPORTED_RUN_ID_NOT_GITHUB_ATTESTED"
        }
    else:
        report = {
            "project": None, "source_verified": False, "observed_at": None,
            "bridge": {"reported_state": "UNKNOWN", "display_state": "UNKNOWN",
                       "seconds_since_reported_heartbeat": None},
            "workers": [], "queue": [], "checkpoint_counts": {},
            "problems": [], "stopped_tasks": [], "possibly_stalled_tasks": [],
            "last_reported_success": None, "last_reported_failure": None,
            "last_reported_run": None,
            "last_run_sort": "HIGHEST_REPORTED_RUN_ID_NOT_GITHUB_ATTESTED"
        }
    matched = None
    condition = "SOURCE_MISSING"
    if lanes is not None and project_status is not None:
        ops = next(x for x in lanes if x["lane"] == "OPS")
        if ops["commit"] is not None:
            matched = (ops["commit"] == report["project"]["head_sha"] and
                       ops["source"] == {
                         "repository": report["project"]["repository"],
                         "branch": report["project"]["branch"]})
            condition = "MATCHES_UNVERIFIED_DECLARATIONS" if matched else "DECLARATIONS_DIFFER"
    return {
        "schema": 1, "kind": "neurofactory_ops_ui_readonly_bundle",
        "board": {"kind": "read_only_coordination_board",
                  "source_verified": False, "lanes": lanes or [{
                       "lane": lane, "reported_phase": "unknown",
                       "evidence_status": "not_verified", "release_allowed": False,
                       "commit": None, "issue_url": None, "source": None
                  } for lane in LANES]},
        "project_detail": report,
        "consistency": {"board_project_match": matched, "status": condition,
                        "does_not_attest_provenance": True},
        "trust": {"live_source_verified": False, "independent_review": False,
                  "release_authorized": False, "all_sources_untrusted": True},
        "actions_allowed": {"recover": False, "retry": False, "publish": False,
                            "merge": False, "restart": False, "send_chatgpt": False}
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline two-layer OPS/UI view")
    parser.add_argument("--board")
    parser.add_argument("--project")
    args = parser.parse_args(argv)
    try:
        lane_board = _parse_unique(read_snapshot(args.board)) if args.board else None
        raw_project = _parse_unique(read_snapshot(args.project)) if args.project else None
        projection = snapshot_to_status(raw_project) if raw_project is not None else None
        print(json.dumps(join_readonly_views(lane_board, projection),
                         ensure_ascii=False, sort_keys=True))
        return 0
    except (SnapshotError, SafeInputError, OSError, KeyError, TypeError) as exc:
        print("OPS_UI_REFUSED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
