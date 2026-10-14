"""Read-only UI-ready OPS status projection from an untrusted supplied snapshot.

Never access a network, live runner, queue, secrets, checkpoint or publisher.
Output is a report of *claims*, never a trusted release decision.
"""
import argparse
from datetime import datetime, timezone
import json
import re
import sys

from diagnose import SnapshotError, _parse_unique
from secure_input import SafeInputError, read_snapshot

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,150}\Z")
WORKER = {"RUNNING", "IDLE", "FAILED", "OFFLINE", "UNKNOWN"}
TASK = {"QUEUED", "CLAIMED", "RUNNING", "BLOCKED", "CHECKED", "UNKNOWN"}
CHECKPOINT = {"VERIFIED", "PARTIAL", "MISSING", "UNKNOWN"}
RUN = {"QUEUED", "IN_PROGRESS", "COMPLETED", "UNKNOWN"}
RESULT = {"SUCCESS", "FAILURE", "CANCELLED", "TIMED_OUT", "UNKNOWN"}
PROBLEM = {"MODEL_TIMEOUT", "RUNNER_LOST", "GITHUB_UNAVAILABLE",
           "CHECKPOINT_PARTIAL", "RECEIPT_UNKNOWN", "DUPLICATE_PUBLICATION",
           "FOREIGN_SCOPE", "REVIEW_REJECTED", "MODEL_REPLY_MALFORMED",
           "LEASE_CONFLICT", "OTHER_FAILURE"}
MAX_WORKERS = 50
MAX_TASKS = 100
MAX_RUNS = 60
MAX_PROBLEMS = 100
WORKER_AGE = 300
TASK_AGE = 900


def expect_dict(obj, keys, name):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise SnapshotError("Invalid " + name + " fields")
    return obj


def token(obj, pattern, name):
    if not isinstance(obj, str) or not pattern.fullmatch(obj):
        raise SnapshotError("Invalid " + name)
    return obj


def choice(obj, allowed, name):
    if not isinstance(obj, str) or obj not in allowed:
        raise SnapshotError("Invalid " + name)
    return obj


def number(obj, name, minimum=0):
    if type(obj) is not int or obj < minimum:
        raise SnapshotError("Invalid " + name)
    return obj


def optional_number(obj, name, minimum=1):
    return None if obj is None else number(obj, name, minimum)


def timestamp(obj, name, *, optional=False):
    if obj is None and optional:
        return None
    if not isinstance(obj, str) or len(obj) > 35:
        raise SnapshotError("Invalid " + name)
    try:
        dt = datetime.fromisoformat(obj.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotError("Invalid " + name) from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise SnapshotError("Timezone required for " + name)
    return dt.astimezone(timezone.utc)


def age(observed, previous):
    if previous is None:
        return None
    diff = (observed - previous).total_seconds()
    if diff < 0:
        raise SnapshotError("Snapshot refers to future events")
    return int(diff)


def bounded_list(items, limit, name):
    if not isinstance(items, list) or len(items) > limit:
        raise SnapshotError("Invalid or excessive " + name)
    return items


def snapshot_to_status(snapshot):
    """Pure projection. Claims are never converted to authenticated status."""
    expect_dict(snapshot, ("schema", "scope", "observed_at", "project",
                           "bridge", "workers", "queue", "runs", "problems"),
                "snapshot")
    if snapshot["schema"] != 1 or snapshot["scope"] != "neurofactory-ops-status":
        raise SnapshotError("Foreign snapshot")
    as_of = timestamp(snapshot["observed_at"], "observed_at")
    p = expect_dict(snapshot["project"],
                    ("id", "repository", "branch", "head_sha"), "project")
    project = {
        "id": token(p["id"], IDENT, "project id"),
        "repository": token(p["repository"], REPO, "repository"),
        "branch": token(p["branch"], BRANCH, "branch"),
        "head_sha": token(p["head_sha"], SHA40, "head SHA"),
    }
    source = {"type": "SUPPLIED_SNAPSHOT", "verified": False,
              "observed_at": as_of.isoformat().replace("+00:00", "Z"),
              "freshness": "AT_OBSERVATION_ONLY"}
    bridge = expect_dict(snapshot["bridge"], ("state", "heartbeat_at"), "bridge")
    bridge_claim = choice(bridge["state"], WORKER, "bridge state")
    bridge_age = age(as_of, timestamp(bridge["heartbeat_at"], "bridge heartbeat",
                                     optional=True))
    bridge_view = {
        "reported_state": bridge_claim,
        # A claimed heartbeat is not platform-attested provenance.
        "display_state": "UNKNOWN" if bridge_claim == "RUNNING" or bridge_age is None
            or bridge_age > WORKER_AGE or bridge_claim in ("UNKNOWN", "OFFLINE")
            else bridge_claim,
        "seconds_since_heartbeat": bridge_age,
        "source_verified": False
    }
    workers = []
    used_workers = set()
    for item in bounded_list(snapshot["workers"], MAX_WORKERS, "workers"):
        w = expect_dict(item, ("id", "role", "state", "heartbeat_at", "run_id"),
                        "worker")
        wid = token(w["id"], IDENT, "worker id")
        if wid in used_workers:
            raise SnapshotError("Duplicate worker id")
        used_workers.add(wid)
        raw_state = choice(w["state"], WORKER, "worker state")
        sec = age(as_of, timestamp(w["heartbeat_at"], "heartbeat",
                                   optional=True))
        workers.append({
            "id": wid, "role": token(w["role"], IDENT, "worker role"),
            "reported_state": raw_state,
            "display_state": raw_state if sec is not None and sec <= WORKER_AGE
                and raw_state not in ("RUNNING", "OFFLINE", "UNKNOWN")
                else "UNKNOWN",
            "seconds_since_heartbeat": sec,
            "run_id": optional_number(w["run_id"], "worker run id"),
            "source_verified": False
        })
    tasks = []
    used_tasks = set()
    counts = {}
    checkpoint_counts = {}
    findings = []
    for item in bounded_list(snapshot["queue"], MAX_TASKS, "queue"):
        q = expect_dict(item, ("task_id", "state", "worker_id", "attempt",
                               "last_progress_at", "checkpoint", "run_id"), "task")
        tid = token(q["task_id"], IDENT, "task id")
        if tid in used_tasks:
            raise SnapshotError("Duplicate task id")
        used_tasks.add(tid)
        state = choice(q["state"], TASK, "task state")
        worker_id = None if q["worker_id"] is None else token(
            q["worker_id"], IDENT, "task worker")
        attempt = number(q["attempt"], "task attempt")
        progress_age = age(as_of, timestamp(q["last_progress_at"],
                                            "last progress", optional=True))
        cp = expect_dict(q["checkpoint"], ("state", "sha256", "durable_readback"),
                         "checkpoint")
        cp_state = choice(cp["state"], CHECKPOINT, "checkpoint state")
        cp_digest = cp["sha256"]
        if cp_digest is not None:
            token(cp_digest, SHA256, "checkpoint digest")
        if type(cp["durable_readback"]) is not bool:
            raise SnapshotError("Invalid checkpoint readback flag")
        if cp_state == "VERIFIED" and (cp_digest is None or
                                       cp["durable_readback"] is not True):
            raise SnapshotError("Checkpoint is not internally complete")
        checkpoint_counts[cp_state] = checkpoint_counts.get(cp_state, 0) + 1
        stale = state in ("RUNNING", "CLAIMED") and (progress_age is None
                 or progress_age > TASK_AGE)
        status = "BLOCKED" if state == "BLOCKED" or cp_state == "PARTIAL" else (
            "UNKNOWN" if state in ("RUNNING", "CLAIMED", "CHECKED") else state)
        counts[status] = counts.get(status, 0) + 1
        if cp_state == "PARTIAL":
            findings.append({"code": "CHECKPOINT_PARTIAL", "task_id": tid,
                             "severity": "BLOCKED", "source_verified": False})
        if stale:
            findings.append({"code": "POSSIBLY_STALLED", "task_id": tid,
                             "severity": "WARNING", "source_verified": False})
        tasks.append({
            "task_id": tid, "reported_state": state, "display_state": status,
            "worker_id": worker_id, "attempt": attempt,
            "run_id": optional_number(q["run_id"], "task run id"),
            "seconds_since_progress": progress_age, "possibly_stalled": bool(stale),
            "checkpoint": {"state": cp_state, "sha256": cp_digest,
                           "reported_durable_readback": cp["durable_readback"],
                           "externally_verified": False},
            "source_verified": False
        })
    runs = []
    seen_runs = set()
    for item in bounded_list(snapshot["runs"], MAX_RUNS, "runs"):
        r = expect_dict(item, ("id", "state", "conclusion", "head_sha"), "run")
        rid = number(r["id"], "GitHub run id", 1)
        if rid in seen_runs:
            raise SnapshotError("Duplicate GitHub run id")
        seen_runs.add(rid)
        rs = choice(r["state"], RUN, "run state")
        outcome = choice(r["conclusion"], RESULT, "run conclusion")
        sha = token(r["head_sha"], SHA40, "run head SHA")
        if rs != "COMPLETED" and outcome != "UNKNOWN":
            raise SnapshotError("Unfinished run cannot have a result")
        runs.append({
            "id": rid, "state": rs, "conclusion": outcome, "head_sha": sha,
            "matches_project_head": sha == project["head_sha"],
            "url": "https://github.com/" + project["repository"] +
                   "/actions/runs/" + str(rid),
            "source_verified": False
        })
    # Run numbers are only a ranking of unverified input IDs, not verified times.
    # Exclude foreign source SHA from current-source outcome summaries.
    same_source_runs = [r for r in runs if r["matches_project_head"]]
    def _newest(claims):
        return max(claims, key=lambda r: r["id"]) if claims else None
    run_highlights = {
        "selection": "HIGHEST_REPORTED_RUN_ID_NOT_GITHUB_ATTESTED",
        "latest_reported": _newest(same_source_runs),
        "last_reported_success": _newest(
            [r for r in same_source_runs if r["state"] == "COMPLETED"
             and r["conclusion"] == "SUCCESS"]),
        "last_reported_failure": _newest(
            [r for r in same_source_runs if r["state"] == "COMPLETED"
             and r["conclusion"] in ("FAILURE", "TIMED_OUT", "CANCELLED")]),
        "source_verified": False
    }
    incidents = {}
    for item in bounded_list(snapshot["problems"], MAX_PROBLEMS, "problems"):
        problem = expect_dict(item, ("code", "task_id", "run_id"), "problem")
        code = choice(problem["code"], PROBLEM, "problem code")
        tid = None if problem["task_id"] is None else token(
            problem["task_id"], IDENT, "problem task")
        run_id = optional_number(problem["run_id"], "problem run id")
        key = (code, tid)
        incidents.setdefault(key, set())
        if run_id is not None:
            incidents[key].add(run_id)
    for (code, tid), run_ids in sorted(incidents.items(), key=lambda x: str(x[0])):
        findings.append({
            "code": code, "task_id": tid,
            "run_ids": sorted(run_ids), "distinct_reported_runs": len(run_ids),
            "recurrent_in_snapshot": len(run_ids) >= 2,
            "severity": "BLOCKED" if code in ("RECEIPT_UNKNOWN",
                 "DUPLICATE_PUBLICATION", "FOREIGN_SCOPE",
                 "CHECKPOINT_PARTIAL") else "WARNING",
            "source_verified": False
        })
    return {
        "schema": 1, "type": "neurofactory.ops.status_view",
        "project": project, "source": source,
        "bridge": bridge_view, "workers": workers,
        "queue": tasks, "queue_counts": dict(sorted(counts.items())),
        "checkpoint_counts": dict(sorted(checkpoint_counts.items())),
        "runs": runs, "run_highlights": run_highlights, "problems": findings,
        "stopped_tasks": [q["task_id"] for q in tasks
                          if q["display_state"] == "BLOCKED"],
        "possibly_stalled_tasks": [q["task_id"] for q in tasks
                                    if q["possibly_stalled"]],
        "integrity": {"independent_review": "NOT_VERIFIED",
                      "publisher_receipt": "UNKNOWN",
                      "snapshot_authenticated": False},
        "actions_allowed": {"restart": False, "retry": False,
                            "recover": False, "publish": False, "merge": False,
                            "send_chatgpt": False},
        "limitations": [
            "This is a read-only view of supplied claims, not live monitoring.",
            "Runner states, GitHub run IDs and checkpoint flags are not attested.",
            "Stall detection uses snapshot times, never a verified wall clock."
        ]
    }


def concise_text(view):
    """Minimal UI preview; do not misrepresent reported state as verified live."""
    lines = ["НЕЙРОЗАВОД — OPS", "Источник: непроверенный внешний снимок",
             "Проект: " + view["project"]["id"],
             "Коммит: " + view["project"]["head_sha"],
             "Windows-мост (по снимку): " + view["bridge"]["display_state"]]
    lines.append("Исполнители: " + str(len(view["workers"])))
    for w in view["workers"]:
        lines.append("  " + w["id"] + ": " + w["display_state"])
    lines.append("Очередь: " + str(len(view["queue"])))
    for q in view["queue"]:
        suffix = " / возможное зависание" if q["possibly_stalled"] else ""
        lines.append("  " + q["task_id"] + ": " + q["display_state"] + suffix)
    last_good = view["run_highlights"]["last_reported_success"]
    last_bad = view["run_highlights"]["last_reported_failure"]
    lines.append("Последний заявленный успешный запуск: " +
                 (str(last_good["id"]) if last_good else "UNKNOWN"))
    lines.append("Последний заявленный отказ: " +
                 (str(last_bad["id"]) if last_bad else "UNKNOWN"))
    lines.append("Остановленные задания: " +
                 (", ".join(view["stopped_tasks"]) if view["stopped_tasks"] else "не заявлены"))
    lines.append("Контрольные точки: " + json.dumps(
        view["checkpoint_counts"], ensure_ascii=False, sort_keys=True))
    lines.append("Обнаруженные признаки проблем: " + str(len(view["problems"])))
    for p in view["problems"]:
        lines.append("  " + p["code"] + ": " + (p["task_id"] or "общая"))
    lines.append("Все операции изменения/восстановления/публикации ЗАПРЕЩЕНЫ.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline OPS read-only UI status")
    parser.add_argument("snapshot")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        view = snapshot_to_status(_parse_unique(read_snapshot(args.snapshot)))
        if args.format == "text":
            print(concise_text(view))
        else:
            print(json.dumps(view, ensure_ascii=False, sort_keys=True))
        return 0
    except (SnapshotError, SafeInputError, OSError) as exc:
        print("OPS_STATUS_REFUSED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
