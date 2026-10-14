"""Strict boundary for direct, untrusted OPS status projections.

A projected dictionary is not proof that status_adapter produced it. Check
every forwarded field, recompute aggregate claims, and fail closed.
"""
import re
from datetime import datetime
from collections import Counter

from diagnose import SnapshotError
from status_adapter import (
    IDENT, SHA40, SHA256, REPO, BRANCH, WORKER, TASK, RUN,
    RESULT, PROBLEM, MAX_WORKERS, MAX_TASKS, MAX_RUNS, MAX_PROBLEMS,
    WORKER_AGE, TASK_AGE,
)

PROJECT_KEYS = {"id", "repository", "branch", "head_sha"}
SOURCE_KEYS = {"type", "verified", "observed_at", "freshness"}
RUN_KEYS = {"id", "state", "conclusion", "head_sha",
            "matches_project_head", "url", "source_verified"}
TASK_KEYS = {"task_id", "reported_state", "display_state", "worker_id",
             "attempt", "run_id", "seconds_since_progress", "possibly_stalled",
             "checkpoint", "source_verified"}
WORKER_KEYS = {"id", "role", "reported_state", "display_state",
               "seconds_since_heartbeat", "run_id", "source_verified"}
VIEW_KEYS = {"schema", "type", "project", "source", "bridge", "workers",
             "queue", "queue_counts", "checkpoint_counts", "runs",
             "run_highlights", "problems", "stopped_tasks",
             "possibly_stalled_tasks", "integrity", "actions_allowed",
             "limitations"}


def refuse():
    raise SnapshotError("Untrusted or inconsistent OPS projected view")


def exact(obj, keys):
    if type(obj) is not dict or set(obj) != keys:
        refuse()
    return obj


def field(value, pattern):
    if type(value) is not str or not pattern.fullmatch(value):
        refuse()
    return value


def enum(value, choices):
    if type(value) is not str or value not in choices:
        refuse()
    return value


def num(value, *, min_value=0, nullable=False):
    if value is None and nullable:
        return
    if type(value) is not int or value < min_value or value > 1_000_000_000_000:
        refuse()


def records(value, limit):
    if type(value) is not list or len(value) > limit:
        refuse()
    return value


def status_expected(claim, seconds):
    if claim in ("RUNNING", "UNKNOWN", "OFFLINE") or seconds is None or seconds > WORKER_AGE:
        return "UNKNOWN"
    return claim


def guard_project_view(view):
    """Validate a projection before forwarding it into the two-layer UI."""
    exact(view, VIEW_KEYS)
    if type(view["schema"]) is not int or view["schema"] != 1 or view["type"] != "neurofactory.ops.status_view":
        refuse()
    project = exact(view["project"], PROJECT_KEYS)
    field(project["id"], IDENT)
    field(project["repository"], REPO)
    field(project["branch"], BRANCH)
    if ".." in project["branch"] or "//" in project["branch"]:
        refuse()
    field(project["head_sha"], SHA40)

    source = exact(view["source"], SOURCE_KEYS)
    if (source["type"] != "SUPPLIED_SNAPSHOT" or source["verified"] is not False
            or source["freshness"] != "AT_OBSERVATION_ONLY"):
        refuse()
    when = source["observed_at"]
    if type(when) is not str or len(when) > 35 or not when.endswith("Z"):
        refuse()
    try:
        observed = datetime.fromisoformat(when.replace("Z", "+00:00"))
    except ValueError:
        refuse()
    if observed.utcoffset().total_seconds() != 0:
        refuse()

    exact(view["integrity"], {"independent_review", "publisher_receipt", "snapshot_authenticated"})
    if view["integrity"] != {"independent_review": "NOT_VERIFIED",
                             "publisher_receipt": "UNKNOWN", "snapshot_authenticated": False}:
        refuse()
    actions = exact(view["actions_allowed"], {
        "restart", "retry", "recover", "publish", "merge", "send_chatgpt"})
    if any(flag is not False for flag in actions.values()):
        refuse()

    bridge = exact(view["bridge"], {
        "reported_state", "display_state", "seconds_since_heartbeat",
        "source_verified"})
    state = enum(bridge["reported_state"], WORKER)
    secs = bridge["seconds_since_heartbeat"]
    num(secs, nullable=True)
    if bridge["source_verified"] is not False or bridge["display_state"] != status_expected(state, secs):
        refuse()

    worker_ids = set()
    for worker in records(view["workers"], MAX_WORKERS):
        exact(worker, WORKER_KEYS)
        wid = field(worker["id"], IDENT)
        if wid in worker_ids:
            refuse()
        worker_ids.add(wid)
        field(worker["role"], IDENT)
        state = enum(worker["reported_state"], WORKER)
        secs = worker["seconds_since_heartbeat"]
        num(secs, nullable=True)
        num(worker["run_id"], min_value=1, nullable=True)
        if (worker["source_verified"] is not False or
                worker["display_state"] != status_expected(state, secs)):
            refuse()

    task_ids = set()
    counts = Counter()
    cp_counts = Counter()
    blocked = []
    stalled = []
    for task in records(view["queue"], MAX_TASKS):
        exact(task, TASK_KEYS)
        tid = field(task["task_id"], IDENT)
        if tid in task_ids:
            refuse()
        task_ids.add(tid)
        state = enum(task["reported_state"], TASK)
        if task["worker_id"] is not None:
            field(task["worker_id"], IDENT)
        num(task["attempt"])
        num(task["run_id"], min_value=1, nullable=True)
        progress_age = task["seconds_since_progress"]
        num(progress_age, nullable=True)
        cp = exact(task["checkpoint"], {
            "state", "sha256", "reported_durable_readback", "externally_verified"})
        enum(cp["state"], {"VERIFIED", "PARTIAL", "MISSING", "UNKNOWN"})
        if cp["sha256"] is not None:
            field(cp["sha256"], SHA256)
        if (type(cp["reported_durable_readback"]) is not bool or
                cp["externally_verified"] is not False):
            refuse()
        if (cp["state"] == "VERIFIED" and
                (cp["sha256"] is None or cp["reported_durable_readback"] is not True)):
            refuse()
        expected_stall = state in ("RUNNING", "CLAIMED") and (
            progress_age is None or progress_age > TASK_AGE)
        expected_state = ("BLOCKED" if state == "BLOCKED" or cp["state"] == "PARTIAL"
                          else "UNKNOWN" if state in ("RUNNING", "CLAIMED", "CHECKED")
                          else state)
        if (task["source_verified"] is not False or
                task["possibly_stalled"] is not expected_stall or
                task["display_state"] != expected_state):
            refuse()
        counts[expected_state] += 1
        cp_counts[cp["state"]] += 1
        if expected_state == "BLOCKED":
            blocked.append(tid)
        if expected_stall:
            stalled.append(tid)
    if (view["queue_counts"] != dict(counts) or
            view["checkpoint_counts"] != dict(cp_counts) or
            view["stopped_tasks"] != blocked or
            view["possibly_stalled_tasks"] != stalled):
        refuse()
    for key in ("queue_counts", "checkpoint_counts"):
        if type(view[key]) is not dict:
            refuse()

    seen = set()
    runs = []
    for run in records(view["runs"], MAX_RUNS):
        exact(run, RUN_KEYS)
        rid = run["id"]
        num(rid, min_value=1)
        if rid in seen:
            refuse()
        seen.add(rid)
        stage = enum(run["state"], RUN)
        conclusion = enum(run["conclusion"], RESULT)
        sha = field(run["head_sha"], SHA40)
        if stage != "COMPLETED" and conclusion != "UNKNOWN":
            refuse()
        if (run["matches_project_head"] is not (sha == project["head_sha"])
                or run["source_verified"] is not False or
                run["url"] != "https://github.com/" + project["repository"] +
                    "/actions/runs/" + str(rid)):
            refuse()
        runs.append(run)
    highlight = exact(view["run_highlights"], {
        "selection", "latest_reported", "last_reported_success",
        "last_reported_failure", "source_verified"})
    if (highlight["source_verified"] is not False or
            highlight["selection"] != "HIGHEST_REPORTED_RUN_ID_NOT_GITHUB_ATTESTED"):
        refuse()
    matching = [r for r in runs if r["matches_project_head"]]
    def latest(items):
        return max(items, key=lambda r: r["id"]) if items else None
    expected = {
        "latest_reported": latest(matching),
        "last_reported_success": latest([
            r for r in matching if r["state"] == "COMPLETED"
            and r["conclusion"] == "SUCCESS"]),
        "last_reported_failure": latest([
            r for r in matching if r["state"] == "COMPLETED"
            and r["conclusion"] in ("FAILURE", "TIMED_OUT", "CANCELLED")]),
    }
    for key, actual in expected.items():
        if highlight[key] != actual:
            refuse()

    for problem in records(view["problems"], MAX_PROBLEMS + 2 * MAX_TASKS):
        if type(problem) is not dict:
            refuse()
        basic = {"code", "task_id", "severity", "source_verified"}
        extended = basic | {"run_ids", "distinct_reported_runs", "recurrent_in_snapshot"}
        if set(problem) not in (basic, extended):
            refuse()
        code = enum(problem["code"], PROBLEM | {"POSSIBLY_STALLED"})
        if problem["task_id"] is not None:
            field(problem["task_id"], IDENT)
        if problem["source_verified"] is not False:
            refuse()
        severity = enum(problem["severity"], {"WARNING", "BLOCKED"})
        expected_severity = ("BLOCKED" if code in (
            "CHECKPOINT_PARTIAL", "RECEIPT_UNKNOWN", "DUPLICATE_PUBLICATION",
            "FOREIGN_SCOPE") else "WARNING")
        if severity != expected_severity:
            refuse()
        if set(problem) == extended:
            runs_seen = records(problem["run_ids"], MAX_PROBLEMS)
            for rid in runs_seen:
                num(rid, min_value=1)
            if (runs_seen != sorted(set(runs_seen)) or
                problem["distinct_reported_runs"] != len(runs_seen) or
                problem["recurrent_in_snapshot"] is not (len(runs_seen) >= 2)):
                refuse()

    if (type(view["limitations"]) is not list or len(view["limitations"]) != 3 or
            any(type(item) is not str or len(item) > 200 for item in view["limitations"])):
        refuse()
    return view
