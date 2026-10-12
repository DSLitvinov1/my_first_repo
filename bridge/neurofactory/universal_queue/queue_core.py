"""Safe, auditable, serial job queue for synthetic Python app prototypes.

This module never executes text as shell commands and never publishes unverified source.
Model execution and evidence generation must be implemented by a separately sandboxed runner.
"""
import copy
import hashlib
import re
from datetime import datetime, timezone

class QueueError(ValueError):
    pass

MAX_TASKS = 12
MAX_REPAIRS = 3
MAX_TEXT_LENGTH = 1800
SUITES = {"mini_crm": 20, "order_calculator": 10, "packaging_calculator": 10,
          "temperature_converter": 10, "fuel_trip_estimator": 10}
FORBIDDEN = (
    r"https?://", r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", r"\b(?:api.?key|private.?key|парол\w*|токен\w*|секрет\w*)\b",
    r"\b(?:telegram|whatsapp|gmail|production|продакшн|боев(?:ой|ую|ые)|оплат[ауые]|платеж[иа])\b",
)

def now():
    return datetime.now(timezone.utc).isoformat()

def route(brief):
    text = brief.casefold()
    if any(word in text for word in ("температур", "цельси", "фаренгейт")):
        return "temperature_converter"
    if any(word in text for word in ("топлив", "бензин", "расход топлива")):
        return "fuel_trip_estimator"
    if any(word in text for word in ("crm", "срм", "мини-срм", "мини-crm")):
        return "mini_crm"
    if any(word in text for word in ("упаковк", "короб", "упаковать")):
        return "packaging_calculator"
    if any(word in text for word in ("калькулятор", "расчёт заказ", "расчет заказ", "стоимост")):
        return "order_calculator"
    return "unclassified"

def validate_brief(brief):
    if not isinstance(brief, str) or not 15 <= len(brief.strip()) <= MAX_TEXT_LENGTH:
        raise QueueError("Need a bounded nonempty Russian-language description")
    if not re.search(r"[А-Яа-яЁё]", brief):
        raise QueueError("Description must include Russian text")
    if any(re.search(rule, brief, flags=re.IGNORECASE) for rule in FORBIDDEN):
        raise QueueError("Only anonymous, noncommercial, synthetic tasks without accounts, secrets or links")
    return brief.strip()

def new_queue():
    return {
        "schema": 1, "enabled": True, "scope": "synthetic_only",
        "paid_services": False, "production_changes": False, "network_effects": False,
        "tasks": [], "events": [], "next_number": 1
    }

def validate_queue(queue):
    if not isinstance(queue, dict) or queue.get("schema") != 1 or queue.get("scope") != "synthetic_only":
        raise QueueError("Wrong queue identity")
    if queue.get("enabled") is not True or any(queue.get(k) is not False for k in (
        "paid_services", "production_changes", "network_effects")):
        raise QueueError("Unsafe queue policy")
    tasks = queue.get("tasks")
    if not isinstance(tasks, list) or len(tasks) > MAX_TASKS:
        raise QueueError("Queue limit exceeded")
    ids = [t.get("id") for t in tasks]
    if len(ids) != len(set(ids)):
        raise QueueError("Duplicate ids")
    if sum(t.get("state") in {"writing", "testing", "reviewing", "publishing"} for t in tasks) > 1:
        raise QueueError("More than one active job")
    for t in tasks:
        validate_brief(t.get("brief"))
        if t.get("kind") != route(t["brief"]):
            raise QueueError("Route mismatch")
        if t.get("state") not in {"pending", "writing", "testing", "reviewing", "publishing",
                                   "verified_done", "blocked", "failed"}:
            raise QueueError("Unknown task status")
        if not isinstance(t.get("attempts"), int) or not 0 <= t["attempts"] <= MAX_REPAIRS:
            raise QueueError("Invalid attempt counter")
    return queue

def add_task(queue, brief):
    validate_queue(queue)
    if len(queue["tasks"]) >= MAX_TASKS:
        raise QueueError("Queue full")
    brief = validate_brief(brief)
    kind = route(brief)
    num = queue["next_number"]
    if not isinstance(num, int) or num < 1:
        raise QueueError("Invalid sequence")
    task = {
        "id": "NFQ-" + str(num).zfill(4), "brief": brief,
        "kind": kind, "state": "pending" if kind in SUITES else "blocked",
        "stage": "writer", "attempts": 0, "suite_size": SUITES.get(kind, 0),
        "proof": {}, "error": "Independent acceptance suite is missing" if kind not in SUITES else "",
    }
    queue["next_number"] += 1
    queue["tasks"].append(task)
    queue["events"].append({"at": now(), "id": task["id"], "event": "queued" if kind in SUITES else "blocked_missing_suite"})
    validate_queue(queue)
    return task["id"]

def next_action(queue):
    validate_queue(queue)
    active = next((t for t in queue["tasks"] if t["state"] in {
        "writing", "testing", "reviewing", "publishing"}), None)
    if active is None:
        active = next((t for t in queue["tasks"] if t["state"] == "pending"), None)
        if active is None:
            return None
        active["state"] = "writing"
        queue["events"].append({"at": now(), "id": active["id"], "event": "started"})
    return {"task_id": active["id"], "kind": active["kind"], "stage": active["stage"],
            "attempt": active["attempts"] + 1, "required_tests": active["suite_size"],
            "brief": active["brief"], "previous_error": active["error"]}

def accept_evidence(queue, task_id, evidence):
    """Only an isolated runner may supply verified evidence after actual tests."""
    validate_queue(queue)
    task = next((t for t in queue["tasks"] if t["id"] == task_id), None)
    if task is None or task["state"] not in {"writing", "testing", "reviewing", "publishing"}:
        raise QueueError("No active task at that stage")
    if not isinstance(evidence, dict) or evidence.get("verified_by_runner") is not True:
        raise QueueError("Independent runner proof required")
    if evidence.get("stage") != task["stage"]:
        raise QueueError("Out-of-order stage")
    event = evidence.get("outcome")
    if event not in ("pass", "fail"):
        raise QueueError("Unknown verification outcome")
    if event == "fail":
        task["attempts"] += 1
        task["error"] = str(evidence.get("reason", "Unspecified failure"))[:260]
        task["proof"] = {}
        if task["attempts"] >= MAX_REPAIRS:
            task["state"] = "failed"
            task["stage"] = "closed"
        else:
            task["state"] = "writing"
            task["stage"] = "writer"
        queue["events"].append({"at": now(), "id": task_id, "event": "failed_attempt", "attempt": task["attempts"]})
    elif task["stage"] == "writer":
        hashes = evidence.get("source_hashes")
        if not isinstance(hashes, dict) or len(hashes) < 2 or len(set(hashes.values())) != len(hashes):
            raise QueueError("Distinct source file hashes required")
        if any(not re.fullmatch("[a-f0-9]{64}", str(v)) for v in hashes.values()):
            raise QueueError("Bad file digest")
        task["proof"]["sources"] = copy.deepcopy(hashes)
        task["stage"] = task["state"] = "testing"
    elif task["stage"] == "testing":
        if evidence.get("total") != task["suite_size"] or evidence.get("passed") != task["suite_size"]:
            raise QueueError("Real full independent acceptance suite required")
        task["proof"]["tests"] = evidence["passed"]
        task["stage"] = task["state"] = "reviewing"
    elif task["stage"] == "reviewing":
        if evidence.get("reviewer") != "qwen3:4b" or evidence.get("verdict") != "REVIEW_OK":
            raise QueueError("Separate second agent approval required")
        task["proof"]["reviewer"] = evidence["reviewer"]
        task["stage"] = task["state"] = "publishing"
    elif task["stage"] == "publishing":
        if not task["proof"].get("sources") or task["proof"].get("tests") != task["suite_size"] or not task["proof"].get("reviewer"):
            raise QueueError("Incomplete source, test or review evidence")
        receipt = evidence.get("manifest_sha256")
        if not isinstance(receipt, str) or not re.fullmatch("[a-f0-9]{64}", receipt):
            raise QueueError("Verified GitHub publication manifest required")
        task["proof"]["manifest_sha256"] = receipt
        task["stage"] = "closed"
        task["state"] = "verified_done"
    else:
        raise QueueError("Unsupported transition")
    queue["events"].append({"at": now(), "id": task_id, "event": task["state"]})
    del queue["events"][:-150]
    validate_queue(queue)
    return task["state"]

def progress(queue):
    validate_queue(queue)
    states = [t["state"] for t in queue["tasks"]]
    return {"total": len(states), "verified": states.count("verified_done"),
            "failed": states.count("failed"), "blocked": states.count("blocked"),
            "remaining": sum(s not in ("verified_done", "failed", "blocked") for s in states)}

if __name__ == "__main__":
    import json
    q = new_queue()
    add_task(q, "Создай учебную мини CRM для вымышленных заявок без интернета")
    print(json.dumps({"progress": progress(q), "next": next_action(q)}, ensure_ascii=False))
