"""Neurofactory development control plane: no demo apps, no paid services.

The model does not choose its own privileges. Roadmap is an approved static plan.
Publishing a prompt does NOT itself mark a development milestone completed.
"""
import argparse
import hashlib
import json
import pathlib
import re
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent
ROADMAP = ROOT / "roadmap.json"
OUTBOX = ROOT / "chat_outbox.json"
SAFE_PREFIXES = ("bridge/neurofactory/", ".github/workflows/neurofactory-")
STATE_VALUES = {"pending", "active", "blocked", "verified"}
REQUIRE_FREE = True

class PlanError(ValueError):
    pass

def validate(plan):
    if not isinstance(plan, dict) or plan.get("version") != 1 or plan.get("mode") != "self_development":
        raise PlanError("Wrong self-development plan")
    if plan.get("free_only") is not True or plan.get("forbid_other_projects") is not True:
        raise PlanError("Unsafe development privilege")
    paths = plan.get("allow_changes_prefixes")
    if not isinstance(paths, list) or paths != list(SAFE_PREFIXES):
        raise PlanError("Changed project-only allowlist")
    milestones = plan.get("milestones")
    if not isinstance(milestones, list) or not 1 <= len(milestones) <= 12:
        raise PlanError("Invalid roadmap size")
    ids = [t.get("id") for t in milestones if isinstance(t, dict)]
    if len(ids) != len(milestones) or len(set(ids)) != len(ids):
        raise PlanError("Duplicate or invalid milestone IDs")
    if sum(t.get("state") == "active" for t in milestones) > 1:
        raise PlanError("Only one actively changing milestone")
    seen = set()
    for t in milestones:
        if t.get("state") not in STATE_VALUES or not re.fullmatch(r"NF-DEV-\d{2}", t.get("id", "")):
            raise PlanError("Unknown milestone status or ID")
        for key in ("title", "objective", "prompt"):
            text = t.get(key)
            if not isinstance(text, str) or not 25 <= len(text) <= 2400:
                raise PlanError("Missing or oversized milestone content")
            if re.search(r"(?:token|токен|секрет|парол|api.key|https?://|\bexec\b)", text, re.IGNORECASE):
                raise PlanError("Sensitive or dangerous instruction")
        if not isinstance(t.get("acceptance"), list) or not t["acceptance"]:
            raise PlanError("Missing acceptance criteria")
        deps = t.get("depends_on", [])
        if not isinstance(deps, list) or any(d not in seen for d in deps):
            raise PlanError("Milestone dependency missing or out of order")
        if t["state"] in ("active", "verified") and any(
             next(x for x in milestones if x["id"] == dep)["state"] != "verified" for dep in deps):
            raise PlanError("Milestone cannot proceed before dependencies verified")
        seen.add(t["id"])
    return plan

def select(plan):
    validate(plan)
    byid = {t["id"]: t for t in plan["milestones"]}
    active = next((t for t in plan["milestones"] if t["state"] == "active"), None)
    if active:
        return active
    return next((t for t in plan["milestones"] if t["state"] == "pending"
                 and all(byid[d]["state"] == "verified" for d in t.get("depends_on", []))), None)

def outbox(plan):
    chosen = select(plan)
    if chosen is None:
        return {"schema": 1, "state": "all_verified_or_blocked", "task_id": None,
                "sequence": None, "prompt": "", "delivery": "no_chat_send"}
    instructions = (
        chosen["prompt"].strip() + "\n"
        "Критерии приёмки: " + "; ".join(chosen["acceptance"]) + ".\n"
        "Ограничения: только нейрозавод; бесплатно; два независимых агента; "
        "реальные проверки и сохранение только подтверждённых результатов в GitHub; "
        "без учебных приложений и без правок чужих проектов; не закрывать пользовательские программы. "
        "В конце отчёта обязательно укажи оставшийся процент и следующий промпт."
    )
    # Stable id changes only if the approved plan or current milestone changes.
    stable = json.dumps({"id": chosen["id"], "prompt": instructions}, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(stable.encode("utf-8")).hexdigest()
    return {
        "schema": 1, "task_id": chosen["id"], "sequence": digest[:24],
        "state": "ready_for_chat_agent", "delivery": "requires_bound_chat",
        "destination_origin": "https://chatgpt.com",
        "destination_conversation": None,
        "auto_send_enabled": False,
        "prompt": instructions,
        "created_from_roadmap": True,
        "requires_result_evidence": True,
        "sha256": digest,
    }

def test_evidence(evidence):
    """Strong constraints for completion; server-side API verification still required."""
    if not isinstance(evidence, dict):
        raise PlanError("Evidence missing")
    if evidence.get("repo") != "DSLitvinov1/my_first_repo":
        raise PlanError("Wrong repository evidence")
    if evidence.get("branch") != "neurofactory-public-lab-20261012":
        raise PlanError("Wrong branch evidence")
    if evidence.get("tests_passed") is not True or evidence.get("independent_review") is not True:
        raise PlanError("Real independent checks not reported")
    commit = evidence.get("commit_sha")
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise PlanError("Expected immutable verified commit SHA")
    return True

def complete(plan, task_id, evidence):
    validate(plan)
    selected = select(plan)
    if selected is None or selected["id"] != task_id or selected["state"] != "active":
        raise PlanError("Can only complete the active non-replayed milestone")
    test_evidence(evidence)
    selected["state"] = "verified"
    selected["evidence"] = evidence.copy()
    for task in plan["milestones"]:
        if task["state"] == "pending" and all(
             next(x for x in plan["milestones"] if x["id"] == d)["state"] == "verified"
             for d in task.get("depends_on", [])):
            task["state"] = "active"
            break
    validate(plan)
    return plan

def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--check", action="store_true")
    cli.add_argument("--out", default="")
    opt = cli.parse_args()
    plan = json.loads(ROADMAP.read_text("utf-8"))
    validate(plan)
    entry = outbox(plan)
    if opt.out:
        pathlib.Path(opt.out).write_text(json.dumps(entry, ensure_ascii=False, indent=2) + "\n", "utf-8")
    print(json.dumps({"task_id": entry["task_id"], "delivery": entry["delivery"],
                      "sequence": entry["sequence"], "active": sum(t["state"] == "active"
                                                                  for t in plan["milestones"]),
                      "verified": sum(t["state"] == "verified"
                                      for t in plan["milestones"])}, ensure_ascii=False))

if __name__ == "__main__":
    main()
