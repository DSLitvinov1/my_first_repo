"""Offline-only operations report over explicitly supplied, untrusted observations.

No GitHub calls, network, subprocesses, secrets, file writes, model invocation,
queue mutation, automatic retries, recovery or release authority.
"""
import argparse
import json
from pathlib import Path
import re
import sys

from diagnose import SnapshotError, diagnose, _parse_unique

MAX_BYTES = 500000
MAX_OBSERVATIONS = 40
MAX_WORKERS = 50
MAX_QUEUE = 100
MAX_INCIDENTS = 100
ASCII_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}\Z")

WORKER_STATES = {"ready", "busy", "offline", "failed", "unknown"}
QUEUE_STATES = {"queued", "running", "retry_wait", "blocked", "completed", "unknown"}
INCIDENT_CODES = {
    "MODEL_TIMEOUT", "RUNNER_LOST", "GITHUB_UNAVAILABLE",
    "CHECKPOINT_PARTIAL", "RECEIPT_UNKNOWN", "DUPLICATE_PUBLICATION",
    "FOREIGN_SCOPE", "REVIEW_REJECTED", "MODEL_REPLY_MALFORMED",
    "LEASE_CONFLICT", "OTHER_FAILURE"
}
RECOMMENDATIONS = {
    "MODEL_TIMEOUT": "Проверить локальную модель и ограничения времени. Повтор возможен только по контракту CORE.",
    "RUNNER_LOST": "Проверить состояние исполнителя и последнюю доверенную контрольную точку. Не перезапускать чужой процесс.",
    "GITHUB_UNAVAILABLE": "Проверить связь с GitHub и достоверный удалённый журнал; не публиковать вслепую.",
    "CHECKPOINT_PARTIAL": "Приостановить операцию до проверки полноты checkpoint владельцем CORE.",
    "RECEIPT_UNKNOWN": "Остановить публикацию; сначала независимый readback GitHub и receipt владельцем CORE/REVIEW.",
    "DUPLICATE_PUBLICATION": "Заблокировать повтор, уведомить координатора, независимо сравнить историю коммитов.",
    "FOREIGN_SCOPE": "Остановить изменения чужой области и уведомить владельца и координатора.",
    "REVIEW_REJECTED": "Сохранить REJECT и передать замечания владельцу исходника без автоматического исправления.",
    "MODEL_REPLY_MALFORMED": "Не принимать вердикт; проверить исходный ответ и доступный лимит бесплатной модели.",
    "LEASE_CONFLICT": "Не захватывать lease повторно без доверенной проверки актуального владельца.",
    "OTHER_FAILURE": "Проверить журнал и квалифицировать причину вручную; не повторять автоматически."
}

def _id(value, name):
    if not isinstance(value, str) or not ASCII_ID.fullmatch(value):
        raise SnapshotError(name + " must be a short safe identifier")
    return value

def _list(value, max_count, name):
    if not isinstance(value, list) or len(value) > max_count:
        raise SnapshotError(name + " is absent or exceeds the record limit")
    return value

def _read_observation(item, seen_ids):
    if not isinstance(item, dict) or set(item) != {
            "id", "snapshot", "workers", "queue", "incidents"}:
        raise SnapshotError("Invalid observation schema")
    key = _id(item["id"], "observation id")
    if key in seen_ids:
        raise SnapshotError("Repeated observation identifier")
    seen_ids.add(key)
    finding = diagnose(item["snapshot"])
    workers = _list(item["workers"], MAX_WORKERS, "workers")
    queue = _list(item["queue"], MAX_QUEUE, "queue")
    incidents = _list(item["incidents"], MAX_INCIDENTS, "incidents")
    clean_workers = []
    clean_queue = []
    clean_incidents = []
    worker_names = set()
    queue_names = set()
    for worker in workers:
        if not isinstance(worker, dict) or set(worker) != {"id", "state", "role"}:
            raise SnapshotError("Invalid worker record schema")
        worker_id = _id(worker["id"], "worker id")
        role = _id(worker["role"], "worker role")
        state = worker["state"]
        if state not in WORKER_STATES:
            raise SnapshotError("Unrecognized worker state")
        if worker_id in worker_names:
            raise SnapshotError("Repeated worker in the same observation")
        worker_names.add(worker_id)
        clean_workers.append({"id": worker_id, "role": role, "state": state})
    for job in queue:
        if not isinstance(job, dict) or set(job) != {"task_id", "state", "attempt"}:
            raise SnapshotError("Invalid queue record schema")
        task_id = _id(job["task_id"], "queue task id")
        if task_id in queue_names:
            raise SnapshotError("Repeated queue task in the same observation")
        queue_names.add(task_id)
        if job["state"] not in QUEUE_STATES:
            raise SnapshotError("Unrecognized queue state")
        if type(job["attempt"]) is not int or not 0 <= job["attempt"] <= 1000:
            raise SnapshotError("Invalid attempt count")
        clean_queue.append({"task_id": task_id, "state": job["state"],
                            "attempt": job["attempt"]})
    for incident in incidents:
        if not isinstance(incident, dict) or set(incident) != {
                "code", "component", "run_id"}:
            raise SnapshotError("Invalid incident record schema")
        code = incident["code"]
        if code not in INCIDENT_CODES:
            raise SnapshotError("Unrecognized incident classification")
        component = _id(incident["component"], "incident component")
        run_id = incident["run_id"]
        if type(run_id) is not int or run_id <= 0:
            raise SnapshotError("Invalid incident run identifier")
        clean_incidents.append({"code": code, "component": component, "run_id": run_id})
    return {"id": key, "finding": finding, "workers": clean_workers,
            "queue": clean_queue, "incidents": clean_incidents}

def report(document):
    """Inventory the LATEST observation; classify distinct historical run failures."""
    if not isinstance(document, dict) or set(document) != {
            "schema", "scope", "observations"}:
        raise SnapshotError("Unexpected OPS report document")
    if document["schema"] != 1 or document["scope"] != "neurofactory-ops-offline-report":
        raise SnapshotError("Foreign OPS report document")
    raw = _list(document["observations"], MAX_OBSERVATIONS, "observations")
    if not raw:
        raise SnapshotError("At least one observation required")
    seen = set()
    clean = [_read_observation(item, seen) for item in raw]
    latest = clean[-1]
    errors = {}
    # Deduplicate identical incident reports in one run or across repeated reads.
    for observation in clean:
        for event in observation["incidents"]:
            key = (event["component"], event["code"])
            errors.setdefault(key, set()).add(event["run_id"])
    recurrent = []
    for (component, code), runs in sorted(errors.items()):
        if len(runs) >= 2:
            recurrent.append({
                "component": component, "code": code,
                "distinct_failed_runs": len(runs),
                "reported_run_ids": sorted(runs),
                "recovery_recommendation": RECOMMENDATIONS[code],
                "auto_recovery_permitted": False
            })
    counts = {}
    for entry in latest["queue"]:
        counts[entry["state"]] = counts.get(entry["state"], 0) + 1
    last_blockers = latest["finding"]["blockers"]
    return {
        "schema": 1,
        "report_type": "isolated_offline_ops_observation",
        "latest_observation_id": latest["id"],
        "observation_count": len(clean),
        "worker_inventory": latest["workers"],
        "queue_inventory": latest["queue"],
        "queue_status_counts": dict(sorted(counts.items())),
        "reported_incidents_total": sum(len(x["incidents"]) for x in clean),
        "distinct_incident_runs": sum(len(x) for x in errors.values()),
        "recurrent_failures": recurrent,
        "latest_diagnosis": latest["finding"]["diagnosis"],
        "latest_blockers": last_blockers,
        "actions_allowed": {"auto_recovery": False, "retry": False,
                            "publish": False, "merge": False,
                            "schedule_task": False},
        "source_trust": "UNTRUSTED_OFFLINE_SNAPSHOTS",
        "coverage": "Only supplied workers, queue records and incidents; not a complete live inventory",
        "limitations": [
            "No live status and no independent GitHub or model-source attestation.",
            "Repeated failures count distinct run IDs, not elapsed time or actual impact.",
            "Recovery recommendations are advisory; CORE and COORDINATOR own action gates.",
            "Never use this report to claim a task was published or a release accepted."
        ]
    }


def render_russian_text(value):
    """Human-readable view of a validated OFFLINE report; no trusted status."""
    if not isinstance(value, dict) or value.get("report_type") != "isolated_offline_ops_observation":
        raise SnapshotError("Unrecognized or unchecked report")
    lines = [
        "НЕЙРОЗАВОД — ИЗОЛИРОВАННАЯ ДИАГНОСТИКА OPS",
        "Только предоставленные снимки, а не живой мониторинг GitHub.",
        "Последний снимок: " + value["latest_observation_id"],
        "Количество снимков: " + str(value["observation_count"]),
        "Состояние: " + value["latest_diagnosis"],
        "ИСПОЛНИТЕЛИ:"
    ]
    for x in value["worker_inventory"]:
        lines.append("  " + x["id"] + " / " + x["role"] + " — " + x["state"])
    if not value["worker_inventory"]:
        lines.append("  Неизвестно: список исполнителей не предоставлен.")
    lines.append("ОЧЕРЕДЬ:")
    for x in value["queue_inventory"]:
        lines.append("  " + x["task_id"] + ": " + x["state"] +
                     ", попытка " + str(x["attempt"]))
    if not value["queue_inventory"]:
        lines.append("  Неизвестно: список задач не предоставлен.")
    lines.append("БЛОКИРУЮЩИЕ ПРОБЛЕМЫ:")
    for code in value["latest_blockers"]:
        lines.append("  " + code)
    if not value["latest_blockers"]:
        lines.append("  Не обнаружено внутри снимка; разрешения на выпуск всё равно нет.")
    lines.append("ПОВТОРЯЮЩИЕСЯ ОТКАЗЫ (различные номера запусков):")
    for entry in value["recurrent_failures"]:
        lines.append("  " + entry["component"] + " / " + entry["code"] +
                     " — " + str(entry["distinct_failed_runs"]) + " запусков")
        lines.append("  Рекомендация: " + entry["recovery_recommendation"])
    if not value["recurrent_failures"]:
        lines.append("  Повторов в предоставленных записях не обнаружено.")
    lines.append("АВТОВОССТАНОВЛЕНИЕ, ПОВТОР, ПУБЛИКАЦИЯ И MERGE ЗАПРЕЩЕНЫ.")
    lines.append("Внешняя приёмка CORE/REVIEW/COORDINATOR и проверка GitHub обязательны.")
    return "\n".join(lines)

def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only OPS summary of local saved observations")
    parser.add_argument("observations", help="Local JSON report envelope; never a live CORE journal")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        path = Path(args.observations)
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise SnapshotError("Input is missing or exceeds the size limit")
        result = report(_parse_unique(path.read_text(encoding="utf-8")))
        if args.format == "text":
            print(render_russian_text(result))
        else:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (SnapshotError, OSError) as exc:
        print("OPS_REPORT_REFUSED: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
