#!/usr/bin/env python3
"""Oleg Legal: strict local dry-run of site-separated Yandex offline conversions.

This file intentionally has NO network capability, OAuth or CRM write operation.
Its input must be a minimal, separately verified consented CRM export — not a
full personal/customer database. The generated CSV remains private on the server.
"""
from __future__ import annotations
import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import re
import sys

CONFIG = {
    "potrebpravo.ru": {"counter": 114249897, "form": "crm_form_fhi3n", "source": "Сайт — Защита прав потребителей"},
    "semya-yurist.ru": {"counter": 114251443, "form": "crm_form_ep5fd", "source": "Сайт — Семейное право"},
}
GOALS = {
    "В работе": "oleg_crm_lead_confirmed",
    "Консультация проведена": "oleg_crm_consultation_completed",
    "Договор заключён": "oleg_crm_contract_signed",
}
ID_PATTERN = re.compile(r"^[0-9]{5,32}$")
CSV_FIELDS = ("ClientId", "Target", "DateTime")
MAX_AGE_S = 21 * 86400

class InvalidRecord(ValueError):
    """Validation error without sensitive field values."""


@dataclass(frozen=True)
class Conversion:
    counter: int
    deal_id: int
    client_id: str
    target: str
    timestamp: int
    site: str

    @property
    def dedup_key(self) -> str:
        return f"{self.counter}:{self.deal_id}:{self.target}"


def validate_record(record: object, now: int) -> Conversion:
    if not isinstance(record, dict):
        raise InvalidRecord("object_required")
    # Explicit whitelist: reject PII-rich exports instead of accidentally storing them.
    allowed = {"deal_id", "site", "form_code", "crm_source", "client_id",
               "analytics_consent_confirmed", "lead_consent_confirmed",
               "crm_stage", "crm_stage_verified", "event_timestamp",
               "is_test", "qualified_lead_confirmed", "responsible_oleg_verified"}
    if set(record) - allowed:
        raise InvalidRecord("unexpected_fields_PII_guard")
    site = record.get("site")
    if type(site) is not str or site not in CONFIG:
        raise InvalidRecord("site_not_allowlisted")
    own = CONFIG[site]
    if record.get("form_code") != own["form"]:
        raise InvalidRecord("form_site_mismatch")
    if record.get("crm_source") != own["source"]:
        raise InvalidRecord("crm_source_site_mismatch")
    if record.get("analytics_consent_confirmed") is not True:
        raise InvalidRecord("analytics_consent_missing")
    if record.get("lead_consent_confirmed") is not True:
        raise InvalidRecord("lead_consent_missing")
    if record.get("crm_stage_verified") is not True:
        raise InvalidRecord("crm_stage_not_verified")
    # The three offline goals represent real, qualified CRM outcomes, never QA/test data.
    # Explicit False is required; missing or null flags must fail closed.
    if record.get("is_test") is not False:
        raise InvalidRecord("test_or_unverified_lead_rejected")
    if record.get("qualified_lead_confirmed") is not True:
        raise InvalidRecord("not_qualified_crm_lead")
    if record.get("responsible_oleg_verified") is not True:
        raise InvalidRecord("crm_responsible_not_verified")
    deal = record.get("deal_id")
    if type(deal) is not int or not 1 <= deal <= 100000000:
        raise InvalidRecord("deal_id_invalid")
    id_ = record.get("client_id")
    if type(id_) is not str or not ID_PATTERN.fullmatch(id_):
        raise InvalidRecord("real_clientid_missing_or_invalid")
    stage = record.get("crm_stage")
    if type(stage) is not str or stage not in GOALS:
        raise InvalidRecord("not_qualified_crm_stage")
    event_timestamp = record.get("event_timestamp")
    if type(event_timestamp) is not int or not (now - MAX_AGE_S) <= event_timestamp <= now:
        raise InvalidRecord("invalid_or_expired_event_timestamp")
    return Conversion(own["counter"], deal, id_, GOALS[stage], event_timestamp, site)


def route_records(rows: object, now: int, used_keys: set[str] | None = None) -> tuple[dict[int, list[Conversion]], dict[str, int]]:
    if not isinstance(rows, list) or len(rows) > 500:
        raise InvalidRecord("input_must_be_bounded_array_max_500")
    result = {v["counter"]: [] for v in CONFIG.values()}
    summary: dict[str, int] = {}
    seen = set(used_keys or ())
    for row in rows:
        try:
            v = validate_record(row, now)
        except InvalidRecord as e:
            summary[str(e)] = summary.get(str(e), 0) + 1
            continue
        if v.dedup_key in seen:
            summary["duplicate_rejected"] = summary.get("duplicate_rejected", 0) + 1
            continue
        seen.add(v.dedup_key)
        result[v.counter].append(v)
        summary["eligible"] = summary.get("eligible", 0) + 1
    return result, summary


def export_private_csv(directory: Path, routed: dict[int, list[Conversion]]) -> dict[str, int]:
    if directory.is_symlink():
        raise InvalidRecord("no_symlink_output")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    # Preflight all destination paths before writing any file; a collision must
    # not leave the first site's output half-created.
    planned = {counter: directory / f"oleg_offline_{counter}.csv"
               for counter, records in routed.items() if records}
    if any(p.is_symlink() or p.exists() for p in planned.values()):
        raise InvalidRecord("refuse_overwrite_existing_csv")
    totals: dict[str, int] = {}
    for counter, records in routed.items():
        if not records:
            totals[str(counter)] = 0
            continue
        target = planned[counter]
        # File is private and opened with exclusive creation (race-safe).
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, extrasaction="raise")
            writer.writeheader()
            for r in records:
                writer.writerow({"ClientId":r.client_id,"Target":r.target,"DateTime":r.timestamp})
        totals[str(counter)] = len(records)
    return totals


def main() -> int:
    parser = argparse.ArgumentParser(description="Oleg CRM offline conversion selector (NO NETWORK)")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--private-output", type=Path, default=None)
    args = parser.parse_args()
    if args.input.stat().st_size > 150_000:
        raise InvalidRecord("too_large_input")
    records = json.loads(args.input.read_text(encoding="utf-8"))
    now = int(datetime.now(timezone.utc).timestamp())
    routed, reasons = route_records(records, now)
    counts = {str(k): len(v) for k, v in routed.items()}
    if args.private_output:
        export_private_csv(args.private_output, routed)
    print(json.dumps({"mode":"DRY_RUN_NO_UPLOAD","network_calls":0,
                      "crm_changes":0,"rows_by_counter":counts,
                      "validation_counts":reasons}, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (InvalidRecord, OSError, json.JSONDecodeError) as exc:
        print("VALIDATION_FAILED: " + type(exc).__name__, file=sys.stderr)
        sys.exit(2)