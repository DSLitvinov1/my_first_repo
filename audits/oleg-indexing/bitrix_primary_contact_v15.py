#!/usr/bin/env python3
"""Add an actionable native Bitrix24 link to two DISABLED demo contact forms.

Never enables the old form or creates/sends a lead. Rebuilds the existing 43-file
offline candidate, preserving its exact source locks and the atomic release gate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil

BASE = Path(__file__).resolve().parent
FORM_BY_HOST = {
    "potrebpravo.ru": "crm_form_fhi3n",
    "semya-yurist.ru": "crm_form_ep5fd",
}
EXPECTED_V14_HOME_SHA = {
    "potrebpravo.ru": "ff2ed57db4dd556debf59959d0579333675dcda737b8ba4de4983f4c8b48a758",
    "semya-yurist.ru": "81c5ede60c7a0caac90bfd55cedbf20d21c3676acb9986d48efcc7a70d0a212e",
}
EXACT_OLD = '<div class="lead-form-unavailable" role="status">Для консультации воспользуйтесь телефоном или электронной почтой.</div>'
PHONE = "tel:+79172052125"
EMAIL = "mailto:centr-uprav@inbox.ru"
FORM_ORIGIN = "https://b24-s2dosa.bitrix24site.ru"


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def patch(original: str, host: str) -> str:
    if host not in FORM_BY_HOST or not isinstance(original, str):
        raise ValueError("Host or HTML invalid")
    if original.count(EXACT_OLD) != 1:
        raise ValueError("Missing or repeated disabled-form notice")
    if original.count('data-form-mode="demo"') != 1:
        raise ValueError("Do not enable the old unverified lead form")
    if original.count('id="lead-form" novalidate hidden aria-disabled="true"') != 1:
        raise ValueError("Unverified old form state")
    if original.count(PHONE) < 1 or original.count(EMAIL) < 1:
        raise ValueError("Contact channels not verified on page")
    form_link = FORM_ORIGIN + "/" + FORM_BY_HOST[host] + "/"
    replacement = (
        '<div class="lead-form-unavailable" role="status">'
        'Для отправки обращения откройте '
        '<a class="ux-link-button" href="' + form_link + '" target="_blank" rel="noopener noreferrer">'
        'форму Битрикс24</a>. '
        'Если она не открывается, <a href="' + PHONE + '">позвоните</a> '
        'или <a href="' + EMAIL + '">напишите на почту</a>. '
        'Обращение считается отправленным только после подтверждения в форме Битрикс24.'
        '</div>'
    )
    amended = original.replace(EXACT_OLD, replacement, 1)
    if amended.replace(replacement, EXACT_OLD, 1) != original:
        raise AssertionError("Patch changed other data")
    if amended.count(form_link) != 1:
        raise AssertionError("Expected exactly one direct CRM link")
    return amended


def build(stage, out):
    stage, out = Path(stage).resolve(), Path(out).resolve()
    if not stage.is_dir() or out.exists() or stage == out or out.is_relative_to(stage):
        raise ValueError("Invalid stage root or output directory")
    before = json.loads((stage / "unified-manifest.json").read_text("utf8"))
    if before.get("status") != "OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT":
        raise ValueError("Unexpected release contract")
    if len(before.get("manifest", [])) != 43:
        raise ValueError("Exactly 43 reviewed entries required")
    src_root, dest_root = stage / "unified-release", out / "unified-release"
    # Validate all staged files BEFORE creating the candidate.
    for row in before["manifest"]:
        path = src_root / row["host"] / "public_html" / row["path"]
        if row["host"] not in FORM_BY_HOST or not path.is_file() or path.is_symlink():
            raise ValueError("Invalid release file")
        if sha(path.read_bytes()) != row["proposed_sha256"]:
            raise ValueError("Stage source SHA drift")
    for host, expected in EXPECTED_V14_HOME_SHA.items():
        p = src_root / host / "public_html" / "index.html"
        if sha(p.read_bytes()) != expected:
            raise ValueError("V14 home SHA drift " + host)
    shutil.copytree(src_root, dest_root, symlinks=False)
    target = dict(before)
    target["v15_status"] = "STAGED_NOT_DEPLOYED_NOT_CRM_VERIFIED"
    target["v15_change"] = "Enable direct external Bitrix link on two disabled homepage contact slots; never enable legacy form"
    target["production_modified"] = False
    target["manifest"] = []
    for row in before["manifest"]:
        new_entry = dict(row)
        file = dest_root / row["host"] / "public_html" / row["path"]
        if row["path"] == "index.html":
            old_html = file.read_text("utf8")
            rewritten = patch(old_html, row["host"])
            file.write_text(rewritten, encoding="utf8")
            new_entry["proposed_sha256"] = sha(file.read_bytes())
        if sha(file.read_bytes()) != new_entry["proposed_sha256"]:
            raise ValueError("Candidate SHA verification failed")
        target["manifest"].append(new_entry)
    out.joinpath("unified-manifest.json").write_text(json.dumps(target, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
    result = {
        "status": "STAGED_NOT_DEPLOYED_NOT_CRM_VERIFIED",
        "files_verified": 43,
        "home_pages_changed_from_v14": 2,
        "other_files_unchanged": 41,
        "crm_forms": FORM_BY_HOST,
        "unverified_legacy_form_remains_disabled": True,
        "confirmation_of_new_crm_deal": False,
        "production_modified": False,
    }
    out.joinpath("v15-primary-crm-links-report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--v14", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    print(json.dumps(build(args.v14, args.out), ensure_ascii=False))
