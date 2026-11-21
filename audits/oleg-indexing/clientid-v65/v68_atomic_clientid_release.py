#!/usr/bin/env python3
"""Oleg Legal V68 — two-site consented ClientID patch, exact-source guarded.
Default DRY-RUN. Writes only with --apply, full backup and rollback.
No Bitrix API calls, customer data, Yandex uploads, or ad actions.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
from datetime import datetime, timezone

PRODUCTION = Path("/home/c/cl664853")
HOSTS = {
    "potrebpravo.ru": {
        "counter": 114249897,
        "form": "crm_form_fhi3n",
        "index_sha": "a7018c2d2057c118cf02b8727d69dbe35e043ce3b0e2bd8beb8eba8a098ca6bd",
        "analytics_sha": "005fc8220d6126a501bd2d6df65a669c88fea006acb2712bdbe89c096472d0d4",
    },
    "semya-yurist.ru": {
        "counter": 114251443,
        "form": "crm_form_ep5fd",
        "index_sha": "0c83d33148173b7f9129692e278a32880f0788d5e49208fb6df4244160ab08e5",
        "analytics_sha": "c0ddbca41838191bdaf280213e44f2087c3e944e7892de3a3497cfafd5a6addd",
    },
}
ASSISTANT_SHA = "67364b71bc9a1a82e8080555b2776dbc34a0c8f50e74a045d21cb6cd5910c98b"
BRIDGE_SHA = "1b60a68b27ee7eafecbca192ff2c3351a6592d7ec60e24c1a7cdca19fc4f46af"
CONSENT_OLD = ("Разрешить Яндекс Метрику для анализа посещаемости? Она использует cookie "
               "и технические сведения о посещении. Вебвизор и запись заполнения форм отключены.")
CONSENT_NEW = ("Разрешить Яндекс Метрику для анализа посещаемости и связи обращения с "
               "посещением сайта? При открытии формы Битрикс24 может передаваться "
               "псевдонимный идентификатор посетителя ClientID для оценки результатов "
               "обращений. Cookie используются только после разрешения; "
               "Вебвизор и запись ввода в формы отключены.")
PRIVACY_NOTE = (
    '<p>Если вы разрешите аналитику, технический идентификатор посетителя '
    'Яндекс Метрики (ClientID) может быть передан в Битрикс24 при переходе '
    'к форме обращения, чтобы связать обращение с посещением именно этого сайта. '
    'Без согласия на аналитику ClientID в CRM-форму не передаётся. '
    'Вы можете изменить выбор через кнопку «Настройки аналитики».</p>'
)
ANALYTICS_TAG = re.compile(r'<script\b[^>]*\bsrc="[^"]*oleg-analytics-v1\.js\?v=[^"]+"[^>]*></script>', re.I)
ASSISTANT_REF = re.compile(r'(assets/legal-assistant-v4\.js\?v=)[a-z0-9]+', re.I)

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def need(condition: bool, reason: str):
    if not condition:
        raise RuntimeError(reason)

def write_private(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def make_plan(root: Path, source: bytes, test_mode: bool):
    need(digest(source) == BRIDGE_SHA, "BRIDGE_SHA_MISMATCH")
    need(b"oleg.analytics.choice.v2" in source, "BRIDGE_CONSENT_SCOPE")
    change = {}
    report = {}
    for host, conf in HOSTS.items():
        site = root / host / "public_html"
        need(site.is_dir() and not site.is_symlink(), "SITE_ROOT_INVALID_" + host)
        index = site / "index.html"
        anal = site / "assets/oleg-analytics-v1.js"
        assistant = site / "assets/legal-assistant-v4.js"
        for p, expected in ((index, conf["index_sha"]), (anal, conf["analytics_sha"]), (assistant, ASSISTANT_SHA)):
            need(p.is_file() and not p.is_symlink(), "ASSET_MISSING_" + host + "_" + p.name)
            if not test_mode:
                need(digest(p.read_bytes()) == expected, "SOURCE_DRIFT_" + host + "_" + p.name)
        analytics = anal.read_text(encoding="utf-8")
        need(analytics.count("oleg.analytics.choice.v1") == 2, "CONSENT_KEY_DRIFT_" + host)
        need(analytics.count(CONSENT_OLD) == 1, "CONSENT_TEXT_DRIFT_" + host)
        need(f"const counter = {conf['counter']};" in analytics, "COUNTER_MISMATCH_" + host)
        need("webvisor: false" in analytics, "WEBVISOR_GUARD_" + host)
        old = "if (frame.src === intended) send('oleg_crm_form_open');"
        need(analytics.count(old) == 1, "FRAME_GOAL_GUARD_" + host)
        new = ("try { var actual = new URL(frame.src); "
               "if (actual.origin === new URL(intended).origin && "
               "actual.pathname === new URL(intended).pathname) "
               "send('oleg_crm_form_open'); } catch (_) {}")
        analytics = analytics.replace(CONSENT_OLD, CONSENT_NEW, 1).replace(
            "oleg.analytics.choice.v1", "oleg.analytics.choice.v2").replace(old, new, 1)
        patched_analytics = analytics.encode("utf-8")
        change[anal] = patched_analytics
        assistant_js = assistant.read_text(encoding="utf-8")
        token = "if (!frame.src) frame.src = formUrl;"
        need(assistant_js.count(token) == 1, "FORM_SCRIPT_DRIFT_" + host)
        assistant_js = assistant_js.replace(token, "if (!frame.src) frame.src = window.__olegClientIdBridgeV1 ? window.__olegClientIdBridgeV1.augment(formUrl) : formUrl;", 1)
        patched_assistant = assistant_js.encode("utf-8")
        change[assistant] = patched_assistant
        bridge_path = site / "assets/oleg-clientid-bridge-v1.js"
        need(not bridge_path.exists() and not bridge_path.is_symlink(), "BRIDGE_ALREADY_PRESENT_" + host)
        change[bridge_path] = source
        pages = 0
        html_count = 0
        for p in sorted(site.rglob("*.html")):
            need(not p.is_symlink(), "SYMLINK_HTML_REJECTED_" + host)
            html_count += 1
            page = p.read_text(encoding="utf-8")
            if p.name == "privacy.html":
                need(PRIVACY_NOTE not in page, "PRIVACY_ALREADY_PATCHED_" + host)
                need(page.count("<h2>Основания") == 1, "PRIVACY_SECTION_DRIFT_" + host)
                page = page.replace("<h2>Основания", PRIVACY_NOTE + "<h2>Основания", 1)
            if "oleg-analytics-v1.js?v=" not in page:
                if p.name == "privacy.html":
                    change[p] = page.encode("utf-8")
                continue
            need(page.count("oleg-clientid-bridge-v1.js") == 0, "BRIDGE_TAG_ALREADY_PRESENT_" + host)
            need(len(ANALYTICS_TAG.findall(page)) == 1, "ANALYTICS_TAG_DRIFT_" + host + "_" + p.name)
            need(bool(ASSISTANT_REF.search(page)), "ASSISTANT_TAG_DRIFT_" + host + "_" + p.name)
            bridge_tag = '<script defer src="/assets/oleg-clientid-bridge-v1.js?v=' + BRIDGE_SHA[:12] + '"></script>'
            def swap(match):
                tag = match.group(0)
                tag = re.sub(r'(oleg-analytics-v1\.js\?v=)[a-z0-9]+', lambda m:m.group(1) + digest(patched_analytics)[:12], tag)
                return tag + bridge_tag
            page, tagcount = ANALYTICS_TAG.subn(swap, page)
            need(tagcount == 1, "ANALYTICS_REPLACEMENT_GUARD")
            page, assistant_count = ASSISTANT_REF.subn(lambda m:m.group(1) + digest(patched_assistant)[:12], page)
            need(assistant_count >= 1, "ASSISTANT_VERSION_UPDATE_GUARD")
            change[p] = page.encode("utf-8")
            pages += 1
        need(pages == (25 if host == "potrebpravo.ru" else 20), "UNEXPECTED_HTML_COUNT_" + host + "_" + str(pages))
        report[host] = {"patched_html":pages,"all_html":html_count, "analytics_sha":digest(patched_analytics),
                        "assistant_sha":digest(patched_assistant),"bridge_sha":BRIDGE_SHA}
    need(len(change) >= 50, "TOO_FEW_PATCHED_FILES")
    return change, report

def backup_and_apply(root: Path, changes: dict, report: dict):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stage = root / ".oleg-seo-ops" / "v68-clientid" / stamp
    need(not stage.exists(), "STAGE_EXISTS")
    stage.mkdir(mode=0o700, parents=True)
    backup = stage / "full-before.tar.gz"
    with tarfile.open(backup, "w:gz") as tf:
        for host in HOSTS:
            tf.add(root / host / "public_html", arcname=host + "/public_html", recursive=True)
    os.chmod(backup, 0o600)
    archive_hash = digest(backup.read_bytes())
    entries = []
    for dest, data in sorted(changes.items(), key=lambda e:str(e[0])):
        rel = dest.relative_to(root)
        prior = dest.read_bytes() if dest.exists() else None
        if prior is not None:
            write_private(stage / "prior" / rel, prior)
        write_private(stage / "prepared" / rel, data)
        entries.append({"path":str(rel),"prior_sha256":digest(prior) if prior is not None else None,
                        "after_sha256":digest(data)})
    manifest = {"status":"PREPARED", "utc":stamp, "site_results":report, "full_backup":backup.name,
                "full_backup_sha256":archive_hash, "file_count":len(entries),"files":entries}
    def save_manifest(status):
        manifest["status"] = status
        p = stage / "manifest.json"
        tmp = stage / ".manifest-new"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
        os.chmod(p, 0o600)
    save_manifest("APPLYING")
    updated = []
    try:
        # New libraries and JS first. HTML switches each page to the new tested versions last.
        ordered = sorted(changes, key=lambda p:(p.suffix == ".html", str(p)))
        for i, dest in enumerate(ordered):
            data = changes[dest]
            need(not dest.is_symlink(), "DEST_SYMLINK_REJECTED")
            entry = next(e for e in entries if e["path"] == str(dest.relative_to(root)))
            current = dest.read_bytes() if dest.exists() else None
            need((digest(current) if current is not None else None) == entry["prior_sha256"], "CONCURRENT_MODIFICATION_" + str(dest))
            temp = dest.parent / (".oleg-v68-patch-" + str(i))
            need(not temp.exists(), "TEMP_COLLISION")
            mode = stat.S_IMODE(dest.stat().st_mode) if dest.exists() else 0o644
            write_private(temp, data)
            os.chmod(temp, mode)
            os.replace(temp, dest)
            updated.append((dest, entry))
        save_manifest("LIVE_WRITTEN_NEEDS_EXTERNAL_QA")
    except BaseException:
        for dest, entry in reversed(updated):
            if entry["prior_sha256"] is None:
                if dest.exists() and digest(dest.read_bytes()) == entry["after_sha256"]:
                    dest.unlink()
                continue
            prior = (stage / "prior" / entry["path"]).read_bytes()
            if dest.exists() and digest(dest.read_bytes()) == entry["after_sha256"]:
                temp = dest.parent / ".oleg-v68-rollback"
                need(not temp.exists(), "ROLLBACK_TEMP_COLLISION")
                write_private(temp, prior)
                os.chmod(temp, stat.S_IMODE(dest.stat().st_mode))
                os.replace(temp, dest)
        save_manifest("ROLLED_BACK_ON_ERROR")
        raise
    return {"status":"LIVE_WRITTEN_NEEDS_EXTERNAL_QA", "stage":str(stage),
            "files_written":len(updated),"backup_sha256":archive_hash,"site_results":report}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root",type=Path, default=PRODUCTION)
    p.add_argument("--test-root",action="store_true")
    p.add_argument("--apply",action="store_true")
    args = p.parse_args()
    root = args.root.resolve(strict=True)
    need(root == PRODUCTION or args.test_root, "PRODUCTION_ROOT_GUARD")
    source = Path(__file__).with_name("clientid-bridge.js").read_bytes()
    changes, report = make_plan(root, source, args.test_root)
    if not args.apply:
        print(json.dumps({"status":"DRY_RUN_OK_NO_WRITES","files_to_patch":len(changes),"site_results":report}, ensure_ascii=False))
    else:
        print(json.dumps(backup_and_apply(root, changes, report),ensure_ascii=False))
if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("RELEASE_REFUSED:" + str(exc)[:200],file=sys.stderr)
        sys.exit(2)
