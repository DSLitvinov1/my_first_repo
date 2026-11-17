#!/usr/bin/env python3
"""V14: prepare a fail-safe contact path in the existing, offline-only 43-file release.

Input: the exact V13 unified stage. Output: a separate V14 candidate.
Never writes to hosting or creates customer leads. No production installer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

HOSTS = ("potrebpravo.ru", "semya-yurist.ru")
PHONE = "tel:+79172052125"
MAIL = "mailto:centr-uprav@inbox.ru"
PREVIOUS_SHA = "e3b14f2ebc1524140d99bf20af5e13e00a596cfbcf0ba963bed2b7d0938c18a6"
ANCHOR = "  fallback.append(open, create('span', '.'));\n  formStep.insertBefore(fallback, frame);"
REPLACEMENT = """  const alternative = create('span', '. Если Битрикс24 недоступен, можно ');
  const phoneLink = create('a', 'позвонить');
  phoneLink.href = 'tel:+79172052125';
  phoneLink.className = 'legal-open';
  const mailLink = create('a', 'написать на почту');
  mailLink.href = 'mailto:centr-uprav@inbox.ru';
  mailLink.className = 'legal-open';
  fallback.append(open, alternative, phoneLink, create('span', ' или '), mailLink,
    create('span', '. Передавайте конфиденциальные сведения только после согласования безопасного способа связи.'));
  formStep.insertBefore(fallback, frame);"""


def digest(b):
    return hashlib.sha256(b).hexdigest()


def patch(raw):
    if not isinstance(raw, bytes) or digest(raw) != PREVIOUS_SHA:
        raise ValueError("V13 candidate SHA drift; patch forbidden")
    text = raw.decode("utf8")
    if text.count(ANCHOR) != 1:
        raise ValueError("Unrecognized fallback; patch forbidden")
    if any(x in text for x in ("phoneLink", "mailLink", "qwen", "Qwen")):
        raise ValueError("Unexpected previous fallback or Qwen")
    result = text.replace(ANCHOR, REPLACEMENT).encode("utf8")
    if result.count(b"tel:+79172052125") != 1 or result.count(b"mailto:centr-uprav@inbox.ru") != 1:
        raise AssertionError("Duplicate or missing contact links")
    if b"formStep.insertBefore(fallback, frame);" not in result:
        raise AssertionError("Fallback not above iframe")
    if result.replace(REPLACEMENT.encode("utf8"), ANCHOR.encode("utf8")) != raw:
        raise AssertionError("Unexpected mutation beyond the reviewed block")
    return result


def build(v13, out):
    v13, out = Path(v13).resolve(), Path(out).resolve()
    if not v13.is_dir() or out.exists() or out.is_relative_to(v13):
        raise ValueError("V13 directory missing or output exists/overlaps")
    current = json.loads((v13 / "unified-manifest.json").read_text("utf8"))
    records = current["manifest"]
    if current.get("files_changed") != 43 or len(records) != 43:
        raise ValueError("V13 manifest is not 43 exact files")
    old_root = v13 / "unified-release"
    old_js = []
    for host in HOSTS:
        js = old_root / host / "public_html" / "assets/legal-assistant-v4.js"
        old_js.append(js.read_bytes())
        main = (old_root / host / "public_html" / "index.html").read_text("utf8")
        if PHONE not in main or MAIL not in main:
            raise ValueError("Unverified published phone/email on "+host)
    if old_js[0] != old_js[1]:
        raise ValueError("V13 helper differs across domains")
    new_js = patch(old_js[0])
    canonical = Path(__file__).parent / "v14-assets" / "legal-assistant-v4.js"
    if not canonical.is_file() or canonical.read_bytes() != new_js:
        raise ValueError("Shared V14 fallback fixture differs from generated JS")
    destination = out / "unified-release"
    shutil.copytree(old_root, destination, symlinks=False)
    for host in HOSTS:
        (destination / host / "public_html" / "assets/legal-assistant-v4.js").write_bytes(new_js)
    new_manifest = dict(current)
    new_manifest["source"] = "V13 offline stage only; source-lock retained, V14 phone/email fallback added"
    new_manifest["status"] = current["status"]  # Preserve V13 fail-closed atomic preflight contract.
    new_manifest["v14_stage_status"] = "OFFLINE_V14_43_FILE_CANDIDATE_NOT_PUBLISHED"
    new_manifest["production_modified"] = False
    new_manifest["files_changed"] = 43
    new_manifest["fallback_contact_verified_from_site_html"] = True
    new_manifest["v14_changes"] = ["two JS assets: direct phone/email if external Bitrix unavailable"]
    new_manifest["manifest"] = []
    for item in records:
        row = dict(item)
        path = destination / row["host"] / "public_html" / row["path"]
        if not path.is_file() or path.is_symlink():
            raise ValueError("Stage file missing or unexpected symlink")
        actual = digest(path.read_bytes())
        if row["path"] == "assets/legal-assistant-v4.js":
            if row["proposed_sha256"] != PREVIOUS_SHA:
                raise ValueError("V13 proposed SHA mismatch")
            row["proposed_sha256"] = digest(new_js)
        if actual != row["proposed_sha256"]:
            raise ValueError("Candidate file SHA mismatch: "+row["host"]+"/"+row["path"])
        new_manifest["manifest"].append(row)
    if len(new_manifest["manifest"]) != 43:
        raise AssertionError("43-file release contract broken")
    (out / "unified-manifest.json").write_text(json.dumps(new_manifest,ensure_ascii=False,indent=2),encoding="utf8")
    report = {"state": new_manifest["v14_stage_status"],"files":43,"js_assets_changed":2,
      "v13_js_sha":PREVIOUS_SHA,"v14_js_sha":digest(new_js),
      "fallback_tel":PHONE,"fallback_email":MAIL,
      "production_writes":0,"new_crm_test_requests":0}
    (out / "v14-fallback-report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf8")
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--v13", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    print("V14_STAGE_RESULT",json.dumps(build(args.v13,args.out),ensure_ascii=False))
