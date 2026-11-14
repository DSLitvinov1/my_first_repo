"""Work ONE one-user, read-only preflight for a local Windows pilot.

No external network, desktop clicks, model inference, file writes or account
operations. The only HTTP calls are bounded GETs to 127.0.0.1:18770.
"""
from __future__ import annotations
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys
from urllib.request import Request, urlopen

REQUIRED = frozenset((
    "work_server.py","work_core.py","agent_one.py","desktop_one.py",
    "desktop_worker.ps1","browser_control.py","browser_worker.cjs",
    "private_flow_one.py","personal_readiness_one.py",
    "app.js","toolmesh.js","index.html","styles.css",
    "START_PRIVATE_WORK_ONE.ps1",
    "portable_runtime_one.py", "SETUP_LOCAL_QWEN.ps1",
))
LOCAL_URL="http://127.0.0.1:18770"
TOKEN_META=re.compile(r'<meta\s+name="nf-token"\s+content="([^"]+)"')
MAX_FILE_BYTES=1024*1024


def verify_manifest(root):
    manifest=root/"manifest.json"
    if manifest.is_symlink() or not manifest.is_file():
        return {"state":"not_packaged","reason":"MISSING_MANIFEST"}
    if manifest.stat().st_size>400000:
        return {"state":"invalid","reason":"MANIFEST_TOO_LARGE"}
    try:
        doc=json.loads(manifest.read_text(encoding="utf-8-sig"))
        names=doc["file_digests"]
        if (doc.get("schema")!="nf.workone.personal-bundle.v1" or
            type(names) is not dict or not REQUIRED.issubset(names) or
            len(names)!=28 or doc.get("contains_secrets") is not False or
            doc.get("installs_windows_service") is not False):
            return {"state":"invalid","reason":"MANIFEST_INVALID"}
        for name,digest in names.items():
            if (type(name) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{2,90}",name)
                or type(digest) is not str or
                not re.fullmatch(r"[0-9a-f]{64}",digest)):
                return {"state":"invalid","reason":"MANIFEST_ENTRY_INVALID"}
            file=root/name
            if (file.is_symlink() or not file.is_file() or
                file.stat().st_size>MAX_FILE_BYTES):
                return {"state":"invalid","reason":"MANIFEST_FILE_INVALID"}
            if hashlib.sha256(file.read_bytes()).hexdigest()!=digest:
                return {"state":"invalid","reason":"MANIFEST_DIGEST_MISMATCH"}
        vendor=doc.get("vendor_file_digests")
        if doc.get("portable_runtime") is True:
            mandatory={"runtime/python/python.exe","runtime/node/node.exe",
                       "node_modules/puppeteer-core/package.json"}
            if (type(vendor) is not dict or not mandatory.issubset(vendor)
                    or not 3<=len(vendor)<=3500):
                return {"state":"invalid","reason":"PORTABLE_VENDOR_INVALID"}
            for name,digest in vendor.items():
                if (type(name) is not str or type(digest) is not str or
                        not re.fullmatch(r"[0-9a-f]{64}",digest) or
                        len(name)>240 or "\\" in name):
                    return {"state":"invalid","reason":"VENDOR_ENTRY_INVALID"}
                parts=name.split("/")
                if (len(parts)<(2 if name.startswith("node_modules/") else 3) or
                        any(part in (".","..") or not re.fullmatch(
                            r"[A-Za-z0-9@_.+-]{1,90}",part)
                            for part in parts) or
                        not (name.startswith("runtime/python/") or
                             name.startswith("runtime/node/") or
                             name.startswith("node_modules/"))):
                    return {"state":"invalid","reason":"VENDOR_PATH_REFUSED"}
            # Validate every path before touching any vendor file.
            for name,digest in vendor.items():
                parts=name.split("/")
                file=root
                for part in parts:
                    file=file/part
                    if file.is_symlink():
                        return {"state":"invalid","reason":"VENDOR_SYMLINK_REFUSED"}
                if not file.is_file() or file.stat().st_size>100*1024*1024:
                    return {"state":"invalid","reason":"VENDOR_FILE_INVALID"}
                if hashlib.sha256(file.read_bytes()).hexdigest()!=digest:
                    return {"state":"invalid","reason":"VENDOR_DIGEST_MISMATCH"}
        elif vendor is not None:
            return {"state":"invalid","reason":"UNEXPECTED_VENDOR"}
        return {"state":"verified","files":len(names),
                "portable_runtime_verified":doc.get("portable_runtime") is True,
                "vendor_files":len(vendor) if vendor else 0}
    except (OSError,ValueError,KeyError,TypeError,UnicodeError):
        return {"state":"invalid","reason":"MANIFEST_UNREADABLE"}


def check_local_work(url=LOCAL_URL):
    """Reads owner-token only in memory; never prints/returns it."""
    if url != LOCAL_URL:
        raise ValueError("UNTRUSTED_LOCAL_URL")
    try:
        with urlopen(url+"/",timeout=2) as response:
            raw=response.read(120000)
            if len(raw)>=120000:
                return {"state":"unknown","reason":"WORK_HTML_TOO_LARGE"}
            markup=raw.decode("utf-8")
        match=TOKEN_META.search(markup)
        if not match:
            return {"state":"unknown","reason":"WORK_OWNER_META_NOT_FOUND"}
        token=html.unescape(match.group(1))
        if not 20<=len(token)<=256:
            return {"state":"unknown","reason":"WORK_OWNER_META_INVALID"}
        req=Request(url+"/api/private/readiness",
                    headers={"X-NF-Work-Token":token,
                             "Host":"127.0.0.1:18770"})
        with urlopen(req,timeout=3) as response:
            if response.status!=200:
                return {"state":"unknown","reason":"WORK_STATUS_NOT_OK"}
            raw=response.read(12000)
            if len(raw)>=12000:
                return {"state":"unknown","reason":"WORK_STATUS_TOO_LARGE"}
            doc=json.loads(raw)
        if (doc.get("mode")!="personal_single_owner" or
                type(doc.get("checks")) is not list):
            return {"state":"unknown","reason":"WORK_STATUS_SCHEMA_INVALID"}
        return {
            "state":"responding",
            "read_only_web_task_ready":doc.get("read_only_web_task_ready") is True,
            "desktop_test_ready":doc.get("desktop_test_ready") is True,
            "external_write_verified":False,
            "components":{c["id"]:c["status"] for c in doc["checks"]
                          if type(c) is dict and c.get("id") in
                          ("qwen","browser","desktop","google_tasks","bitrix24")
                          and c.get("status") in
                          ("ready","needs_setup","needs_live_test")}
        }
    except (OSError,ValueError,TypeError,UnicodeError,KeyError):
        return {"state":"not_running","reason":"WORK_LOCAL_NOT_AVAILABLE"}


def inspect(root=None,*,check_http=True):
    root=Path(root) if root else Path(__file__).resolve().parent
    result={
        "mode":"personal_safe_preflight",
        "os":"windows" if os.name=="nt" else "not_windows",
        "python_supported":sys.version_info>=(3,11),
        "manifest":verify_manifest(root),
        "local_work":check_local_work() if check_http else
                     {"state":"not_checked"},
        "no_mutations":True,
        "no_accounts_accessed":True,
        "remote_devices_not_tested":True,
    }
    return result


if __name__=="__main__":
    report=inspect()
    print(json.dumps(report,ensure_ascii=False,indent=2))
    if (not report["python_supported"] or
            report["manifest"]["state"]!="verified"):
        raise SystemExit(2)
