#!/usr/bin/env python3
"""Oleg V6: READ-ONLY server-side route inventory, no secrets or file writes.

Run only within an independently authenticated Timeweb terminal. The supplied
paths are NOT proof that the server is real Timeweb; verify separately.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from xml.etree import ElementTree as ET

HOSTS = ("potrebpravo.ru", "semya-yurist.ru")
SAFE_SUFFIXES = {".js", ".cjs", ".mjs", ".php", ".conf", ".htaccess"}
SKIP_NAMES = {".git", ".ssh", "node_modules", "vendor", "cache",
              "tmp", "backups", "backup", "private", "logs", ".env"}
MAX_FILES = 800
MAX_FILE_BYTES = 300_000
MAX_DEPTH = 6

def inside(path, parent):
    return path.resolve().is_relative_to(parent.resolve())

def assert_root(path, home):
    if not path.is_dir() or path.is_symlink() or not inside(path, home):
        raise ValueError("Untrusted or missing input directory")
    return path.resolve()

def file_summary(path, root):
    if path.is_symlink() or not path.is_file() or not inside(path, root):
        return {"present": False}
    if path.stat().st_size > MAX_FILE_BYTES:
        return {"present": True, "oversized": True}
    raw = path.read_bytes()
    return {"present": True, "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw)}

def site_inventory(host, docroot):
    found = {"host": host, "docroot": str(docroot), "files": {}}
    for rel in ("index.html", "sitemap.xml", "robots.txt", "assets/site.js",
                "assets/legal-assistant-v4.js", "assets/oleg-analytics-v1.js"):
        found["files"][rel] = file_summary(docroot / rel, docroot)
    sitemap = docroot / "sitemap.xml"
    if found["files"]["sitemap.xml"].get("present") and not found["files"]["sitemap.xml"].get("oversized"):
        try:
            root = ET.fromstring(sitemap.read_bytes())
            urls = [n.text for n in root.iter() if n.tag.split("}")[-1] == "loc" and n.text]
            found["sitemap_urls"] = len(urls)
            found["sitemap_unique_urls"] = len(set(urls))
            found["sitemap_host_match"] = all(x.startswith("https://" + host + "/") for x in urls)
        except (ET.ParseError, OSError, UnicodeDecodeError):
            found["sitemap_status"] = "invalid_or_unreadable"
    sitejs = docroot / "assets" / "site.js"
    if found["files"]["assets/site.js"].get("sha256"):
        text = sitejs.read_text(encoding="utf-8", errors="replace")
        found["lead_form_client"] = {
            "posts_to_api_leads": bool(re.search(r"/api/leads", text, re.I)),
            "uses_only_http_ok": bool(re.search(r"response\\.ok|result\\.ok", text)),
            "explicit_readback_proof": bool(re.search(r"readback_confirmed", text))
        }
    return found

def backend_refs(root):
    scanned = 0
    matches = []
    ignored = 0
    for directory, subdirs, files in os.walk(root, followlinks=False):
        d = Path(directory)
        depth = len(d.relative_to(root).parts)
        subdirs[:] = [name for name in subdirs if depth < MAX_DEPTH and name not in SKIP_NAMES
                      and not name.startswith(".") and not (d / name).is_symlink()]
        for name in files:
            if scanned >= MAX_FILES:
                return matches, scanned, ignored, True
            p = d / name
            if p.is_symlink() or name in SKIP_NAMES or name.startswith(".env"):
                continue
            if p.suffix.lower() not in SAFE_SUFFIXES and name != ".htaccess":
                continue
            scanned += 1
            if not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
                ignored += 1
                continue
            raw = p.read_bytes()
            # Never print the source code, URLs, webhook tokens or credentials.
            text = raw.decode("utf-8", errors="replace")
            lead_route = bool(re.search(r"/api/leads?\\b", text, re.I))
            bitrix = bool(re.search(r"bitrix24|crm\\.item\\.(?:add|get)|crm\\.deal\\.(?:add|get)", text, re.I))
            if lead_route or bitrix:
                matches.append({
                    "relative_path": str(p.relative_to(root)),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "route_reference": lead_route,
                    "bitrix_reference": bitrix,
                    "post_method_reference": bool(re.search(r"POST|post\\s*\\(", text, re.I)),
                    "route_implementation_confirmed": False
                })
    return matches, scanned, ignored, False

def inventory(home, backend, consumer, family):
    home = assert_root(home, home)
    backend = assert_root(backend, home)
    roots = {"potrebpravo.ru": assert_root(consumer, home),
             "semya-yurist.ru": assert_root(family, home)}
    if roots[HOSTS[0]] == roots[HOSTS[1]]:
        raise ValueError("Different domains cannot share same explicit docroot")
    matches, scanned, ignored, truncated = backend_refs(backend)
    return {
        "mode": "READ_ONLY_NO_SECRET_VALUES",
        "authenticated_real_timeweb_confirmed": False,
        "real_post_handler_confirmed": False,
        "crm_receipt_confirmed": False,
        "server_backup_created": False,
        "sites": [site_inventory(host, roots[host]) for host in HOSTS],
        "candidate_backend_files": matches,
        "candidate_files_scanned": scanned,
        "candidate_files_ignored": ignored,
        "scan_truncated": truncated,
        "actions": ["read_regular_files", "hash", "safe_regex_boolean"],
        "next_step": "Manually verify ownership, route implementation, CRM and backup in authenticated Timeweb."
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--backend-root", type=Path, required=True)
    parser.add_argument("--consumer-root", type=Path, required=True)
    parser.add_argument("--family-root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inventory(args.home, args.backend_root,
                               args.consumer_root, args.family_root),
                     ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
