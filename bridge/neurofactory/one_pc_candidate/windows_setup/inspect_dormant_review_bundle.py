"""Offline integrity boundary for the 2026-10-22 UNRELEASED Windows HOST bundle.

Pure read-only; it verifies a reviewer-supplied exact expected source revision
and every staged file. THIS IS NOT SIGNATURE VERIFICATION OR RELEASE APPROVAL.
The independent reviewer must pin the archive digest separately, and a signed
release gate MUST run before any owner-machine deployment.

No key enrollment, machine permissions, SCM operations or auto-approval.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

HEX40 = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
RELPATH = re.compile(r"[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)*\Z")
VENDOR = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
SERVICE = "neurofactory_dormant_service.py"
READONLY_AUDITOR = "audit_protected_host_readonly.ps1"
REQUIRED_ROOT = frozenset({
    SERVICE, READONLY_AUDITOR, "dormant-config.json", "README-ACCEPTANCE-RU.txt",
})
MANIFEST_FIELDS = frozenset({
    "schema","source_sha","vendor_python_sha256","service_sha256","status",
    "production_release_approved","host_effect_allowed",
    "windows_service_installed","independent_reviewer_approved","entries",
})
ENTRY_FIELDS = frozenset({"path","sha256","bytes"})
CFG_FIELDS = frozenset((
    "schema","service_name","source_sha40","mode",
    "real_host_execution_allowed","core_queue_allowed",
    "network_listener_allowed","production_release_approved",
    "independent_review_approved","owner_key_installed",
    "external_witness_verified",
))
CFG_FALSE = CFG_FIELDS - {"schema","service_name","source_sha40","mode"}

class BundleDenied(ValueError):
    pass

def _deny(reason):
    raise BundleDenied("Untrusted Windows review package: " + reason)

def _unique(pairs):
    answer = {}
    for key, value in pairs:
        if key in answer:
            _deny("duplicate JSON property")
        answer[key] = value
    return answer

def _read_json(path, size_max):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > size_max:
            _deny("untrusted metadata file")
        data = path.read_bytes()
        if len(data) > size_max or len(data) < 10:
            _deny("metadata size")
        return json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique,
                          parse_constant=lambda _: _deny("invalid JSON constant"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BundleDenied("Unreadable release metadata") from exc

def _regular(root, path, *, directory=False):
    p = root/path
    try:
        if p.is_symlink():
            _deny("symbolic link")
        st = p.lstat()
        wanted = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
        if not wanted or (os.name == "nt" and
                          st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            _deny("reparse, junction or nonregular filesystem object")
    except OSError as exc:
        raise BundleDenied("Staged file disappeared or is unreadable") from exc
    return st

def verify_review_bundle(root: Path, *, expected_source_sha: str):
    if (type(root) is not Path or not root.is_absolute() or
        type(expected_source_sha) is not str or not HEX40.fullmatch(expected_source_sha)):
        _deny("operator must independently pin exact source")
    _regular(root, Path("."), directory=True)
    manifest = _read_json(root/"bundle-manifest.json", 16000)
    if (type(manifest) is not dict or set(manifest) != MANIFEST_FIELDS or
        manifest["schema"] != "nf.windows.protected_host_review_bundle.v1" or
        manifest["status"] != "UNSIGNED_REVIEW_ONLY" or
        manifest["source_sha"] != expected_source_sha or
        manifest["vendor_python_sha256"] != VENDOR or
        type(manifest["service_sha256"]) is not str or
        not HEX64.fullmatch(manifest["service_sha256"]) or
        any(manifest[k] is not False for k in (
            "production_release_approved","host_effect_allowed",
            "windows_service_installed","independent_reviewer_approved",
        ))):
        _deny("invalid review-only envelope")
    entries = manifest["entries"]
    if type(entries) is not list or not 35 <= len(entries) <= 65:
        _deny("unexpected immutable file count")
    seen = set()
    sizes = 0
    for item in entries:
        if type(item) is not dict or set(item) != ENTRY_FIELDS or \
                type(item["path"]) is not str or len(item["path"]) > 170 or \
                not RELPATH.fullmatch(item["path"]) or \
                any(x in {".",".."} for x in item["path"].split("/")) or \
                type(item["sha256"]) is not str or not HEX64.fullmatch(item["sha256"]) or \
                type(item["bytes"]) is not int or not 0 < item["bytes"] <= 30_000_000:
            _deny("unsafe manifest entry")
        path = item["path"]
        folded = path.casefold()
        if folded in seen or path == "bundle-manifest.json" or (
                "/" in path and not path.startswith("runtime/")):
            _deny("duplicate or unexpected runtime location")
        if "/" not in path and path not in REQUIRED_ROOT:
            _deny("unexpected root executable/script")
        seen.add(folded)
        sizes += item["bytes"]
        if sizes > 55_000_000:
            _deny("unexpected cumulative file size")
        rel = Path(*path.split("/"))
        for parent in rel.parents:
            _regular(root,parent,directory=True)
        info = _regular(root,rel)
        if info.st_size != item["bytes"]:
            _deny("staged file size mismatch")
        h = hashlib.sha256()
        with (root/rel).open("rb") as file:
            while block := file.read(1024*1024):
                h.update(block)
        if h.hexdigest() != item["sha256"]:
            _deny("staged file SHA256 mismatch")
    if not REQUIRED_ROOT.issubset(seen) or "runtime/python.exe" not in seen:
        _deny("missing service, auditor, config, manual or Python executable")
    # Detect any extra file, unlisted folder or reparse point even if the
    # attacker supplied a manifest that omits it.
    actual = set()
    for cur,dirs,files in os.walk(root, topdown=True,followlinks=False):
        where = Path(cur)
        for name in dirs:
            rel = (where/name).relative_to(root).as_posix()
            if rel not in ("runtime", "status"):
                _deny("unlisted directory")
            _regular(root,Path(rel),directory=True)
        for name in files:
            rel = (where/name).relative_to(root).as_posix()
            if rel != "bundle-manifest.json":
                actual.add(rel.casefold())
            _regular(root,Path(rel))
    if actual != seen:
        _deny("unlisted, missing or ambiguous archive file")
    if hashlib.sha256((root/SERVICE).read_bytes()).hexdigest() != manifest["service_sha256"]:
        _deny("installed Windows service mismatches signed candidate content")
    cfg = _read_json(root/"dormant-config.json", 1400)
    if (type(cfg) is not dict or set(cfg) != CFG_FIELDS or
            cfg["schema"] != "nf.windows.dormant_host_provision.v1" or
            cfg["service_name"] != "NeurofactoryCoreHost" or
            cfg["source_sha40"] != expected_source_sha or
            cfg["mode"] != "REVIEW_BLOCKED_NOT_PRODUCTION" or
            any(cfg[k] is not False for k in CFG_FALSE)):
        _deny("malicious service authority in staged config")
    return {
        "schema":"nf.windows.dormant_review_bundle_audit.v1",
        "status":"INTEGRITY_MATCHES_UNRELEASED_BUNDLE_NO_AUTHORITY",
        "source_sha40":expected_source_sha,
        "checked_files":len(seen),
        "immutable_file_sha256_verified":True,
        "windows_service_install_allowed":False,
        "production_release_approved":False,
        "current_owner_or_reviewer_keys_attested":False,
        "archive_authenticode_signature_verified":False,
        "operator_trust_root_enrolled":False,
    }
