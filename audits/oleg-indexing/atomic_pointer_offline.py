#!/usr/bin/env python3
"""Offline-only proof of single-pointer switch for both Oleg domains.

This module deliberately refuses any tree without a sandbox marker under /tmp.
It is NOT a production installer and never contacts Timeweb.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

DOMAINS = ("potrebpravo.ru", "semya-yurist.ru")
STATUS = "OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT"
NAME_RE = re.compile(r"^v[a-zA-Z0-9_-]{1,70}$")
PATH_RE = re.compile(r"^[a-zA-Z0-9_./-]+$")
MARKER = ".oleg-atomic-offline-sandbox"
POINTER = ".oleg-current-release"
VERSIONS = ".oleg-release-versions"
JOURNAL = ".oleg-pointer-transaction.json"


class SwitchError(ValueError):
    pass


class SimulatedCrash(Exception):
    pass


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 256), b""):
            h.update(chunk)
    return h.hexdigest()


def sandbox(root):
    root = Path(root).resolve(strict=True)
    if not root.is_relative_to(Path("/tmp")) or not (root / MARKER).is_file():
        raise SwitchError("OFFLINE_ONLY: sandbox marker under /tmp is required")
    return root


def version_path(root, name):
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise SwitchError("Unsafe version identifier")
    versions = root / VERSIONS
    if versions.is_symlink() or not versions.is_dir():
        raise SwitchError("Immutable versions directory missing")
    version = versions / name
    if version.is_symlink() or not version.is_dir() or version.resolve().parent != versions.resolve():
        raise SwitchError("Candidate release must be a direct real directory")
    return version


def current_name(root):
    pointer = root / POINTER
    if not pointer.is_symlink():
        raise SwitchError("Shared release pointer is missing")
    link = os.readlink(pointer)
    candidate = Path(link)
    if candidate.is_absolute() or len(candidate.parts) != 2 or candidate.parts[0] != VERSIONS:
        raise SwitchError("Pointer must target a version inside the private versions directory")
    version_path(root, candidate.parts[1])
    for host in DOMAINS:
        docroot = root / host / "public_html"
        if not docroot.is_symlink():
            raise SwitchError("Both public_html paths must follow the shared pointer")
        expected = os.path.normpath(str(root / POINTER / host / "public_html"))
        resolved_link = os.readlink(docroot)
        actual = os.path.normpath(str((docroot.parent / resolved_link) if not os.path.isabs(resolved_link) else Path(resolved_link)))
        if actual != expected or not docroot.is_dir():
            raise SwitchError("Docroot does not follow exactly the shared pointer: " + host)
    return candidate.parts[1]


def safe_rel(rel):
    if not isinstance(rel, str) or not PATH_RE.fullmatch(rel):
        raise SwitchError("Unexpected manifest path")
    if rel.startswith("/") or any(x in ("", ".", "..") for x in rel.split("/")):
        raise SwitchError("Unsafe relative path")
    path = Path(rel)
    if path.suffix not in (".html", ".js"):
        raise SwitchError("Non-HTML/JS release manifest path")
    if path.suffix == ".js" and str(path) != "assets/legal-assistant-v4.js":
        raise SwitchError("Only the reviewed assistant JS asset is permitted")
    return path


def regular(path):
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise SwitchError("Regular file required: " + str(path))


def snapshot_files(root):
    output = {}
    for host in DOMAINS:
        site = root / host / "public_html"
        if site.is_symlink() or not site.is_dir():
            raise SwitchError("Version site directory invalid")
        for parent, dirs, files in os.walk(site, followlinks=False):
            parent = Path(parent)
            for name in dirs:
                if (parent / name).is_symlink():
                    raise SwitchError("Symlink in release snapshot")
            for name in files:
                path = parent / name
                regular(path)
                output[host + "/" + str(path.relative_to(site))] = sha(path)
    return output


def audit(root, manifest, new_version):
    root = sandbox(root)
    old_version = current_name(root)
    if old_version == new_version:
        raise SwitchError("Candidate is already active")
    old = version_path(root, old_version)
    new = version_path(root, new_version)
    data = json.loads(Path(manifest).read_text(encoding="utf8"))
    if data.get("status") != STATUS:
        raise SwitchError("Unexpected release manifest status")
    entries = data.get("manifest")
    if not isinstance(entries, list) or len(entries) != 43:
        raise SwitchError("43 exact reviewed files required")
    expected = {}
    for item in entries:
        host = item.get("host")
        if host not in DOMAINS:
            raise SwitchError("Domain not allowed")
        path = safe_rel(item.get("path"))
        key = host + "/" + str(path)
        if key in expected or item.get("changed") is not True:
            raise SwitchError("Duplicate or unchanged manifest entry")
        a, b = item.get("original_sha256"), item.get("proposed_sha256")
        if not all(isinstance(s, str) and re.fullmatch(r"[0-9a-f]{64}", s) for s in (a, b)) or a == b:
            raise SwitchError("Invalid source/target SHA")
        expected[key] = (a, b)
    if sum(k.endswith(".html") for k in expected) != 41:
        raise SwitchError("Expected 41 HTML and two JS")
    actual_old, actual_new = snapshot_files(old), snapshot_files(new)
    if set(actual_old) != set(actual_new):
        raise SwitchError("Incomplete immutable snapshot: file set differs")
    for key in actual_old:
        a, b = expected.get(key, (actual_old[key], actual_old[key]))
        if actual_old[key] != a or actual_new[key] != b:
            raise SwitchError("Source drift or unreviewed candidate content: " + key)
    if not set(expected).issubset(actual_old):
        raise SwitchError("Missing staged files")
    return {"old": old_version, "new": new_version, "files_reviewed": 43, "full_snapshot_files": len(actual_old),
            "two_domains_ready": True, "only_reviewed_files_changed": True}


def atomic_json(path, data):
    tmp = path.with_name(path.name + ".new")
    if tmp.exists():
        raise SwitchError("Unexpected transaction temp file")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf8") as out:
            json.dump(data, out, ensure_ascii=False, indent=2)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        fsync_parent(path.parent)
    finally:
        if tmp.exists():
            tmp.unlink()


def fsync_parent(parent):
    fd = os.open(str(parent), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_point(root, version):
    version_path(root, version)
    target = VERSIONS + "/" + version
    temp = root / (POINTER + ".next")
    if temp.exists() or temp.is_symlink():
        raise SwitchError("Unexpected pointer temp file")
    os.symlink(target, temp)
    try:
        os.replace(temp, root / POINTER)
        fsync_parent(root)
    finally:
        if temp.is_symlink():
            temp.unlink()


def locked(root, action):
    lockpath = root / ".oleg-release.lock"
    lock_fd = os.open(str(lockpath), os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(lock_fd, "r+") as fd:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
        return action()


def switch(root, manifest, version, crash_at=None):
    root = sandbox(root)
    def action():
        journal = root / JOURNAL
        if journal.exists() and json.loads(journal.read_text("utf8")).get("state") == "PREPARED":
            raise SwitchError("Unresolved transaction: recovery required")
        preflight = audit(root, manifest, version)
        record = dict(preflight, state="PREPARED", sandbox_only=True)
        atomic_json(journal, record)
        if crash_at == "after_prepare":
            raise SimulatedCrash("After writing durable PREPARED")
        atomic_point(root, version)
        if crash_at == "after_pointer":
            raise SimulatedCrash("After single atomic pointer replacement")
        if current_name(root) != version:
            raise SwitchError("Pointer postflight failed")
        record["state"] = "COMMITTED"
        atomic_json(journal, record)
        return record
    return locked(root, action)


def recover(root):
    root = sandbox(root)
    def action():
        journal = root / JOURNAL
        if not journal.exists():
            raise SwitchError("No transaction to recover")
        record = json.loads(journal.read_text("utf8"))
        status = record.get("state")
        now = current_name(root)
        if status == "PREPARED":
            if now not in (record["old"], record["new"]):
                raise SwitchError("Unexpected live pointer during recovery")
            if now == record["new"]:
                atomic_point(root, record["old"])
            if current_name(root) != record["old"]:
                raise SwitchError("Recovery did not restore original version")
            record["state"] = "ROLLED_BACK"
            atomic_json(journal, record)
        elif status == "COMMITTED":
            if now != record["new"]:
                raise SwitchError("Committed pointer differs from journal")
        elif status != "ROLLED_BACK" or now != record["old"]:
            raise SwitchError("Unexpected transaction state")
        return record
    return locked(root, action)


def manual_rollback(root):
    root = sandbox(root)
    def action():
        journal = root / JOURNAL
        record = json.loads(journal.read_text("utf8"))
        if record.get("state") != "COMMITTED" or current_name(root) != record["new"]:
            raise SwitchError("Only a verified committed release can be rolled back")
        atomic_point(root, record["old"])
        if current_name(root) != record["old"]:
            raise SwitchError("Manual rollback verification failed")
        record["state"] = "ROLLED_BACK"
        atomic_json(journal, record)
        return record
    return locked(root, action)
