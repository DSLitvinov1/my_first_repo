#!/usr/bin/env python3
"""Read-only 43-file Timeweb release fingerprint and single-switch topology gate.

No write, copy, symlink creation, SSH, web request or deployment functionality.
A 43-file per-path os.replace() batch is *not* a two-domain atomic release.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

DOMAINS = frozenset(("potrebpravo.ru", "semya-yurist.ru"))
STATUS = "OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT"
HEX = re.compile(r"^[0-9a-f]{64}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_./-]+$")


class GateError(ValueError):
    pass


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 256), b""):
            h.update(block)
    return h.hexdigest()


def checked_rel(value):
    if not isinstance(value, str) or not SAFE_PATH.fullmatch(value):
        raise GateError("Unexpected relative path")
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ("", ".", "..") for x in value.split("/")):
        raise GateError("Unsafe relative path")
    if p.suffix not in (".html", ".js") or len(p.parts) > 5:
        raise GateError("Unapproved release file")
    return Path(*p.parts)


def checked_regular(path, root):
    if not path.is_file() or path.is_symlink():
        raise GateError("File is absent or a symlink: " + str(path))
    if not path.resolve().is_relative_to(root.resolve()):
        raise GateError("Path escaped its allowed root")
    if not stat.S_ISREG(path.stat().st_mode):
        raise GateError("Not a regular file")


def pointer_state(root):
    """One shared pointer must be used by BOTH site docroots for one atomic switch."""
    parent = root.absolute()
    current = parent / ".oleg-current-release"
    releases = parent / ".oleg-release-versions"
    if not current.is_symlink() or not releases.is_dir() or releases.is_symlink():
        return False, "missing_shared_release_pointer"
    try:
        version = current.resolve(strict=True)
        allowed = releases.resolve(strict=True)
    except (OSError, RuntimeError):
        return False, "invalid_release_pointer"
    if not version.is_dir() or version.parent != allowed:
        return False, "pointer_target_not_one_managed_version"
    for host in DOMAINS:
        docroot = parent / host / "public_html"
        if not docroot.is_symlink():
            return False, "physical_docroots_cannot_switch_atomically"
        raw = Path(os.readlink(docroot))
        raw = raw if raw.is_absolute() else docroot.parent / raw
        wanted = current / host / "public_html"
        # Compare LEXICAL symlink paths. Resolve would accept an unsafe direct
        # symlink to a specific version, which would not follow pointer swaps.
        if os.path.normpath(str(raw)) != os.path.normpath(str(wanted)):
            return False, "docroot_does_not_follow_shared_pointer"
        if not docroot.is_dir():
            return False, "shared_pointer_site_missing"
    return True, "single_pointer_topology_verified"


def preflight(site_parent, release_root, manifest_path, backup_path=None, backup_sha=None):
    site_parent = Path(site_parent).absolute()
    release_root = Path(release_root).absolute()
    manifest_path = Path(manifest_path).absolute()
    report = json.loads(manifest_path.read_text(encoding="utf-8"))
    if report.get("status") != STATUS:
        raise GateError("Unexpected release manifest status")
    entries = report.get("manifest")
    if not isinstance(entries, list) or len(entries) != 43:
        raise GateError("Expected exactly 43 reviewed files")
    if not site_parent.is_dir() or not release_root.is_dir():
        raise GateError("Source or stage root missing")
    matched = {"potrebpravo.ru": 0, "semya-yurist.ru": 0}
    html = js = 0
    seen = set()
    for entry in entries:
        host = entry.get("host")
        if host not in DOMAINS:
            raise GateError("Host not allowlisted")
        rel = checked_rel(entry.get("path"))
        key = (host, str(rel))
        if key in seen:
            raise GateError("Duplicate entry in release manifest")
        seen.add(key)
        if entry.get("changed") is not True:
            raise GateError("A reviewed file unexpectedly unchanged")
        old = entry.get("original_sha256")
        new = entry.get("proposed_sha256")
        if not isinstance(old, str) or not isinstance(new, str) or not HEX.fullmatch(old) or not HEX.fullmatch(new) or old == new:
            raise GateError("Invalid or unchanged digest")
        site_root = site_parent / host / "public_html"
        stage_site_root = release_root / host / "public_html"
        live = site_root / rel
        staged = stage_site_root / rel
        checked_regular(live, site_root)
        checked_regular(staged, stage_site_root)
        if digest(live) != old:
            raise GateError("Live server source SHA drift: " + host + "/" + str(rel))
        if digest(staged) != new:
            raise GateError("Staged output SHA differs from reviewed manifest")
        matched[host] += 1
        if rel.suffix == ".html":
            html += 1
        else:
            js += 1
            if str(rel) != "assets/legal-assistant-v4.js":
                raise GateError("Unapproved JS asset")
    if (html, js) != (41, 2) or not all(matched.values()):
        raise GateError("Wrong release composition")
    backup_checked = False
    if backup_path is not None:
        backup_path = Path(backup_path).absolute()
        if not backup_sha or not HEX.fullmatch(backup_sha):
            raise GateError("Expected private backup digest required")
        checked_regular(backup_path, backup_path.parent)
        if digest(backup_path) != backup_sha:
            raise GateError("Backup archive SHA mismatch")
        with tarfile.open(backup_path, "r:gz") as tar:
            members = tar.getmembers()
            # Read archive index only. Do not extract, and reject unexpected paths.
            if len(members) < 43 or any(
                m.issym() or m.islnk() or m.name.startswith("/")
                or ".." in PurePosixPath(m.name).parts for m in members
            ):
                raise GateError("Untrusted backup archive member")
        backup_checked = True
    atomic, reason = pointer_state(site_parent)
    return {
        "mode": "READ_ONLY_PREFLIGHT",
        "source_and_staged_sha_verified": sum(matched.values()),
        "html_files": html,
        "js_files": js,
        "sites": matched,
        "private_backup_sha_verified": backup_checked,
        "safe_single_pointer_atomic_release": atomic,
        "atomicity_gate": reason,
        "release_authorized": False,
        "live_modified": False,
        "next_action": (
            "Ready for separate owner-approved reviewed release-switch procedure"
            if atomic else "DO_NOT_DEPLOY: first design and independently verify shared-pointer migration"
        ),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--site-parent", required=True, type=Path)
    ap.add_argument("--release-root", required=True, type=Path)
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("--backup", type=Path)
    ap.add_argument("--backup-sha256")
    ap.add_argument("--require-atomic", action="store_true")
    args = ap.parse_args(argv)
    result = preflight(args.site_parent, args.release_root, args.manifest, args.backup, args.backup_sha256)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if (result["safe_single_pointer_atomic_release"] or not args.require_atomic) else 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        print("PREFLIGHT_ABORTED: " + str(exc), file=sys.stderr)
        sys.exit(2)
