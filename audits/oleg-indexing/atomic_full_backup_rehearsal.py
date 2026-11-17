#!/usr/bin/env python3
"""Use a real private backup as source for OFFLINE two-domain crash/rollback rehearsal.

Never connects to hosting. Never modifies input archives or source stage.
Writes exclusively to a temporary sandbox under /tmp and one optional report path.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import os
import shutil
import tarfile
import tempfile

from atomic_pointer_offline import (
    DOMAINS, MARKER, POINTER, VERSIONS,
    SimulatedCrash, audit, current_name, manual_rollback, recover, switch,
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def extract_safely(archive, target):
    total = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isdir() and not member.isfile():
                raise ValueError("Unexpected non-regular archive member")
            rel = PurePosixPath(member.name)
            if rel.is_absolute() or ".." in rel.parts or len(rel.parts) < 2 or rel.parts[0] not in DOMAINS or rel.parts[1] != "public_html":
                raise ValueError("Archive contains unexpected path")
            dst = target.joinpath(*rel.parts)
            if not dst.resolve().is_relative_to(target.resolve()):
                raise ValueError("Archive path escaped sandbox")
            if member.isdir():
                dst.mkdir(parents=True, exist_ok=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, dst.open("xb") as out:
                    shutil.copyfileobj(source, out)
                total += 1
    return total


def run(backup, backup_sha, stage_root, manifest_file):
    backup = Path(backup)
    stage_root = Path(stage_root)
    manifest_file = Path(manifest_file)
    if sha(backup.read_bytes()) != backup_sha:
        raise ValueError("Timeweb backup SHA mismatches expected: abort")
    manifest = json.loads(manifest_file.read_text(encoding="utf8"))
    items = manifest["manifest"]
    if len(items) != 43 or manifest.get("status") != "OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT":
        raise ValueError("Wrong 43-file release manifest")
    with tempfile.TemporaryDirectory(prefix="oleg-atomic-real-backup-") as temporary:
        root = Path(temporary)
        (root / MARKER).write_text("Offline user test fixture only.", encoding="utf8")
        versions = root / VERSIONS
        old = versions / "v000"
        new = versions / "v001"
        old.mkdir(parents=True)
        total = extract_safely(backup, old)
        if total != 168:
            raise ValueError("Unexpected number of original backup files")
        shutil.copytree(old, new)
        for item in items:
            host, rel = item["host"], item["path"]
            if host not in DOMAINS:
                raise ValueError("Unknown release host")
            original = old / host / "public_html" / rel
            target = new / host / "public_html" / rel
            prepared = stage_root / host / "public_html" / rel
            if not original.is_file() or original.is_symlink() or not target.is_file() or target.is_symlink():
                raise ValueError("Missing original or staged release path")
            if sha(original.read_bytes()) != item["original_sha256"]:
                raise ValueError("Real backup drift: " + host + "/" + rel)
            if not prepared.is_file() or sha(prepared.read_bytes()) != item["proposed_sha256"]:
                raise ValueError("Staged candidate differs from exact reviewed SHA")
            target.write_bytes(prepared.read_bytes())
        os.symlink(VERSIONS + "/v000", root / POINTER)
        for host in DOMAINS:
            site_dir = root / host
            site_dir.mkdir()
            os.symlink("../" + POINTER + "/" + host + "/public_html", site_dir / "public_html")
        first = audit(root, manifest_file, "v001")
        if first["full_snapshot_files"] != total:
            raise ValueError("Candidate did not preserve the full backup snapshot")
        # Simulate abrupt stop after both sites' shared pointer was changed,
        # before the durable committed journal was written.
        try:
            switch(root, manifest_file, "v001", crash_at="after_pointer")
        except SimulatedCrash:
            pass
        else:
            raise AssertionError("Crash injection was not triggered")
        if current_name(root) != "v001":
            raise AssertionError("Pointer not switched as expected")
        rec = recover(root)
        if rec["state"] != "ROLLED_BACK" or current_name(root) != "v000":
            raise AssertionError("Recovery failed")
        # A second verified commit and explicit rollback must restore
        # the original complete release as well.
        completed = switch(root, manifest_file, "v001")
        if completed["state"] != "COMMITTED" or current_name(root) != "v001":
            raise AssertionError("Single pointer commit failed")
        rolled = manual_rollback(root)
        if rolled["state"] != "ROLLED_BACK" or current_name(root) != "v000":
            raise AssertionError("Manual rollback failed")
        for item in items:
            path = root / item["host"] / "public_html" / item["path"]
            if sha(path.read_bytes()) != item["original_sha256"]:
                raise AssertionError("Original files not fully recovered")
    return {
        "utc": datetime.now(timezone.utc).isoformat(),
        "status": "OFFLINE_REAL_BACKUP_REHEARSAL_PASS",
        "real_private_backup_sha256_match": True,
        "archive_files_reconstructed": total,
        "release_reviewed_files": len(items),
        "both_domains_single_pointer": True,
        "crash_after_pointer_recovery_pass": True,
        "manual_rollback_pass": True,
        "whole_snapshot_unchanged_files_preserved": True,
        "production_modified": False,
        "production_topology_migrated": False,
        "authorized_for_production_release": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup", required=True)
    parser.add_argument("--backup-sha256", required=True)
    parser.add_argument("--stage-root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    result = run(args.backup, args.backup_sha256, args.stage_root, args.manifest)
    Path(args.report).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf8")
    print("REAL_BACKUP_REHEARSAL", json.dumps(result, ensure_ascii=False))
