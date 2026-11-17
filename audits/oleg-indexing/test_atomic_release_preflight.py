"""Regression tests for read-only two-domain release and atomicity gate."""
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from atomic_release_preflight import GateError, preflight, pointer_state


def sha(data):
    return hashlib.sha256(data).hexdigest()


class AtomicPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.live = self.base / "live"
        self.stage = self.base / "stage"
        self.live.mkdir()
        self.stage.mkdir()
        self.entries = []
        self.original_files = []
        for host, count in (("potrebpravo.ru", 23), ("semya-yurist.ru", 18)):
            for i in range(count + 1):
                rel = "assets/legal-assistant-v4.js" if i == count else (
                    "index.html" if i == 0 else "services/page-%02d.html" % i
                )
                old = ("source|" + host + "|" + rel).encode()
                new = ("proposal|" + host + "|" + rel).encode()
                current = self.live / host / "public_html" / rel
                proposed = self.stage / host / "public_html" / rel
                current.parent.mkdir(parents=True, exist_ok=True)
                proposed.parent.mkdir(parents=True, exist_ok=True)
                current.write_bytes(old)
                proposed.write_bytes(new)
                self.original_files.append((current, old))
                self.entries.append({
                    "host": host, "path": rel, "original_sha256": sha(old),
                    "proposed_sha256": sha(new), "changed": True
                })
        assert len(self.entries) == 43
        self.manifest = self.base / "manifest.json"
        self.write_manifest()

    def write_manifest(self):
        self.manifest.write_text(json.dumps({
            "status": "OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT",
            "manifest": self.entries
        }), encoding="utf-8")

    def check_no_live_writes(self):
        for path, old in self.original_files:
            self.assertEqual(path.read_bytes(), old)

    def test_physical_live_roots_fail_atomic_gate(self):
        result = preflight(self.live, self.stage, self.manifest)
        self.assertEqual(result["source_and_staged_sha_verified"], 43)
        self.assertEqual((result["html_files"], result["js_files"]), (41, 2))
        self.assertFalse(result["safe_single_pointer_atomic_release"])
        self.assertEqual(result["atomicity_gate"], "missing_shared_release_pointer")
        self.assertFalse(result["live_modified"])
        self.check_no_live_writes()

    def test_one_shared_pointer_for_both_domains_is_atomic_ready(self):
        releases = self.live / ".oleg-release-versions"
        release = releases / "verified-v1"
        release.mkdir(parents=True)
        for host in ("potrebpravo.ru", "semya-yurist.ru"):
            current_root = self.live / host / "public_html"
            stored_root = release / host / "public_html"
            stored_root.parent.mkdir(parents=True)
            shutil.move(str(current_root), str(stored_root))
        current = self.live / ".oleg-current-release"
        current.symlink_to(release, target_is_directory=True)
        for host in ("potrebpravo.ru", "semya-yurist.ru"):
            (self.live / host / "public_html").symlink_to(
                current / host / "public_html", target_is_directory=True
            )
        status = preflight(self.live, self.stage, self.manifest)
        self.assertTrue(status["safe_single_pointer_atomic_release"])
        self.assertEqual(status["atomicity_gate"], "single_pointer_topology_verified")
        self.check_no_live_writes()
        # Pointing one site directly to the VERSION would not update it on a swap.
        link = self.live / "semya-yurist.ru" / "public_html"
        link.unlink()
        link.symlink_to(release / "semya-yurist.ru" / "public_html", target_is_directory=True)
        status = preflight(self.live, self.stage, self.manifest)
        self.assertFalse(status["safe_single_pointer_atomic_release"])
        self.assertEqual(status["atomicity_gate"], "docroot_does_not_follow_shared_pointer")

    def test_refuse_live_source_drift(self):
        target, _ = self.original_files[3]
        target.write_bytes(b"unexpected live edit")
        with self.assertRaisesRegex(GateError, "Live server source SHA drift"):
            preflight(self.live, self.stage, self.manifest)

    def test_refuse_staged_sha_drift(self):
        item = self.entries[5]
        f = self.stage / item["host"] / "public_html" / item["path"]
        f.write_bytes(b"unexpected staged edit")
        with self.assertRaisesRegex(GateError, "Staged output SHA"):
            preflight(self.live, self.stage, self.manifest)

    def test_refuse_duplicate_and_path_traversal(self):
        self.entries[3] = dict(self.entries[0])
        self.write_manifest()
        with self.assertRaisesRegex(GateError, "Duplicate"):
            preflight(self.live, self.stage, self.manifest)
        self.entries[3]["path"] = "../private-data.html"
        self.write_manifest()
        with self.assertRaisesRegex(GateError, "Unsafe relative path"):
            preflight(self.live, self.stage, self.manifest)

    def test_refuse_symlink_in_staged_files(self):
        item = self.entries[1]
        f = self.stage / item["host"] / "public_html" / item["path"]
        f.unlink()
        f.symlink_to(self.stage / item["host"] / "public_html" / "index.html")
        with self.assertRaisesRegex(GateError, "symlink"):
            preflight(self.live, self.stage, self.manifest)

    def test_private_backup_digest_and_member_validation(self):
        backup = self.base / "backup.tar.gz"
        with tarfile.open(backup, "w:gz") as archive:
            for item in self.entries:
                f = self.live / item["host"] / "public_html" / item["path"]
                archive.add(f, arcname=item["host"] + "/public_html/" + item["path"])
        ok = preflight(self.live, self.stage, self.manifest, backup, sha(backup.read_bytes()))
        self.assertTrue(ok["private_backup_sha_verified"])
        with self.assertRaisesRegex(GateError, "Backup archive SHA mismatch"):
            preflight(self.live, self.stage, self.manifest, backup, "0" * 64)

    def test_readonly_requires_exact_manifest(self):
        self.entries.pop()
        self.write_manifest()
        with self.assertRaisesRegex(GateError, "43 reviewed"):
            preflight(self.live, self.stage, self.manifest)


if __name__ == "__main__":
    unittest.main()
