#!/usr/bin/env python3
"""Offline synthetic release-pointer acceptance, no Timeweb access or browser writes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from atomic_pointer_offline import (
    MARKER, POINTER, VERSIONS, SwitchError, SimulatedCrash, audit,
    current_name, manual_rollback, recover, switch,
)

DOMAINS = ("potrebpravo.ru", "semya-yurist.ru")
STATUS = "OFFLINE_UNIFIED_RELEASE_READY_FOR_OWNER_SERVER_PREFLIGHT"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fixture(parent):
    root = Path(parent) / "oleg-two-sites"
    root.mkdir()
    (root / MARKER).write_text("Never use on the real hosting.", encoding="utf8")
    versions = root / VERSIONS
    versions.mkdir()
    old, new = versions / "v000", versions / "v001"
    pairs = []
    manifest = []
    for host, count in zip(DOMAINS, (23, 18)):
        site = old / host / "public_html"
        site.mkdir(parents=True)
        for idx in range(count):
            name = "index.html" if idx == 0 else ("services/service-%02d.html" % idx)
            pairs.append((host, name))
            path = site / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("original:" + host + ":" + name).encode())
        path = site / "assets" / "legal-assistant-v4.js"
        path.parent.mkdir()
        path.write_bytes(("old js " + host).encode())
        pairs.append((host, "assets/legal-assistant-v4.js"))
        (site / "robots.txt").write_text("User-agent: *\nAllow: /\n", encoding="utf8")
        (site / "assets" / "styling.css").write_text("body{color:black}", encoding="utf8")
    shutil.copytree(old, new)
    for host, name in pairs:
        original = (old / host / "public_html" / name).read_bytes()
        replacement = ("new reviewed:"+host+":"+name).encode()
        (new / host / "public_html" / name).write_bytes(replacement)
        manifest.append({
            "host": host, "path": name, "original_sha256": sha(original),
            "proposed_sha256": sha(replacement), "changed": True,
        })
    os.symlink(VERSIONS + "/v000", root / POINTER)
    for host in DOMAINS:
        site_dir = root / host
        site_dir.mkdir()
        os.symlink("../" + POINTER + "/" + host + "/public_html", site_dir / "public_html")
    plan = root / "manifest.json"
    plan.write_text(json.dumps({"status": STATUS, "manifest": manifest}, indent=2), encoding="utf8")
    assert len(pairs) == 43
    return root, plan, pairs


class AtomicPointerAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="oleg-atomic-")
        self.addCleanup(self.tmp.cleanup)
        self.root, self.plan, self.pairs = fixture(self.tmp.name)

    def test_ready_43_guarded_files_and_unmodified_assets(self):
        result = audit(self.root, self.plan, "v001")
        self.assertEqual(result["files_reviewed"], 43)
        self.assertTrue(result["two_domains_ready"])
        self.assertEqual(result["full_snapshot_files"], 47)
        self.assertEqual(current_name(self.root), "v000")

    def test_single_shared_pointer_swaps_both_sites_and_manual_rollback(self):
        before = [((self.root / host / "public_html" / name).read_bytes()) for host,name in self.pairs]
        status = switch(self.root, self.plan, "v001")
        self.assertEqual(status["state"], "COMMITTED")
        self.assertEqual(current_name(self.root), "v001")
        after = [((self.root / host / "public_html" / name).read_bytes()) for host,name in self.pairs]
        self.assertTrue(all(a != b for a,b in zip(before,after)))
        for host in DOMAINS:
            self.assertEqual((self.root / host / "public_html" / "robots.txt").read_text(), "User-agent: *\nAllow: /\n")
        done = manual_rollback(self.root)
        self.assertEqual(done["state"], "ROLLED_BACK")
        self.assertEqual(current_name(self.root), "v000")
        self.assertEqual([((self.root / host / "public_html" / name).read_bytes()) for host,name in self.pairs], before)

    def test_crash_before_pointer_never_leaks_partial_release(self):
        with self.assertRaises(SimulatedCrash):
            switch(self.root, self.plan, "v001", crash_at="after_prepare")
        self.assertEqual(current_name(self.root), "v000")
        self.assertEqual(recover(self.root)["state"], "ROLLED_BACK")
        self.assertEqual(current_name(self.root), "v000")

    def test_crash_after_pointer_recovers_both_sites_together(self):
        with self.assertRaises(SimulatedCrash):
            switch(self.root, self.plan, "v001", crash_at="after_pointer")
        self.assertEqual(current_name(self.root), "v001")
        self.assertEqual(recover(self.root)["state"], "ROLLED_BACK")
        self.assertEqual(current_name(self.root), "v000")
        self.assertEqual(recover(self.root)["state"], "ROLLED_BACK")

    def test_candidate_source_drift_fails_closed(self):
        p = self.root / VERSIONS / "v000" / "potrebpravo.ru" / "public_html" / "index.html"
        p.write_text("not approved")
        with self.assertRaisesRegex(SwitchError,"Source drift"):
            audit(self.root,self.plan,"v001")
        self.assertEqual(current_name(self.root), "v000")

    def test_unreviewed_asset_change_is_rejected(self):
        p = self.root / VERSIONS / "v001" / "semya-yurist.ru" / "public_html" / "assets" / "styling.css"
        p.write_text("body{color:red}")
        with self.assertRaisesRegex(SwitchError,"unreviewed"):
            audit(self.root,self.plan,"v001")

    def test_missing_file_fails_closed(self):
        p = self.root / VERSIONS / "v001" / "potrebpravo.ru" / "public_html" / "index.html"
        p.unlink()
        with self.assertRaisesRegex(SwitchError,"Incomplete immutable"):
            audit(self.root,self.plan,"v001")

    def test_suspicious_symlink_in_release_fails_closed(self):
        p = self.root / VERSIONS / "v001" / "potrebpravo.ru" / "public_html" / "index.html"
        p.unlink()
        p.symlink_to("/etc/passwd")
        with self.assertRaises(SwitchError):
            audit(self.root,self.plan,"v001")

    def test_wrong_site_pointer_fails_closed(self):
        p = self.root / "semya-yurist.ru" / "public_html"
        p.unlink()
        p.symlink_to("../" + VERSIONS + "/v000/semya-yurist.ru/public_html")
        with self.assertRaisesRegex(SwitchError,"shared pointer"):
            switch(self.root,self.plan,"v001")
        self.assertEqual(os.readlink(self.root / POINTER), VERSIONS + "/v000")

    def test_pending_transaction_blocks_second_switch_until_recovery(self):
        with self.assertRaises(SimulatedCrash):
            switch(self.root,self.plan,"v001",crash_at="after_pointer")
        with self.assertRaisesRegex(SwitchError,"Unresolved"):
            switch(self.root,self.plan,"v000")
        recover(self.root)
        self.assertEqual(current_name(self.root), "v000")

    def test_recovery_rejects_unexpected_pointer_and_leaves_it_untouched(self):
        with self.assertRaises(SimulatedCrash):
            switch(self.root,self.plan,"v001",crash_at="after_prepare")
        (self.root / VERSIONS / "v999").mkdir()
        temp = self.root / "temp-pointer"
        os.symlink(VERSIONS + "/v999", temp)
        os.replace(temp, self.root / POINTER)
        with self.assertRaises(SwitchError):
            recover(self.root)
        self.assertEqual(os.readlink(self.root / POINTER), VERSIONS + "/v999")

    def test_manifest_path_traversal_is_rejected(self):
        plan = json.loads(self.plan.read_text("utf8"))
        plan["manifest"][0]["path"] = "../outside.html"
        self.plan.write_text(json.dumps(plan), encoding="utf8")
        with self.assertRaisesRegex(SwitchError, "Unsafe"):
            audit(self.root, self.plan, "v001")

    def test_unreviewed_javascript_asset_is_rejected(self):
        plan = json.loads(self.plan.read_text("utf8"))
        entry = next(x for x in plan["manifest"] if x["path"].endswith(".js"))
        entry["path"] = "assets/unsafe-other.js"
        self.plan.write_text(json.dumps(plan), encoding="utf8")
        with self.assertRaisesRegex(SwitchError, "Only the reviewed"):
            audit(self.root, self.plan, "v001")

    def test_journal_and_lock_files_are_private(self):
        import stat
        switch(self.root, self.plan, "v001")
        self.assertEqual(stat.S_IMODE((self.root / ".oleg-pointer-transaction.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / ".oleg-release.lock").stat().st_mode), 0o600)

    def test_unmarked_directory_cannot_be_mutated(self):
        (self.root / MARKER).unlink()
        with self.assertRaisesRegex(SwitchError,"OFFLINE_ONLY"):
            switch(self.root,self.plan,"v001")


if __name__ == "__main__":
    unittest.main(verbosity=2)
