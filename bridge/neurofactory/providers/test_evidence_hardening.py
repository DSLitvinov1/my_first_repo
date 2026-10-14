"""New adversarial tests ONLY for hardened evidence file/commit-seal semantics.

Every 'model reply' is a local fixture.  No Qwen or Ollama call is made.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import evidence_receipt as e


class EvidenceHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="provider-evidence-security-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dir = self.root / "private"
        self.dir.mkdir(mode=0o700)
        self.task = "NF-DEV-05-Q931"
        self.params = dict(
            task_id=self.task,
            project_id="sandbox-one",
            input_sha256="a"*64,
            prompt_sha256="b"*64,
            model="qwen2.5-coder:1.5b",
            response_text="def add(a,b):\n    return a+b\n",
            elapsed_ms=123,
        )

    def write(self):
        return e.persist_model_evidence(self.dir, **self.params)

    def files(self):
        name = e.evidence_name(self.task)
        return self.dir / name, self.dir / (name+".seal")

    def test_commit_seal_is_required(self):
        original = self.write()
        record, seal = self.files()
        self.assertTrue(seal.is_file())
        self.assertEqual(seal.read_bytes(), (original["evidence_sha256"]+"\n").encode())
        seal.unlink()
        with self.assertRaises(e.EvidenceError):
            e.verify_model_evidence(self.dir, self.task)
        with self.assertRaises(e.EvidenceError):
            self.write()  # never replace old record after missing seal

    def test_crash_between_record_write_and_seal_is_uncommitted(self):
        base_fsync = e.os.fsync
        calls = [0]
        def fail_second(fd):
            calls[0] += 1
            if calls[0] == 2:
                raise OSError("simulated fsync failure before commit seal")
            return base_fsync(fd)
        with patch.object(e.os, "fsync", side_effect=fail_second):
            with self.assertRaises(e.EvidenceError):
                self.write()
        record, seal = self.files()
        self.assertTrue(record.exists())
        self.assertFalse(seal.exists())
        with self.assertRaises(e.EvidenceError):
            e.verify_model_evidence(self.dir, self.task)
        with self.assertRaises(e.EvidenceError):
            self.write()

    def test_external_anchor_detects_rewritten_receipt_plus_seal(self):
        original = self.write()
        record, seal = self.files()
        data = json.loads(record.read_text(encoding="utf-8"))
        data["response_text"] = "FORGED RESPONSE"
        data["response_sha256"] = sha256(data["response_text"].encode()).hexdigest()
        forged = (json.dumps(data, ensure_ascii=False, allow_nan=False,
                             sort_keys=True, separators=(",",":"))+"\n").encode()
        record.write_bytes(forged)
        seal.write_bytes((sha256(forged).hexdigest()+"\n").encode())
        # Local self-consistency is not proof against the machine owner.
        unanchored = e.verify_model_evidence(self.dir, self.task)
        self.assertEqual(unanchored["response_sha256"], data["response_sha256"])
        with self.assertRaises(e.EvidenceError):
            e.verify_model_evidence(self.dir, self.task,
                                    expected_evidence_sha256=original["evidence_sha256"])

    def test_valid_external_anchor_matches_exact_bytes(self):
        digest = self.write()["evidence_sha256"]
        checked = e.verify_model_evidence(self.dir, self.task,
                                          expected_evidence_sha256=digest)
        self.assertEqual(checked["evidence_sha256"], digest)

    def test_fake_external_anchor_not_a_sha_is_rejected(self):
        self.write()
        for bad in ("not-a-sha", "A"*64, True, ""):
            with self.subTest(bad=bad):
                with self.assertRaises(e.EvidenceError):
                    e.verify_model_evidence(self.dir, self.task,
                                            expected_evidence_sha256=bad)

    def test_symlink_record_does_not_follow_outside_directory(self):
        original = self.write()
        rec, seal = self.files()
        elsewhere = self.root / "outside.txt"
        elsewhere.write_bytes(rec.read_bytes())
        rec.unlink()
        try:
            rec.symlink_to(elsewhere)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unsupported by CI permissions")
        with self.assertRaises(e.EvidenceError):
            e.verify_model_evidence(self.dir, self.task,
                                    expected_evidence_sha256=original["evidence_sha256"])

    def test_symlink_commit_seal_rejected(self):
        self.write()
        rec, seal = self.files()
        elsewhere = self.root / "external-seal"
        elsewhere.write_bytes(seal.read_bytes())
        seal.unlink()
        try:
            seal.symlink_to(elsewhere)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unsupported by CI permissions")
        with self.assertRaises(e.EvidenceError):
            e.verify_model_evidence(self.dir, self.task)

    @unittest.skipUnless(os.name=="posix", "POSIX pinned directory inode security")
    def test_directory_swap_to_external_symlink_rejected_after_open(self):
        outside = self.root / "outside"
        outside.mkdir()
        moved = self.root / "moved-private"
        real_open = e.os.open
        swapped = [False]
        def swap_on_file_open(path, flags, *args, **kwargs):
            if (not swapped[0] and kwargs.get("dir_fd") is not None and
                    flags & os.O_CREAT):
                swapped[0] = True
                self.dir.rename(moved)
                self.dir.symlink_to(outside, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(e.os, "open", side_effect=swap_on_file_open):
            with self.assertRaises(e.EvidenceError):
                self.write()
        self.assertTrue(swapped[0])
        self.assertFalse(any(outside.iterdir()), "outside dir was never written")
        self.assertTrue(any(moved.iterdir()), "record stays in pinned old inode")

    @unittest.skipUnless(os.name=="posix", "POSIX file/parent private modes")
    def test_exclusive_record_and_seal_are_mode_0600(self):
        self.write()
        record, seal = self.files()
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(seal.stat().st_mode), 0o600)


if __name__=="__main__":
    unittest.main()
