"""REVIEW-owned independently authored negative audit of CORE legacy path.

This is an isolated narrow code-path test, NOT external human sign-off.
No live services, issuer key, provider, user files or production authorization.
"""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest
from unittest.mock import patch

CORE_SHA = "9313d508a1f5d9288f18046abf5130b46bedc194"
CORE_PATH = "bridge/neurofactory/development/core_owned/one_task_core.py"
TARGET = "bridge/neurofactory/development/core_owned/narrow_review_demo.txt"

def git(repo, *args):
    return subprocess.check_output(["git","-C",str(repo),*args],
                                   stderr=subprocess.PIPE, text=True,timeout=10).strip()

def load(path):
    spec=importlib.util.spec_from_file_location("independent_review_pinned_core",path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

class NarrowCoreDenyReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name!="posix" or os.environ.get("NF_REVIEW_READ_ONLY_FIXTURE")!="1":
            raise RuntimeError("review allowed in isolated Linux only")
        root=Path(__file__).resolve().parents[4]
        checkout=root/"_review_fixture"/"core"
        if git(checkout,"rev-parse","HEAD")!=CORE_SHA:
            raise RuntimeError("unaudited CORE source SHA")
        cls.mod=load(checkout/CORE_PATH)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="review-nf-sandbox-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.repo=self.root/"fixture-git"
        self.repo.mkdir(mode=0o700)
        git(self.repo,"init","-q")
        git(self.repo,"config","user.name","review-fixture")
        git(self.repo,"config","user.email","review@example.invalid")
        (self.repo/"README.md").write_text("Review offline only\n",encoding="utf8")
        git(self.repo,"add","README.md")
        git(self.repo,"commit","-qm","review source")
        source=git(self.repo,"rev-parse","HEAD")
        self.workspace=self.root/"workspace"
        self.workspace.mkdir(mode=0o700)
        self.core=self.mod.OneTaskCore(self.workspace,self.repo)
        self.spec=dict(schema="neurofactory.core.task.v1",
             task_id="NF-DEV-05-Q984",project_id="review-test",
             target=TARGET,objective="Write harmless offline review file only.",
             source_sha=source,source_sha256=self.mod.EMPTY_SHA,
             approval_commit=source,model="qwen2.5-coder:1.5b",reserved_units=1)
        self.core.enqueue(self.spec,trusted_approval_check=lambda x: x==self.spec)
        self.local=self.core.claim("review-worker",now=1000,lease_seconds=120)
        content="REVIEW_ONLY = True\n"
        self.proposal=dict(schema="neurofactory.core.proposal.v1",
             target=TARGET,content=content,
             content_sha256=hashlib.sha256(content.encode()).hexdigest(),
             mode="OFFLINE_TEST")

    def no_file(self):
        self.assertFalse((self.core.sandbox/TARGET).exists())
        self.assertEqual(self.core.snapshot()["state"],"CLAIMED")

    def test_old_public_writer_denies_with_positive_local_callback(self):
        with self.assertRaisesRegex(self.mod.CoreSafetyError,"LEGACY_WRITE_DISABLED"):
            self.core.apply_offline_test(self.spec["task_id"],self.local["token"],
                                         self.proposal,now=1001)
        self.no_file()

    def test_old_public_writer_denies_even_with_fixture_switch(self):
        with patch.dict(os.environ,{"NF_CORE_OFFLINE_FIXTURE":"1"}):
            with self.assertRaisesRegex(self.mod.CoreSafetyError,"LEGACY_WRITE_DISABLED"):
                self.core.apply_offline_test(self.spec["task_id"],self.local["token"],
                                             self.proposal,now=1001)
        self.no_file()

    def test_old_public_writer_denies_after_fake_foreign_token(self):
        with self.assertRaisesRegex(self.mod.CoreSafetyError,"LEGACY_WRITE_DISABLED"):
            self.core.apply_offline_test(self.spec["task_id"],secrets.token_hex(32),
                                         self.proposal,now=1001)
        self.no_file()

    def test_fixture_function_denies_without_explicit_switch(self):
        with patch.dict(os.environ,{"NF_CORE_OFFLINE_FIXTURE":""}):
            with self.assertRaises(self.mod.CoreSafetyError):
                self.core.apply_fixture_offline_test(
                    self.spec["task_id"],self.local["token"],
                    self.proposal,now=1001)
        self.no_file()

    def test_fixture_function_denies_outside_disposable_temp_even_with_switch(self):
        # Use per-runner disposable HOME, never user's machine. Unit creates
        # local SQLite but asserts no effect file in the external workspace.
        with tempfile.TemporaryDirectory(
                prefix="review-nf-outside-tmp-",dir=Path.home()) as outside:
            dst=Path(outside)/"workspace"
            dst.mkdir(mode=0o700)
            forged=self.mod.OneTaskCore(dst,self.repo)
            forged.enqueue(self.spec,trusted_approval_check=lambda x:x==self.spec)
            lease=forged.claim("review-worker",now=1000)
            with patch.dict(os.environ,{"NF_CORE_OFFLINE_FIXTURE":"1"}):
                with self.assertRaises(self.mod.CoreSafetyError):
                    forged.apply_fixture_offline_test(
                        self.spec["task_id"],lease["token"],
                        self.proposal,now=1001)
            self.assertFalse((forged.sandbox/TARGET).exists())

    def test_test_bridge_denies_when_fixture_feature_not_explicitly_enabled(self):
        file=Path(__file__).resolve().parents[4]/"_review_fixture"/"core"/(
              "bridge/neurofactory/development/core_owned/fenced_offline_core.py")
        spec=importlib.util.spec_from_file_location("independent_review_bridge",file)
        bridge=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bridge)
        with patch.dict(os.environ,{"NF_CORE_FENCED_TEST_ONLY":""}):
            with self.assertRaises(bridge.FencedOfflineBoundaryError):
                bridge.FencedOfflineTestBridge(self.core,object())
        self.no_file()

if __name__=="__main__":
    unittest.main()
