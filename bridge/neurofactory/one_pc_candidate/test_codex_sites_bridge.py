"""Targeted Codex/Sites adapter tests; zero real external calls or login."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from codex_sites_bridge import prepare, codex_readonly, HandoffDenied

BASE = {
    "mode":"codex",
    "project_id":"a"*32,
    "project_name":"Neurofactory approved sandbox",
    "objective":"Please examine the isolated application source and propose two fixes.",
}

class CodexSitesOptInTests(unittest.TestCase):
    def test_codex_user_review_only_handoff_is_stable(self):
        result=prepare(BASE)
        self.assertEqual(result["mode"],"codex")
        self.assertEqual(result["status"],"REVIEW_ONLY_USER_HANDOFF")
        self.assertTrue(result["open_url"].startswith("https://chatgpt.com/"))
        self.assertFalse(result["automatic_codex_execution"])
        self.assertFalse(result["host_write_allowed"])
        self.assertFalse(result["local_core_queue_allowed"])
        self.assertEqual(result["prompt_sha256"],sha256(result["prompt"].encode()).hexdigest())
        self.assertIn(BASE["objective"],result["prompt"])

    def test_sites_external_manual_only_and_no_fake_api(self):
        data={**BASE,"mode":"sites"}
        with patch("subprocess.run",side_effect=AssertionError("network or subprocess forbidden")):
            result=prepare(data)
        self.assertEqual(result["mode"],"sites")
        self.assertIn("@Sites",result["prompt"])
        self.assertFalse(result["automatic_sites_publish"])
        self.assertFalse(result["uses_openai_api_key"])
        self.assertIn("Не публикуй",result["prompt"])
        self.assertTrue(result["requires_explicit_user_action"])

    def test_bad_request_too_short_control_and_foreign_project_denied(self):
        candidates=[
            {**BASE,"project_id":"b"*31},
            {**BASE,"mode":"privileged"},
            {**BASE,"objective":"run"},
            {**BASE,"objective":"a"*1201},
            {**BASE,"objective":"Command\ninjected: run now."},
            {**BASE,"project_name":"unsafe\nheader"},
            {**BASE,"project_name":" "},
            {**BASE,"extra":"silent escalation"},
        ]
        for case in candidates:
            with self.subTest(case=case),self.assertRaises(HandoffDenied):
                prepare(case)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-codex-disabled-test-")
        self.root=Path(self.tmp.name).resolve()
        self.git=self.root/"repo"
        self.git.mkdir()
        (self.git/".git").mkdir()
        self.exe=self.root/("codex.exe" if os.name=="nt" else "codex")
        self.exe.write_bytes(b"native codex fixture: NEVER executed by this test")

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_permission_never_starts_cli(self):
        with patch("subprocess.run",side_effect=AssertionError("must not execute")):
            with self.assertRaises(HandoffDenied):
                codex_readonly(BASE,repo=self.git,executable=self.exe)

    def test_manual_codex_cli_is_readonly_ephemeral_and_no_inherited_api_keys(self):
        fake=Mock(returncode=0,stdout="Review-only analysis\n",stderr="")
        def guarded(args, **kwargs):
            self.assertEqual(args[:4],[str(self.exe),"exec","--sandbox","read-only"])
            self.assertIn("--ephemeral",args)
            self.assertIn("--ignore-user-config",args)
            self.assertNotIn("--yolo",args)
            self.assertNotIn("--sandbox workspace-write",args)
            self.assertEqual(kwargs["cwd"],self.git)
            self.assertEqual(kwargs["env"].get("OPENAI_API_KEY"),None)
            self.assertEqual(kwargs["env"].get("CODEX_API_KEY"),None)
            self.assertEqual(kwargs["timeout"],180)
            return fake
        with patch.dict(os.environ,{"OPENAI_API_KEY":"FICTIONAL_NO_REAL_SECRET","CODEX_API_KEY":"FICTIONAL"}):
            with patch("subprocess.run",side_effect=guarded) as run:
                result=codex_readonly(BASE,repo=self.git,executable=self.exe,operator_confirmed=True)
        self.assertEqual(run.call_count,1)
        self.assertTrue(result["model_output_untrusted"])
        self.assertFalse(result["source_applied"])
        self.assertFalse(result["core_queue_allowed"])
        self.assertEqual(result["proposal_text"],"Review-only analysis\n")

    def test_non_native_wrapper_and_untrusted_workspace_denied(self):
        bad=self.root/"codex.cmd"
        bad.write_text("@echo off\n")
        with patch("subprocess.run",side_effect=AssertionError("invalid exe should not run")):
            with self.assertRaises(HandoffDenied):
                codex_readonly(BASE,repo=self.git,executable=bad,operator_confirmed=True)
            with self.assertRaises(HandoffDenied):
                codex_readonly(BASE,repo=self.root,executable=self.exe,operator_confirmed=True)

    def test_model_error_no_automatic_retry(self):
        with patch("subprocess.run",return_value=Mock(returncode=1,stdout="",stderr="secret data")) as run:
            with self.assertRaises(HandoffDenied):
                codex_readonly(BASE,repo=self.git,executable=self.exe,operator_confirmed=True)
            self.assertEqual(run.call_count,1)

    def test_oversized_untrusted_output_denied(self):
        with patch("subprocess.run",return_value=Mock(returncode=0,stdout="x"*25000,stderr="")) as run:
            with self.assertRaises(HandoffDenied):
                codex_readonly(BASE,repo=self.git,executable=self.exe,operator_confirmed=True)
            self.assertEqual(run.call_count,1)

if __name__=="__main__":
    unittest.main()
