"""Targeted one-shot Qwen cloud selfdev boundary tests, no model download."""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import selfdev_cloud_research as target


class CloudResearchSafetyTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix" or os.geteuid() == 0:
            self.skipTest("non-root posix isolation required")
        self.tmp=tempfile.TemporaryDirectory(prefix="nf-selfdev-lab-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.repo=self.root/"source"
        self.lab=self.root/"proposals"
        self.models=self.root/"models"
        self.bin=self.root/"bin"
        for d in (self.repo,self.lab,self.models,self.bin):
            d.mkdir(mode=0o700)
        self.model=self.models/"Qwen3-0.6B-Q8_0.gguf"
        self.model.write_bytes(b"disposable model fixture")
        self.exe=self.bin/"llama-cli"
        self.exe.write_text("#!/bin/sh\nexit 0\n")
        self.exe.chmod(0o700)
        self.calls=[]
    def runner(self,cmd,**kw):
        self.calls.append((cmd,kw))
        self.assertIsInstance(cmd,list)
        self.assertEqual(cmd[0],str(self.exe))
        self.assertIn("--single-turn",cmd)
        self.assertEqual(kw["cwd"],str(self.lab))
        self.assertNotIn("GITHUB_TOKEN",kw["env"])
        self.assertNotIn("SSH_AUTH_SOCK",kw["env"])
        self.assertEqual(kw["env"]["PATH"],"/usr/bin:/bin")
        prompt=cmd[-1]
        return SimpleNamespace(
            returncode=0,
            stdout="model banner\n> "+prompt+"\nРиск: повторная операция. Тест: перезапуск. PASS: повтор заблокирован.\n[ Prompt: 10 t/s ]",
            stderr="")
    def generate(self,**changes):
        params=dict(repo=self.repo,lab=self.lab,model=self.model,
                    executable=self.exe,task="host_recovery",
                    timestamp=1793633400,runner=self.runner)
        params.update(changes)
        def fake_hash(path):
            if path==self.model:return target.QWEN_MODEL_SHA256
            if path==self.exe:return target.LLAMA_CLI_SHA256
            self.fail("unexpected digest target")
        with patch.object(target,"_digest_file",side_effect=fake_hash), \
             patch.object(target,"_git_head",return_value="c"*40):
            return target.run_one(**params)

    def test_private_proposal_saved_no_apply_no_git_change(self):
        path,proof=self.generate()
        self.assertEqual(len(self.calls),1)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        saved=json.loads(path.read_text())
        self.assertEqual(saved,proof)
        self.assertEqual(saved["status"],"UNTRUSTED_QWEN_RESEARCH_NO_APPLY")
        for flag in ("code_executed_from_model","git_changed",
                     "automatic_pr_created","owner_reviewer_approval",
                     "production_release_allowed","host_task_effect_allowed"):
            self.assertIs(saved[flag],False)
        self.assertEqual(saved["source_sha40"],"c"*40)

    def test_reject_unknown_model_or_binary_hash_before_inference(self):
        with patch.object(target,"_digest_file",return_value="0"*64):
            with self.assertRaises(target.ResearchDenied):
                target.run_one(repo=self.repo,lab=self.lab,model=self.model,
                               executable=self.exe,task="host_recovery",runner=self.runner)
        self.assertEqual(self.calls,[])

    def test_reject_unknown_task_before_inference(self):
        with self.assertRaises(target.ResearchDenied):
            self.generate(task="install_production_service")
        self.assertEqual(self.calls,[])

    def test_reject_model_response_without_prompt_boundary(self):
        def wrong(cmd,**kw):
            return SimpleNamespace(returncode=0,stdout="Fake answer",stderr="")
        with self.assertRaises(target.ResearchDenied):
            self.generate(runner=wrong)
        self.assertEqual(list(self.lab.iterdir()),[])

    def test_llama_console_truncated_echo_parsed_as_only_untrusted_answer(self):
        def shortened(cmd,**kw):
            return SimpleNamespace(returncode=0,
                stdout=chr(10).join((
                    "model banner","> /no_think",
                    "Prompt partly shown ... (truncated)",
                    "Риск: потеря журнала. Тест: удалить базу. PASS: отказ без создания.",
                    "[ Prompt: stats ]"
                )),stderr="")
        path,proof=self.generate(runner=shortened)
        self.assertIn("Тест: удалить базу",proof["proposal"])
        self.assertNotIn("Prompt partly shown",proof["proposal"])

    def test_reject_nonzero_model_exit(self):
        def failed(cmd,**kw):
            return SimpleNamespace(returncode=21,stdout="",stderr="error")
        with self.assertRaises(target.ResearchDenied):
            self.generate(runner=failed)
        self.assertEqual(list(self.lab.iterdir()),[])

    def test_reject_inference_timeout(self):
        def slow(cmd,**kw):
            raise subprocess.TimeoutExpired(cmd,100)
        with self.assertRaises(target.ResearchDenied):
            self.generate(runner=slow)
        self.assertEqual(list(self.lab.iterdir()),[])

    def test_reject_git_checkout_inside_writable_lab(self):
        inside=self.lab/"repo"
        inside.mkdir()
        with self.assertRaises(target.ResearchDenied):
            self.generate(repo=inside)
        self.assertEqual(self.calls,[])

    def test_second_proposal_never_overwrites_first(self):
        first,_=self.generate()
        second,_=self.generate()
        self.assertNotEqual(first,second)
        self.assertEqual(len(list(self.lab.glob("*.json"))),2)


if __name__=="__main__":
    unittest.main()
