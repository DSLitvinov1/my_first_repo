"""Independent REVIEW process-level proof of unsafe old HANDOFF filesystem behavior.

This suite intentionally proves the old rejected code has weaknesses; PASS is
evidence of a reproducible regression, NEVER release authorization.
Only synthetic files inside isolated TemporaryDirectory paths are touched.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from model_handoff_owned import handoff_gate as gate

TASK = "NF-DEV-05-Q098"


def launch(source, *arguments):
    env = os.environ.copy()
    return subprocess.Popen([sys.executable, "-B", "-c", source,
                             *map(str, arguments)],
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


class IndependentProcessLevelRegression(unittest.TestCase):
    def test_real_other_process_can_swap_task_directory_after_check(self):
        if os.name == "nt":
            self.skipTest("POSIX symlink exploitation proof; Windows requires own privileged runner test")
        script = r'''
import json, pathlib, sys, time
from model_handoff_owned import handoff_gate as gate
root, marker, release = map(pathlib.Path, sys.argv[1:])
native = pathlib.Path.open
def at_open(path, mode="r", *args, **kwargs):
    if pathlib.Path(path).name == "candidate.json" and mode == "xb":
        marker.write_text("checked",encoding="utf-8")
        for _ in range(700):
            if release.exists(): break
            time.sleep(.01)
        else:
            raise RuntimeError("Other process failed to perform swap")
    return native(path,mode,*args,**kwargs)
pathlib.Path.open = at_open
result=gate.store_once(root,"NF-DEV-05-Q098","candidate.json",{"value":"outside"})
print(json.dumps(result),flush=True)
'''
        with tempfile.TemporaryDirectory(prefix="nf-review-real-process-swap-") as tmp:
            location = Path(tmp)
            root=location/"root"; root.mkdir()
            foreign=location/"foreign"; foreign.mkdir()
            marker=location/"marked"
            release=location/"swapped"
            child=launch(script,root,marker,release)
            try:
                for _ in range(500):
                    if marker.exists() or child.poll() is not None: break
                    time.sleep(.01)
                self.assertTrue(marker.exists(),"Writer did not reach post-check open")
                taskdir=root/TASK
                self.assertTrue(taskdir.is_dir())
                taskdir.rename(root/"before_swap")
                taskdir.symlink_to(foreign,target_is_directory=True)
                release.write_text("continue",encoding="utf-8")
                output,error=child.communicate(timeout=15)
                self.assertEqual(child.returncode,0,error)
                self.assertTrue(json.loads(output)["created"])
                self.assertEqual(json.loads((foreign/"candidate.json").read_text()),
                                 {"value":"outside"})
                self.assertFalse((root/"before_swap"/"candidate.json").exists())
            finally:
                release.touch(exist_ok=True)
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)

    def test_partial_hard_crash_refuses_replay_instead_of_overwriting(self):
        script = r'''
import os,pathlib,sys
from model_handoff_owned import handoff_gate as gate
root=pathlib.Path(sys.argv[1])
original=pathlib.Path.open
class CrashOnWrite:
    def __init__(self,stream): self.stream=stream
    def __enter__(self): return self
    def __exit__(self,*args): return self.stream.__exit__(*args)
    def write(self,payload):
        self.stream.write(payload[:max(1,len(payload)//3)])
        self.stream.flush()
        os._exit(79)
    def __getattr__(self,name): return getattr(self.stream,name)
def injected(path,mode="r",*args,**kwargs):
    opened=original(path,mode,*args,**kwargs)
    if mode=="xb" and pathlib.Path(path).name=="candidate.json":
        return CrashOnWrite(opened)
    return opened
pathlib.Path.open=injected
gate.store_once(root,"NF-DEV-05-Q098","candidate.json",{"safe":True,"long":"alpha-beta-gamma-delta"})
'''
        with tempfile.TemporaryDirectory(prefix="nf-review-partial-crash-") as tmp:
            root=Path(tmp)
            child=launch(script,root)
            try:
                out,err=child.communicate(timeout=15)
                self.assertEqual(child.returncode,79,err or out)
                expected=gate.encoded({"safe":True,"long":"alpha-beta-gamma-delta"})+b"\n"
                record=root/TASK/"candidate.json"
                self.assertTrue(record.is_file())
                raw=record.read_bytes()
                self.assertLess(len(raw),len(expected))
                self.assertGreater(len(raw),0)
                with self.assertRaises(gate.HandoffError):
                    gate.store_once(root,TASK,"candidate.json",
                                    {"safe":True,"long":"alpha-beta-gamma-delta"})
                self.assertEqual(record.read_bytes(),raw,"Partial proof was overwritten")
            finally:
                if child.poll() is None:
                    child.kill();child.communicate(timeout=5)

    def test_three_piece_dossier_is_never_mistaken_for_complete_on_mid_write_fault(self):
        source = ("def transform(value):\n"
                  "    return str(value).strip()\n")
        target="bridge/neurofactory/development/model_handoff_owned/review_only.py"
        packet=gate.candidate_packet(TASK,target,source)
        reply=json.dumps({"verdict":"APPROVE",
                          "candidate_sha256":packet["candidate_sha256"],
                          "findings":[]})
        review=gate.review_packet(packet,reply)
        saved=gate.store_once
        calls=[]
        def interruption(root,task,filename,document):
            calls.append(filename)
            if filename=="review.json":
                raise RuntimeError("simulated abrupt interruption")
            return saved(root,task,filename,document)
        with tempfile.TemporaryDirectory(prefix="nf-review-checkpoint-split-") as tmp:
            with mock.patch.object(gate,"store_once",side_effect=interruption):
                with self.assertRaisesRegex(RuntimeError,"interruption"):
                    gate.persist_handoff(tmp,packet,review)
            folder=Path(tmp)/TASK
            self.assertEqual(calls,["candidate.json","review.json"])
            self.assertTrue((folder/"candidate.json").exists())
            self.assertFalse((folder/"review.json").exists())
            self.assertFalse((folder/"handoff.json").exists())
            # No committed handoff marker exists: a safe importer MUST reject
            # the incomplete set instead of treating candidate as approval.
            result=gate.persist_handoff(tmp,packet,review)
            self.assertFalse(result["candidate.json"]["created"])
            self.assertTrue(result["review.json"]["created"])
            self.assertTrue(result["handoff.json"]["created"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
