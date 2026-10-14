"""Independent REVIEW tests for HANDOFF remediation commit f91803c.

These tests must not be run against the old rejected module. All writes target
TemporaryDirectory only. No models, Windows executors or GitHub publishers.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from model_handoff_owned import handoff_gate as gate

TASK = "NF-DEV-05-Q098"
TARGET = "bridge/neurofactory/development/model_handoff_owned/review_only.py"
SOURCE = "def normalize_label(value):\n    return str(value).strip().lower()\n"
FIXED_COMMIT = "a08af89b8105aa58be403385c043ccd5d666772d"

def make_packet():
    p = gate.candidate_packet(TASK,TARGET,SOURCE)
    reply = json.dumps({"verdict":"APPROVE","candidate_sha256":p["candidate_sha256"],"findings":[]})
    return p,gate.review_packet(p,reply)

class RemediationIndependentTests(unittest.TestCase):
    def test_exploit_interleaving_cannot_escape_open_directory_fd(self):
        if os.name != "posix":
            self.skipTest("Linux descriptor race: Windows must be tested separately")
        script=r'''
import json,os,pathlib,sys,time
from model_handoff_owned import handoff_gate as gate
root,marker,release=map(pathlib.Path,sys.argv[1:])
native=os.open
supported=gate._secure_storage_available()
assert supported,"POSIX directory-handle prerequisites absent"
def blocked_open(path, flags, *args, **kw):
    if path=="candidate.json" and flags & os.O_CREAT:
        marker.write_text("about-to-create")
        for _ in range(700):
            if release.exists(): break
            time.sleep(.01)
        else:
            raise RuntimeError("Interleaving did not complete")
    return native(path,flags,*args,**kw)
os.open=blocked_open
# Preserve the real platform capability decision while instrumenting os.open.
gate._secure_storage_available=lambda: supported
try:
    v=gate.store_once(root,"NF-DEV-05-Q098","candidate.json",{"value":"must-not-escape"})
    print("CREATED:"+str(v["created"]),flush=True)
except gate.HandoffError as exc:
    print("DENIED:"+str(exc),flush=True)
'''
        with tempfile.TemporaryDirectory(prefix="nf-review-fixed-dirfd-") as temp:
            where=Path(temp)
            root=where/"private";root.mkdir(mode=0o700)
            foreign=where/"foreign";foreign.mkdir()
            marker=where/"about-to-open"
            release=where/"do-open"
            env=os.environ.copy()
            child=subprocess.Popen([sys.executable,"-B","-c",script,str(root),str(marker),str(release)],
                                   env=env,stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,text=True)
            try:
                for _ in range(500):
                    if marker.exists() or child.poll() is not None: break
                    time.sleep(.01)
                self.assertTrue(marker.exists(),"Writer never reached controlled creation")
                taskdir=root/TASK
                taskdir.rename(root/"old_taskdir")
                taskdir.symlink_to(foreign,target_is_directory=True)
                release.write_text("swapped")
                stdout,stderr=child.communicate(timeout=15)
                self.assertEqual(child.returncode,0,stderr or stdout)
                self.assertTrue(stdout.startswith("DENIED:"),stdout)
                self.assertFalse((foreign/"candidate.json").exists(),
                                 "Fixed source still wrote evidence outside private root")
                self.assertFalse((root/"old_taskdir"/"candidate.json").exists(),
                                 "Failed post-write anchor check did not clean up partial result")
            finally:
                release.touch(exist_ok=True)
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)

    def test_incomplete_three_file_checkpoint_denied_before_finalize(self):
        if os.name != "posix":
            self.skipTest("Linux descriptor evidence check; Windows must explicitly fail closed")
        candidate,review=make_packet()
        with tempfile.TemporaryDirectory(prefix="nf-review-partial-fixed-") as tmp:
            root=Path(tmp)
            gate.store_once(root,TASK,"candidate.json",candidate)
            with self.assertRaises(gate.HandoffError):
                gate.verify_complete_handoff(root,candidate,review)
            gate.store_once(root,TASK,"review.json",review)
            with self.assertRaises(gate.HandoffError):
                gate.verify_complete_handoff(root,candidate,review)
            gate.store_once(root,TASK,"handoff.json",gate.handoff_dossier(candidate,review))
            self.assertTrue(gate.verify_complete_handoff(root,candidate,review))
            again=gate.persist_handoff(root,candidate,review)
            self.assertTrue(all(x["created"] is False for x in again.values()))

    def test_forged_claim_refused_by_external_verifier_on_negative(self):
        candidate,review=make_packet()
        fake={"run_id":9999,"head_sha":"1"*40,"artifact_id":8888,
              "artifact_sha256":"2"*64,
              "candidate_sha256":candidate["candidate_sha256"],
              "reviewer_model":"qwen3:4b","raw_reply_sha256":"3"*64}
        with self.assertRaises(gate.HandoffError):
            gate.verify_trusted_runner_origin(candidate,review,fake,
                                              verify_github=lambda *args: False)
        with self.assertRaises(gate.HandoffError):
            gate.verify_trusted_runner_origin(candidate,review,fake,verify_github=None)

    def test_fake_positive_callback_is_a_trust_boundary_not_authentication(self):
        # An arbitrary caller-supplied callback returning True makes this
        # helper report attestation without any GitHub request. Integration
        # MUST bind the verifier to the trusted separate owner, not model IO.
        candidate,review=make_packet()
        fake={"run_id":9999,"head_sha":"1"*40,"artifact_id":8888,
              "artifact_sha256":"2"*64,
              "candidate_sha256":candidate["candidate_sha256"],
              "reviewer_model":"qwen3:4b","raw_reply_sha256":"3"*64}
        outcome=gate.verify_trusted_runner_origin(
            candidate,review,fake,verify_github=lambda *args: True)
        self.assertTrue(outcome["receipt_correlated_by_callback"])
        self.assertFalse(outcome["origin_attested_by_external_verifier"])
        self.assertFalse(outcome["release_authorized"])
        self.assertTrue(outcome["needs_independent_review_owner"])

    def test_unsafe_windows_storage_is_denied_without_native_handles(self):
        candidate,review=make_packet()
        with tempfile.TemporaryDirectory(prefix="nf-review-platform-fail-") as tmp:
            if gate._secure_storage_available():
                self.skipTest("Native POSIX secure handles available, tested separately")
            with self.assertRaises(gate.HandoffError):
                gate.persist_handoff(tmp,candidate,review)

if __name__=="__main__":
    unittest.main(verbosity=2)
