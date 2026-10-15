"""Targeted offline tests ONLY: synthetic Git fixture, NO Qwen, no remote writes."""
import copy
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from one_task_core import CoreSafetyError, OneTaskCore, EMPTY_SHA, _canonical

TARGET = "bridge/neurofactory/development/core_owned/lesson_once.py"


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE).decode().strip()


class CoreOnceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.repo = self.base / "repository"
        self.repo.mkdir(mode=0o700)
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "offline-test")
        git(self.repo, "config", "user.email", "offline@example.invalid")
        (self.repo / "README.md").write_text("isolated fixture\n", "utf8")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-qm", "synthetic source")
        sha = git(self.repo, "rev-parse", "HEAD")
        self.workspace = self.base / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.q = OneTaskCore(self.workspace, self.repo)
        self.spec = {
            "schema": "neurofactory.core.task.v1",
            "task_id": "NF-DEV-05-Q901", "project_id": "core-test",
            "target": TARGET, "objective": "Create one synthetic offline Python fixture safely.",
            "source_sha": sha, "source_sha256": EMPTY_SHA,
            "approval_commit": sha, "model": "qwen2.5-coder:1.5b",
            "reserved_units": 10
        }
        self.approver = lambda p: p == self.spec  # TEST STUB, not real approval

    def secure_parents(self, target):
        current = self.q.sandbox
        for component in pathlib.PurePosixPath(TARGET).parts[:-1]:
            current = current / component
            current.mkdir(mode=0o700, exist_ok=True)
            current.chmod(0o700)

    def admit(self):
        return self.q.enqueue(copy.deepcopy(self.spec), trusted_approval_check=self.approver)

    def proposal(self, content="VALUE = 123\n"):
        return {
            "schema": "neurofactory.core.proposal.v1", "target": TARGET,
            "content": content, "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "mode": "OFFLINE_TEST"
        }

    def test_one_file_real_offline_write_and_checkpoint(self):
        self.assertEqual(self.admit()["state"], "QUEUED")
        claim = self.q.claim("worker-one", now=1000, lease_seconds=200)
        receipt = self.q.apply_offline_test(self.spec["task_id"], claim["token"],
                                            self.proposal(), now=1010)
        path = self.q.sandbox / TARGET
        self.assertEqual(path.read_text("utf8"), "VALUE = 123\n")
        self.assertEqual(receipt["result_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertIs(receipt["model_invoked"], False)
        self.assertIs(receipt["published"], False)
        self.assertEqual(self.q.snapshot()["state"], "CHECKPOINTED_TEST")
        evidence_dir = os.environ.get("NF_CORE_EVIDENCE_DIR")
        if evidence_dir:
            pathlib.Path(evidence_dir).mkdir(parents=True, exist_ok=True)
            summary = {"schema": 1, "evidence_type": "synthetic_offline_test",
                       "model_executed": False, "github_published": False,
                       "checkout_source_sha": self.spec["source_sha"],
                       "checkpoint_state": self.q.snapshot()["state"],
                       "receipt": receipt,
                       "sandbox_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            (pathlib.Path(evidence_dir) / "offline-test-checkpoint.json").write_text(
                json.dumps(summary, sort_keys=True, indent=2) + "\n", "utf8")
        self.assertEqual(self.q.recover(now=2000)["state"], "CHECKPOINTED_TEST")
        self.assertEqual(OneTaskCore(self.workspace, self.repo).snapshot()["receipt"], receipt)
        with self.assertRaises(CoreSafetyError):
            self.q.claim("worker-again", now=1011)

    def test_two_separate_processes_only_one_claim(self):
        self.admit()
        program = """import sys
sys.path.insert(0, sys.argv[1])
from one_task_core import OneTaskCore,CoreSafetyError
try:
    OneTaskCore(sys.argv[2],sys.argv[3]).claim(sys.argv[4],now=1000)
    print('CLAIMED')
except CoreSafetyError:
    print('BLOCKED')
"""
        module = str(pathlib.Path(__file__).resolve().parent)
        runs = [subprocess.Popen([sys.executable, "-c", program, module,
                                  str(self.workspace), str(self.repo), "process-" + str(i)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for i in range(3)]
        outputs = [p.communicate(timeout=15) for p in runs]
        self.assertEqual(sum("CLAIMED" in stdout for stdout, _ in outputs), 1, outputs)
        self.assertTrue(all(not err for _, err in outputs), outputs)
        self.assertEqual(self.q.snapshot()["attempts"], 1)

    @unittest.skipUnless(os.name == "posix", "POSIX synthetic side-effect only")
    def test_exact_expiry_disallows_side_effect(self):
        """At t == lease_until, recovery already treats the claim as expired."""
        self.admit()
        held = self.q.claim("expiry-worker", now=100, lease_seconds=10)
        with self.assertRaises(CoreSafetyError):
            self.q.apply_offline_test(self.spec["task_id"], held["token"],
                                      self.proposal(), now=110)
        self.assertFalse((self.q.sandbox / TARGET).exists())
        self.assertEqual(self.q.snapshot()["state"], "CLAIMED")
        self.assertEqual(self.q.recover(now=110)["state"], "NEEDS_MANUAL_REVIEW")
        with self.assertRaises(CoreSafetyError):
            self.q.claim("another-worker", now=111)

    def test_crash_after_claim_expires_to_manual_no_retry(self):
        self.admit()
        self.q.claim("worker", now=100, lease_seconds=10)
        self.assertEqual(self.q.recover(now=111)["state"], "NEEDS_MANUAL_REVIEW")
        with self.assertRaises(CoreSafetyError):
            self.q.claim("worker-restart", now=120)

    def test_crash_after_intent_cannot_replay(self):
        self.admit()
        claim = self.q.claim("worker", now=100, lease_seconds=10)
        with sqlite3.connect(self.q.db) as con:
            con.execute("UPDATE single_job SET state='APPLYING' WHERE singleton=1")
        self.assertEqual(self.q.recover(now=115)["state"], "NEEDS_MANUAL_REVIEW")
        with self.assertRaises(CoreSafetyError):
            self.q.apply_offline_test(self.spec["task_id"], claim["token"], self.proposal(), now=115)
        self.assertFalse((self.q.sandbox / TARGET).exists())

    @unittest.skipIf(os.name == "nt", "Windows file writer intentionally blocked until trusted ACL host")
    def test_killed_after_atomic_file_replace_never_replays(self):
        """Real child death between visible file and SQLite receipt, no fake receipt."""
        self.admit()
        claim = self.q.claim("worker", now=100, lease_seconds=10)
        worker_code = """
import json
import os
import pathlib
import sys
sys.path.insert(0, sys.argv[1])
from one_task_core import OneTaskCore
workspace = pathlib.Path(sys.argv[2])
repo = pathlib.Path(sys.argv[3])
token = sys.argv[4]
task = sys.argv[5]
proposal = json.loads(sys.argv[6])
core = OneTaskCore(workspace, repo)
wanted = core.sandbox / proposal["target"]
original_replace = os.replace

def die_after_effect(src, dst, **kwargs):
    original_replace(src, dst, **kwargs)
    if kwargs.get("dst_dir_fd") is not None:
        os._exit(87)
os.replace = die_after_effect
core.apply_offline_test(task, token, proposal, now=101)
raise AssertionError("injection did not intercept target replace")
"""
        process = subprocess.run(
            [sys.executable, "-B", "-c", worker_code,
             str(pathlib.Path(__file__).resolve().parent),
             str(self.workspace), str(self.repo), claim["token"],
             self.spec["task_id"], json.dumps(self.proposal())],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 87, process.stderr)
        target = self.q.sandbox / TARGET
        self.assertEqual(target.read_text("utf8"), self.proposal()["content"])
        self.assertEqual(self.q.snapshot()["state"], "APPLYING")
        self.assertEqual(self.q.recover(now=111)["state"], "NEEDS_MANUAL_REVIEW")
        self.assertIsNone(self.q.snapshot()["receipt"])
        with self.assertRaises(CoreSafetyError):
            self.q.claim("another-worker", now=120)
        with self.assertRaises(CoreSafetyError):
            self.q.apply_offline_test(self.spec["task_id"], claim["token"],
                                      self.proposal("VALUE = 999\\n"), now=120)
        self.assertEqual(target.read_text("utf8"), self.proposal()["content"])

    @unittest.skipUnless(os.name == "nt", "Windows-only fail-closed host gate")
    def test_windows_writer_explicitly_disabled(self):
        self.admit()
        claim = self.q.claim("windows-host", now=100, lease_seconds=10)
        with self.assertRaises(CoreSafetyError):
            self.q.apply_offline_test(self.spec["task_id"], claim["token"],
                                      self.proposal(), now=101)
        self.assertEqual(self.q.snapshot()["state"], "CLAIMED")
        self.assertFalse((self.q.sandbox / TARGET).exists())

    @unittest.skipUnless(os.name == "posix", "Descriptor-relative POSIX only")
    def test_parent_swap_at_atomic_replace_never_writes_attacker_directory(self):
        from unittest.mock import patch
        self.admit()
        claim = self.q.claim("host", now=100, lease_seconds=10)
        target = self.q.sandbox / TARGET
        parent = target.parent
        displaced = self.base / "displaced_original_parent"
        attacker = self.base / "attacker_outside"
        attacker.mkdir(mode=0o700)
        original_replace = os.replace
        swapped = []

        def swap_before_replace(src, dst, **kwargs):
            if kwargs.get("dst_dir_fd") is not None and not swapped:
                parent.rename(displaced)
                parent.symlink_to(attacker, target_is_directory=True)
                swapped.append(True)
            return original_replace(src, dst, **kwargs)

        with patch.object(os, "replace", side_effect=swap_before_replace):
            with self.assertRaises(CoreSafetyError):
                self.q.apply_offline_test(self.spec["task_id"], claim["token"],
                                          self.proposal(), now=101)
        self.assertTrue(swapped, "attack must actually occur at effect boundary")
        self.assertFalse((attacker / target.name).exists())
        self.assertEqual(self.q.snapshot()["state"], "APPLYING")
        self.assertEqual(self.q.recover(now=111)["state"], "NEEDS_MANUAL_REVIEW")
        with self.assertRaises(CoreSafetyError):
            self.q.claim("retry", now=112)
        parent.unlink()
        # Restore only the test fixture tree for teardown and investigation.
        displaced.rename(parent)

    def test_foreign_or_forged_approval_is_not_enough(self):
        with self.assertRaises(CoreSafetyError):
            self.q.enqueue(self.spec)
        with self.assertRaises(CoreSafetyError):
            self.q.enqueue(self.spec, trusted_approval_check=lambda s: False)
        self.assertEqual(self.q.snapshot()["state"], "EMPTY")

    def test_pinned_commit_and_digest_verified_from_git(self):
        wrong = copy.deepcopy(self.spec)
        wrong["source_sha"] = "0" * 40
        with self.assertRaises(CoreSafetyError):
            self.q.enqueue(wrong, trusted_approval_check=lambda s: True)
        wrong = copy.deepcopy(self.spec)
        wrong["source_sha256"] = "0" * 64
        with self.assertRaises(CoreSafetyError):
            self.q.enqueue(wrong, trusted_approval_check=lambda s: True)
        self.assertEqual(self.q.snapshot()["state"], "EMPTY")

    def test_path_traversal_and_extra_fields_refused(self):
        for path in ("../forbidden.py", TARGET.replace("lesson_once.py", "../x.py"),
                     "bridge/neurofactory/development/stage5_usage_ledger.py",
                     TARGET + "/file", TARGET[:-3] + ".sh"):
            bad = copy.deepcopy(self.spec)
            bad["target"] = path
            with self.assertRaises(CoreSafetyError, msg=path):
                self.q.enqueue(bad, trusted_approval_check=lambda s: True)
        bad = dict(self.spec, approved=True)
        with self.assertRaises(CoreSafetyError):
            self.q.enqueue(bad, trusted_approval_check=lambda s: True)

    def test_existing_symlink_path_refused(self):
        dest = self.q.sandbox / TARGET
        self.secure_parents(dest)
        external = self.base / "foreign"
        external.write_text("protected")
        try:
            dest.symlink_to(external)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not permitted on this host")
        with self.assertRaises(CoreSafetyError):
            self.q.enqueue(self.spec, trusted_approval_check=lambda s: True)
        self.assertEqual(external.read_text(), "protected")

    def test_duplicate_admission_refused(self):
        self.admit()
        with self.assertRaises(CoreSafetyError):
            self.q.enqueue(self.spec, trusted_approval_check=self.approver)
        self.assertEqual(self.q.snapshot()["state"], "QUEUED")

    def test_mismatched_worker_token_and_output_digest(self):
        self.admit()
        self.q.claim("worker", now=100, lease_seconds=100)
        with self.assertRaises(CoreSafetyError):
            self.q.apply_offline_test(self.spec["task_id"], "fake", self.proposal(), now=101)
        bad = self.proposal()
        bad["content_sha256"] = "a" * 64
        with self.assertRaises(CoreSafetyError):
            self.q.apply_offline_test(self.spec["task_id"], "fake", bad, now=101)
        self.assertEqual(self.q.snapshot()["state"], "CLAIMED")

    def test_sandbox_preimage_tamper_refused(self):
        self.admit()
        claim = self.q.claim("worker", now=100)
        target = self.q.sandbox / TARGET
        self.secure_parents(target)
        target.write_text("intruder")
        with self.assertRaises(CoreSafetyError):
            self.q.apply_offline_test(self.spec["task_id"], claim["token"], self.proposal(), now=101)
        self.assertEqual(target.read_text(), "intruder")
        self.assertEqual(self.q.snapshot()["state"], "CLAIMED")

    def test_test_completion_tamper_stops_on_recovery(self):
        self.admit()
        claim = self.q.claim("worker", now=100)
        self.q.apply_offline_test(self.spec["task_id"], claim["token"], self.proposal(), now=101)
        (self.q.sandbox / TARGET).write_text("replaced")
        self.assertEqual(self.q.recover(now=220)["state"], "NEEDS_MANUAL_REVIEW")
        with self.assertRaises(CoreSafetyError):
            self.q.claim("retry", now=230)

    def test_provider_wire_is_disabled_without_core_permission(self):
        self.admit()
        preview = self.q.provider_preview(self.spec["task_id"])
        self.assertFalse(preview["permissions"]["execution"])
        self.assertFalse(preview["permissions"]["publication"])
        self.assertFalse(preview["permissions"]["paid_api"])
        self.assertEqual(preview["schema"], "neurofactory.coordination.provider_bridge.v1")
        self.assertEqual(set(preview), {"schema", "request", "binding", "permissions"})
        self.assertEqual(preview["request"]["task_id"], self.spec["task_id"])
        self.assertEqual(set(preview["request"]), {
            "schema", "task_id", "project_id", "input_sha256", "target_path", "instruction"})
        self.assertEqual(preview["request"]["target_path"], "src/lesson_once.py")
        self.assertEqual(preview["binding"]["core_target"], TARGET)
        self.assertEqual(preview["binding"]["provider_target"], "src/lesson_once.py")
        self.assertEqual(preview["binding"]["source_sha"], self.spec["source_sha"])
        self.assertEqual(preview["request"]["input_sha256"],
                         hashlib.sha256(_canonical(self.spec)).hexdigest())
        self.assertEqual(preview["binding"]["input_sha256"],
                         preview["request"]["input_sha256"])
        claim = self.q.claim("worker", now=100)
        fake = self.proposal()
        fake["mode"] = "PROVIDER_UNVERIFIED"
        with self.assertRaises(CoreSafetyError):
            self.q.apply_offline_test(self.spec["task_id"], claim["token"], fake, now=101)
        self.assertEqual(self.q.snapshot()["state"], "CLAIMED")

    def test_markdown_provider_mapping_without_model_execution(self):
        self.spec["target"] = "bridge/neurofactory/development/core_owned/notes/lesson.md"
        self.admit()
        packet = self.q.provider_preview(self.spec["task_id"])
        self.assertEqual(packet["request"]["target_path"], "docs/notes/lesson.md")
        self.assertEqual(packet["binding"]["core_target"], self.spec["target"])
        self.assertEqual(packet["binding"]["source_sha256"], EMPTY_SHA)
        self.assertIs(packet["permissions"]["execution"], False)

    def test_non_string_model_is_safely_rejected(self):
        bad = copy.deepcopy(self.spec)
        bad["model"] = ["qwen3:4b"]
        with self.assertRaises(CoreSafetyError):
            self.q.enqueue(bad, trusted_approval_check=lambda s: True)

    def test_corrupt_checkpoint_identity_stops(self):
        self.admit()
        with sqlite3.connect(self.q.db) as con:
            con.execute("UPDATE single_job SET spec_sha256=? WHERE singleton=1", ("a" * 64,))
        with self.assertRaises(CoreSafetyError):
            self.q.snapshot()

    @unittest.skipUnless(os.name == "posix", "POSIX synthetic write only")
    def test_external_anchor_rejects_consistent_local_db_and_file_forgery(self):
        self.admit()
        claim = self.q.claim("host", now=100, lease_seconds=10)
        self.q.apply_offline_test(self.spec["task_id"], claim["token"],
                                  self.proposal(), now=101)
        external_reference = self.q.checkpoint_fingerprint()
        checked = self.q.check_external_checkpoint(external_reference)
        self.assertTrue(checked["matches_supplied_external_digest"])
        self.assertFalse(checked["external_origin_attested"])
        self.assertFalse(checked["execution_allowed"])
        with self.assertRaises(CoreSafetyError):
            self.q.check_external_checkpoint(None)
        with self.assertRaises(CoreSafetyError):
            self.q.check_external_checkpoint("not a digest")

        # Reproducer from independent REVIEW: attacker can modify BOTH DB and file.
        replacement = "FORGED = 73\\n".replace("\\\\n", "\\n")
        forged_digest = hashlib.sha256(replacement.encode("utf8")).hexdigest()
        (self.q.sandbox / TARGET).write_text(replacement, "utf8")
        with sqlite3.connect(self.q.db) as db:
            raw = db.execute("SELECT receipt FROM single_job WHERE singleton=1").fetchone()[0]
            fake_receipt = json.loads(raw)
            fake_receipt["result_sha256"] = forged_digest
            db.execute("UPDATE single_job SET result_sha256=?, receipt=? WHERE singleton=1",
                       (forged_digest, json.dumps(fake_receipt)))
        # Local hashes are self-consistent, which is the confirmed risk.
        self.assertEqual(self.q.snapshot()["state"], "CHECKPOINTED_TEST")
        self.assertNotEqual(external_reference, self.q.checkpoint_fingerprint())
        with self.assertRaises(CoreSafetyError):
            self.q.check_external_checkpoint(external_reference)

    @unittest.skipUnless(os.name == "posix", "Completed synthetic file checkpoint required")
    def test_external_anchor_db_snapshot_race(self):
        """Spec metadata can be replaced between old two independent SQLite reads."""
        from unittest.mock import patch
        self.admit()
        held = self.q.claim("worker", now=100, lease_seconds=10)
        self.q.apply_offline_test(self.spec["task_id"], held["token"],
                                  self.proposal(), now=101)
        anchored = self.q.checkpoint_fingerprint()
        original_snapshot = self.q.snapshot
        intervened = []

        def switch_sqlite_before_second_read():
            intervened.append(True)
            with sqlite3.connect(self.q.db) as db:
                raw = db.execute("SELECT spec FROM single_job WHERE singleton=1").fetchone()[0]
                changed = json.loads(raw)
                changed["objective"] = (
                    "New forged objective injected between metadata and snapshot reads."
                )
                body = _canonical(changed)
                db.execute("UPDATE single_job SET spec=?, spec_sha256=? WHERE singleton=1",
                           (body.decode("utf8"), hashlib.sha256(body).hexdigest()))
            return original_snapshot()

        with patch.object(self.q, "snapshot", side_effect=switch_sqlite_before_second_read):
            result = self.q.check_external_checkpoint(anchored)
            self.assertFalse(intervened,
                "External checkpoint comparison read stale metadata across separate SQLite snapshots")
            self.assertFalse(result["external_origin_attested"])
            self.assertFalse(result["execution_allowed"])

    def test_poisoned_receipt_cannot_appear_successful(self):
        self.admit()
        claim = self.q.claim("worker", now=100)
        self.q.apply_offline_test(self.spec["task_id"], claim["token"],
                                  self.proposal(), now=101)
        with sqlite3.connect(self.q.db) as db:
            receipt = json.loads(db.execute(
                "SELECT receipt FROM single_job WHERE singleton=1").fetchone()[0])
            receipt["published"] = True
            db.execute("UPDATE single_job SET receipt=? WHERE singleton=1",
                       (json.dumps(receipt),))
        with self.assertRaises(CoreSafetyError):
            self.q.snapshot()

    def test_poisoned_result_digest_cannot_appear_successful(self):
        self.admit()
        claim = self.q.claim("worker", now=100)
        self.q.apply_offline_test(self.spec["task_id"], claim["token"],
                                  self.proposal(), now=101)
        with sqlite3.connect(self.q.db) as db:
            db.execute("UPDATE single_job SET result_sha256=? WHERE singleton=1",
                       ("0" * 64,))
        with self.assertRaises(CoreSafetyError):
            self.q.snapshot()

    def test_windows_reserved_device_names_rejected_on_every_host(self):
        from one_task_core import _safe_target
        for suffix in ("NUL.py", "con.txt", "Com1.md", "folder/AUX.json",
                       "folder/trailing./child.py", "folder/PRN.txt"):
            with self.subTest(suffix=suffix), self.assertRaises(CoreSafetyError):
                _safe_target(
                    "bridge/neurofactory/development/core_owned/" + suffix)

    def test_checkpointed_snapshot_must_read_back_result(self):
        self.admit()
        claim = self.q.claim("worker", now=100)
        self.q.apply_offline_test(self.spec["task_id"], claim["token"],
                                  self.proposal(), now=101)
        (self.q.sandbox / TARGET).write_text("tampered after commit", "utf8")
        with self.assertRaises(CoreSafetyError):
            self.q.snapshot()

    def test_unmodified_source_is_not_overwritten_on_admission(self):
        path = self.repo / TARGET
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("BASE = 1\n")
        git(self.repo, "add", TARGET)
        git(self.repo, "commit", "-qm", "add tracked fixture")
        sha = git(self.repo, "rev-parse", "HEAD")
        self.spec["source_sha"] = self.spec["approval_commit"] = sha
        self.spec["source_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        sandbox = self.q.sandbox / TARGET
        self.secure_parents(sandbox)
        sandbox.write_bytes(path.read_bytes())
        self.admit()
        self.assertEqual(sandbox.read_text(), "BASE = 1\n")


if __name__ == "__main__":
    unittest.main()
