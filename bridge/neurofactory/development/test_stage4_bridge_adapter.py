"""Offline acceptance checks for separate runner integration; no models or GitHub writes."""
import base64
import copy
import hashlib
import json
import pathlib
import tempfile
import unittest

import stage4_bridge_adapter as adapter
from stage4_queue import Stage4Queue, Stage4Error

ROOT = pathlib.Path(__file__).resolve().parent
PLAN = json.loads((ROOT / "roadmap.json").read_text(encoding="utf-8"))
COMMIT = "a" * 40
TARGET = "bridge/neurofactory/development/path_policy.py"
SOURCE = b"def approved_change_path(path):\n    return True\n"
DIGEST = hashlib.sha256(SOURCE).hexdigest()


class FakeGithub:
    def __init__(self):
        self.published = False
        self.duplicate_calls = 0
        self.publish_calls = 0
        self.ancestry = "ahead"
        self.source = SOURCE

    def fetch(self, url):
        if "/compare/" in url:
            return {"status": self.ancestry}
        if "/commits?" in url:
            return [{"sha": COMMIT}] if self.published else []
        if "/commits/" in url:
            if not self.published:
                return None
            return {"sha": COMMIT,
                    "files": [{"filename": TARGET, "status": "added"}]}
        if "/contents/" in url:
            if not self.published:
                return None
            return {"encoding": "base64",
                    "content": base64.b64encode(self.source).decode()}
        raise AssertionError("Unexpected external read: " + url)

    def publish(self, path, digest):
        self.publish_calls += 1
        if self.published:
            self.duplicate_calls += 1
        assert path == TARGET and digest == DIGEST
        self.published = True
        return COMMIT


class Stage4BridgeAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nf-live-gate-")
        self.addCleanup(self.tmp.cleanup)
        self.remote = FakeGithub()
        self.receipts = adapter.ReadOnlyGithubReceipts(fetch=self.remote.fetch)
        self.bridge = adapter.Stage4BridgeAdapter(
            self.tmp.name, copy.deepcopy(PLAN), self.receipts)
        self.bridge.queue.prepare()

    def verified_first_two_agents(self):
        queue = self.bridge.queue
        queue.claim("writer", 100, lease_seconds=30)
        queue.before_external_effect("writer", source_sha256=DIGEST)
        self.remote.published = True
        self.bridge.complete_with_verified_receipt("writer", COMMIT, TARGET)
        queue.claim("reviewer", 110, lease_seconds=30)
        queue.before_external_effect("reviewer", source_sha256=DIGEST,
                                     verdict="REVIEW_OK")
        self.bridge.complete_with_verified_receipt("reviewer", COMMIT, TARGET)
        self.remote.published = False

    def test_invalid_cross_project_destination_fails_before_claim(self):
        self.verified_first_two_agents()
        with self.assertRaises(adapter.ReceiptError):
            self.bridge.publish_trusted(200, "bridge/other_project/do.py",
                                        self.remote.publish)
        self.assertEqual(self.bridge.queue.prepare()["publisher"]["state"], "queued")

    def test_verified_agents_mandatory_for_publisher(self):
        with self.assertRaises(Stage4Error):
            self.bridge.publish_trusted(200, TARGET, self.remote.publish)
        self.assertEqual(self.remote.publish_calls, 0)

    def test_publication_intent_is_saved_before_external_effect(self):
        self.verified_first_two_agents()
        observed = []
        def publisher(path, digest):
            snapshot = self.bridge.queue.prepare()["publisher"]
            observed.append((snapshot["state"], snapshot["proof"]["source_sha256"]))
            return self.remote.publish(path, digest)
        output = self.bridge.publish_trusted(200, TARGET, publisher)
        self.assertEqual(observed, [("publishing", DIGEST)])
        self.assertEqual(output["state"], "verified_done")
        self.assertEqual(self.remote.publish_calls, 1)

    def test_repeated_delivery_has_no_second_effect(self):
        self.verified_first_two_agents()
        self.bridge.publish_trusted(200, TARGET, self.remote.publish)
        repeated = self.bridge.publish_trusted(201, TARGET, self.remote.publish)
        self.assertEqual(repeated["state"], "verified_done")
        self.assertEqual(self.remote.publish_calls, 1)

    def test_crash_after_remote_commit_reconciles_without_republish(self):
        self.verified_first_two_agents()
        def ambiguous(path, digest):
            self.remote.publish(path, digest)
            raise OSError("disconnected before receipt")
        with self.assertRaises(OSError):
            self.bridge.publish_trusted(200, TARGET, ambiguous)
        self.assertEqual(self.bridge.queue.prepare()["publisher"]["state"], "publishing")
        state = self.bridge.recover(201, TARGET)
        self.assertEqual(state["publisher"]["state"], "verified_done")
        self.assertEqual(self.remote.publish_calls, 1)
        self.assertEqual(self.remote.duplicate_calls, 0)

    def test_crash_before_remote_commit_blocks_all_replays(self):
        self.verified_first_two_agents()
        def fail(path, digest):
            raise OSError("failed before API call")
        with self.assertRaises(OSError):
            self.bridge.publish_trusted(200, TARGET, fail)
        self.assertEqual(self.bridge.recover(201, TARGET)["publisher"]["state"],
                         "needs_receipt_check")
        with self.assertRaises(adapter.ReceiptError):
            self.bridge.publish_trusted(202, TARGET, self.remote.publish)
        self.assertEqual(self.remote.publish_calls, 0)

    def test_tampered_remote_source_does_not_complete(self):
        self.verified_first_two_agents()
        self.remote.source = b"tampered"
        with self.assertRaises(adapter.ReceiptError):
            self.bridge.publish_trusted(200, TARGET, self.remote.publish)
        self.assertEqual(self.bridge.recover(201, TARGET)["publisher"]["state"],
                         "needs_receipt_check")
        self.assertEqual(self.remote.publish_calls, 1)

    def test_wrong_branch_ancestry_blocks_false_receipt(self):
        self.verified_first_two_agents()
        self.remote.ancestry = "behind"
        with self.assertRaises(adapter.ReceiptError):
            self.bridge.publish_trusted(200, TARGET, self.remote.publish)
        self.assertEqual(self.bridge.queue.prepare()["publisher"]["state"], "publishing")

    def test_wrong_digest_blocks_receipt(self):
        self.verified_first_two_agents()
        self.remote.source = b"not reviewed"
        self.remote.published = True
        with self.assertRaises(adapter.ReceiptError):
            self.bridge.receipts.verify(COMMIT, TARGET, DIGEST)

    def test_recovery_preserves_original_writer_and_reviewer_proofs(self):
        self.verified_first_two_agents()
        before = self.bridge.queue.prepare()
        self.assertEqual(self.bridge.recover(210, TARGET)["publisher"]["state"],
                         "queued")
        after = self.bridge.queue.prepare()
        self.assertEqual(after["writer"], before["writer"])
        self.assertEqual(after["reviewer"], before["reviewer"])

    def test_other_workflow_path_disallowed(self):
        self.assertFalse(adapter.approved_target(".github/workflows/other.yml"))
        self.assertFalse(adapter.approved_target("bridge/neurofactory/../secret.py"))
        self.assertFalse(adapter.approved_target("bridge/neurofactory/a//b.py"))
        self.assertFalse(adapter.approved_target("bridge/neurofactory/code.py?token"))
        self.assertTrue(adapter.approved_target(TARGET))


if __name__ == "__main__":
    unittest.main(verbosity=2)
