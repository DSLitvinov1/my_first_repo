"""Bounded negative and metamorphic tests of offline-only OPS diagnostics.

All inputs synthetic and confined to memory/TemporaryDirectory. Never read a
real CORE journal, call an API, invoke subprocesses, or write a release receipt.
"""
import copy
import json
import random
import socket
import subprocess
from unittest import TestCase, mock

from diagnose import SnapshotError, _parse_unique, diagnose
from ops_report import report, render_russian_text
from test_diagnose import example
from test_ops_report import envelope, observation


class AdversarialOfflineOpsTests(TestCase):
    def test_400_distinct_repeat_patterns_never_release(self):
        rng = random.Random(40503)
        codes = ("MODEL_TIMEOUT", "RUNNER_LOST", "RECEIPT_UNKNOWN",
                 "LEASE_CONFLICT", "GITHUB_UNAVAILABLE")
        for i in range(400):
            code = rng.choice(codes)
            count = rng.randrange(1, 5)
            ids = rng.sample(range(1, 30000), count)
            examples = [observation("case-%d-%d" % (i,j), run=run,
                                    code=code, component="worker-%d" % (i%5))
                        for j, run in enumerate(ids)]
            found = report(envelope(*examples))
            self.assertFalse(any(found["actions_allowed"].values()))
            self.assertEqual(found["distinct_incident_runs"], count)
            self.assertEqual(bool(found["recurrent_failures"]), count >= 2)
            if count >= 2:
                self.assertEqual(found["recurrent_failures"][0]["reported_run_ids"],
                                 sorted(ids))
                self.assertFalse(found["recurrent_failures"][0]["auto_recovery_permitted"])

    def test_repeated_same_run_never_exaggerates_outage(self):
        for n in (1, 2, 3, 10, 40):
            observations = [
                observation("same-%02d" % k,run=91245,code="RUNNER_LOST")
                for k in range(n)]
            found = report(envelope(*observations))
            self.assertEqual(found["distinct_incident_runs"], 1)
            self.assertEqual(found["recurrent_failures"], [])

    def test_reordering_distinct_runs_does_not_change_repeat_detection(self):
        seq = [observation("a",run=71),observation("b",run=72),
               observation("c",run=73)]
        result = report(envelope(*seq))
        permuted = report(envelope(*reversed(seq)))
        self.assertEqual(result["recurrent_failures"],permuted["recurrent_failures"])

    def test_many_categories_do_not_mix_components(self):
        observations=[]
        for i in range(20):
            observations.append(observation("o-"+str(i),run=100+i,
                                            code="RUNNER_LOST",
                                            component="isolated-"+str(i)))
        found=report(envelope(*observations))
        self.assertEqual(found["recurrent_failures"],[])
        self.assertEqual(found["distinct_incident_runs"],20)

    def test_duplicate_observation_id_fail_closed_despite_different_runs(self):
        d=envelope(observation("same",run=1),observation("same",run=2))
        with self.assertRaises(SnapshotError):
            report(d)

    def test_40_is_allowed_and_41_fails(self):
        inputs=[observation("o-"+str(i),run=i+1) for i in range(40)]
        self.assertEqual(report(envelope(*inputs))["observation_count"],40)
        with self.assertRaises(SnapshotError):
            report(envelope(*(inputs+[observation("new",run=41)])))

    def test_101_workers_disallowed_without_scanning_others(self):
        d=envelope(observation("obs"))
        d["observations"][0]["workers"]=[
            {"id":"runner-%03d" % i,"role":"runner","state":"ready"}
            for i in range(51)]
        with self.assertRaises(SnapshotError):
            report(d)

    def test_101_queue_items_disallowed(self):
        d=envelope(observation("obs"))
        d["observations"][0]["queue"]=[
            {"task_id":"TASK-%03d" % i,"state":"queued","attempt":0}
            for i in range(101)]
        with self.assertRaises(SnapshotError):
            report(d)

    def test_101_incidents_disallowed(self):
        d=envelope(observation("obs"))
        d["observations"][0]["incidents"]=[
            {"code":"RUNNER_LOST","component":"worker","run_id":i+1}
            for i in range(101)]
        with self.assertRaises(SnapshotError):
            report(d)

    def test_bool_run_id_not_numeric_evidence(self):
        d=envelope(observation("obs"))
        d["observations"][0]["incidents"][0]["run_id"]=True
        with self.assertRaises(SnapshotError):
            report(d)

    def test_attempt_over_limit_refused(self):
        d=envelope(observation("obs"))
        d["observations"][0]["queue"][0]["attempt"]=1001
        with self.assertRaises(SnapshotError):
            report(d)

    def test_injected_slash_in_worker_name_refused(self):
        d=envelope(observation("obs"))
        d["observations"][0]["workers"][0]["id"]="../other_repo"
        with self.assertRaises(SnapshotError):
            report(d)

    def test_injected_newline_in_component_refused(self):
        d=envelope(observation("obs"))
        d["observations"][0]["incidents"][0]["component"]="queue\nRELEASE_OK"
        with self.assertRaises(SnapshotError):
            report(d)

    def test_script_like_component_never_executed_or_echoed(self):
        d=envelope(observation("obs"))
        d["observations"][0]["incidents"][0]["component"]="<script>"
        with self.assertRaises(SnapshotError):
            report(d)

    def test_untrusted_secret_in_nested_snapshot_not_in_report(self):
        d=envelope(observation("obs"))
        d["observations"][0]["snapshot"]["review"]["token"]="secret-value-ops-779"
        summary=report(d)
        self.assertNotIn("secret-value-ops-779",
                         json.dumps(summary,ensure_ascii=False))
        self.assertNotIn("secret-value-ops-779",
                         render_russian_text(summary))

    def test_forced_unknown_status_does_not_convert_to_success(self):
        d=envelope(observation("obs"))
        d["observations"][0]["workers"]=[]
        d["observations"][0]["queue"]=[]
        summary=report(d)
        rendered=render_russian_text(summary).lower()
        self.assertIn("неизвестно",rendered)
        self.assertEqual(summary["latest_diagnosis"],"BLOCKED")
        self.assertFalse(summary["actions_allowed"]["retry"])

    def test_forged_approved_review_still_blocks_release(self):
        d=envelope(observation("obs"))
        d["observations"][0]["snapshot"]["review"]["verdict"]="APPROVE"
        result=report(d)
        self.assertIn("REVIEW_PROVENANCE_UNVERIFIED",result["latest_blockers"])
        self.assertFalse(result["actions_allowed"]["publish"])

    def test_uncertain_publisher_still_blocks_release(self):
        d=envelope(observation("obs"))
        d["observations"][0]["snapshot"]["publisher_receipt"]={"state":"uncertain"}
        result=report(d)
        self.assertIn("UNCERTAIN_PUBLISH_STOP",result["latest_blockers"])
        self.assertFalse(result["actions_allowed"]["publish"])

    def test_case_sensitive_duplicate_keys_rejected(self):
        with self.assertRaises(SnapshotError):
            _parse_unique('{"review":{"verdict":"REJECT","verdict":"APPROVE"}}')

    def test_null_input_never_authorized(self):
        with self.assertRaises(SnapshotError):
            report(None)
        with self.assertRaises(SnapshotError):
            diagnose(None)

    def test_missing_incident_code_denied(self):
        d=envelope(observation("obs"))
        del d["observations"][0]["incidents"][0]["code"]
        with self.assertRaises(SnapshotError):
            report(d)

    def test_unknown_lifecycle_state_denied(self):
        d=envelope(observation("obs"))
        d["observations"][0]["queue"][0]["state"]="released"
        with self.assertRaises(SnapshotError):
            report(d)

    def test_no_network_subprocess_or_file_writes(self):
        d=envelope(observation("obs"))
        with mock.patch.object(socket, "create_connection",
                               side_effect=AssertionError("network")), \
             mock.patch.object(subprocess, "run",
                               side_effect=AssertionError("subprocess")), \
             mock.patch("pathlib.Path.write_text",
                        side_effect=AssertionError("disk write")):
            output=report(d)
            self.assertTrue(render_russian_text(output))
            self.assertFalse(output["actions_allowed"]["auto_recovery"])

    def test_input_objects_unchanged_after_reporting(self):
        d=envelope(observation("obs"))
        before=copy.deepcopy(d)
        report(d)
        self.assertEqual(d,before)

    def test_recovery_advice_never_contains_executable_commands(self):
        d=envelope(observation("a",run=8,code="LEASE_CONFLICT"),
                   observation("b",run=9,code="LEASE_CONFLICT"))
        item=report(d)["recurrent_failures"][0]
        self.assertIn("проверки",item["recovery_recommendation"])
        self.assertFalse(item["auto_recovery_permitted"])

if __name__=="__main__":
    import unittest
    unittest.main()
