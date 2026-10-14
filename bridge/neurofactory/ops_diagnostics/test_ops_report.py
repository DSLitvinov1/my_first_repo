"""OPS report-only tests: fake snapshots and strictly no network or queue actions."""
import copy
import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from diagnose import SnapshotError, _parse_unique
from ops_report import main, report, RECOMMENDATIONS
from test_diagnose import example

def observation(name, *, run=111, code="RUNNER_LOST", component="local_worker"):
    return {
        "id": name,
        "snapshot": example(),
        "workers": [{"id": "runner-A", "role": "writer", "state": "failed"},
                    {"id": "runner-B", "role": "observer", "state": "ready"}],
        "queue": [{"task_id": "NF-DEV-05-Q091", "state": "blocked", "attempt": 1},
                  {"task_id": "NF-DEV-05-Q092", "state": "queued", "attempt": 0}],
        "incidents": [{"code": code, "component": component, "run_id": run}]
    }

def envelope(*observations):
    return {"schema": 1, "scope": "neurofactory-ops-offline-report",
            "observations": list(observations)}

class OfflineOpsReportTests(unittest.TestCase):
    def two(self):
        return envelope(observation("obs-1",run=111), observation("obs-2",run=112))

    def fail(self, mutate):
        d=self.two()
        mutate(d)
        with self.assertRaises(SnapshotError):
            report(d)

    def test_single_observation_inventory_is_only_observed_items(self):
        d=envelope(observation("obs-1"))
        result=report(d)
        self.assertEqual(result["latest_observation_id"],"obs-1")
        self.assertEqual(len(result["worker_inventory"]),2)
        self.assertEqual(result["queue_status_counts"],{"blocked":1,"queued":1})
        self.assertEqual(result["recurrent_failures"],[])
        self.assertEqual(result["source_trust"],"UNTRUSTED_OFFLINE_SNAPSHOTS")

    def test_two_distinct_runs_mean_repeated_failure(self):
        result=report(self.two())
        failure=result["recurrent_failures"][0]
        self.assertEqual(failure["distinct_failed_runs"],2)
        self.assertEqual(failure["reported_run_ids"],[111,112])
        self.assertEqual(failure["code"],"RUNNER_LOST")
        self.assertFalse(failure["auto_recovery_permitted"])

    def test_duplicate_observation_of_same_run_not_counted_twice(self):
        d=envelope(observation("obs-1",run=111),observation("obs-2",run=111))
        self.assertEqual(report(d)["recurrent_failures"],[])
        self.assertEqual(report(d)["distinct_incident_runs"],1)

    def test_duplicate_incident_inside_snapshot_is_not_another_run(self):
        obs=observation("obs-1")
        obs["incidents"].append(copy.deepcopy(obs["incidents"][0]))
        self.assertEqual(report(envelope(obs))["recurrent_failures"],[])

    def test_same_code_different_components_are_not_conflated(self):
        d=envelope(observation("obs-1",run=111,component="runner1"),
                   observation("obs-2",run=112,component="runner2"))
        self.assertEqual(report(d)["recurrent_failures"],[])

    def test_different_codes_same_component_not_conflated(self):
        d=envelope(observation("obs-1",run=111,code="RUNNER_LOST"),
                   observation("obs-2",run=112,code="MODEL_TIMEOUT"))
        self.assertEqual(report(d)["recurrent_failures"],[])

    def test_unknown_receipt_never_recommend_second_publication(self):
        d=envelope(observation("obs-1",run=111,code="RECEIPT_UNKNOWN"),
                   observation("obs-2",run=112,code="RECEIPT_UNKNOWN"))
        r=report(d)
        text=r["recurrent_failures"][0]["recovery_recommendation"].lower()
        self.assertIn("остановить",text)
        self.assertIn("readback",text)
        self.assertFalse(r["actions_allowed"]["publish"])

    def test_duplicate_publication_warning_blocks_all_actions(self):
        d=envelope(observation("obs-1",run=100,code="DUPLICATE_PUBLICATION"),
                   observation("obs-2",run=101,code="DUPLICATE_PUBLICATION"))
        r=report(d)
        self.assertIn("координатора",r["recurrent_failures"][0]["recovery_recommendation"])
        self.assertTrue(all(v is False for v in r["actions_allowed"].values()))

    def test_each_incident_has_safe_recommendation(self):
        for code in RECOMMENDATIONS:
            d=envelope(observation("obs-1",run=1,code=code),
                       observation("obs-2",run=2,code=code))
            r=report(d)
            self.assertTrue(r["recurrent_failures"][0]["recovery_recommendation"])
            self.assertFalse(r["actions_allowed"]["auto_recovery"])

    def test_latest_state_only_not_old_worker_inventory(self):
        old=observation("obs-1")
        new=observation("obs-2")
        new["workers"]=[{"id":"new-runner","role":"reviewer","state":"unknown"}]
        new["queue"]=[]
        r=report(envelope(old,new))
        self.assertEqual(r["worker_inventory"],new["workers"])
        self.assertEqual(r["queue_inventory"],[])
        self.assertEqual(r["queue_status_counts"],{})

    def test_latest_snapshot_diagnosis_is_preserved_as_blocked(self):
        r=report(self.two())
        self.assertEqual(r["latest_diagnosis"],"BLOCKED")
        self.assertIn("REVIEW_PROVENANCE_UNVERIFIED",r["latest_blockers"])

    def test_even_approved_synthetic_snapshot_no_release(self):
        r=report(self.two())
        self.assertNotIn("release_authorized",r)
        self.assertFalse(r["actions_allowed"]["publish"])

    def test_foreign_scope_refused(self):
        self.fail(lambda d: d.update(scope="production"))

    def test_unexpected_top_level_refused(self):
        self.fail(lambda d: d.update(unsafe_command="publish"))

    def test_missing_observations_refused(self):
        self.fail(lambda d: d.update(observations=[]))

    def test_duplicate_observation_ids_refused(self):
        self.fail(lambda d: d["observations"][1].update(id="obs-1"))

    def test_unknown_worker_state_refused(self):
        self.fail(lambda d: d["observations"][0]["workers"][0].update(state="publish"))

    def test_invalid_worker_schema_refused(self):
        self.fail(lambda d: d["observations"][0]["workers"][0].update(token="SECRET"))

    def test_duplicate_worker_in_observation_refused(self):
        self.fail(lambda d: d["observations"][0]["workers"].append(
            copy.deepcopy(d["observations"][0]["workers"][0])))

    def test_duplicate_queue_task_refused(self):
        self.fail(lambda d: d["observations"][0]["queue"].append(
            copy.deepcopy(d["observations"][0]["queue"][0])))

    def test_invalid_negative_attempt_refused(self):
        self.fail(lambda d: d["observations"][0]["queue"][0].update(attempt=-1))

    def test_boolean_attempt_refused(self):
        self.fail(lambda d: d["observations"][0]["queue"][0].update(attempt=True))

    def test_unknown_incident_code_refused(self):
        self.fail(lambda d: d["observations"][0]["incidents"][0].update(code="AUTO_REPAIR"))

    def test_incident_must_have_positive_integer_run_id(self):
        self.fail(lambda d: d["observations"][0]["incidents"][0].update(run_id=0))

    def test_untrusted_string_is_not_echoed(self):
        d=self.two()
        d["observations"][0]["snapshot"]["review"]["private_token"]="NOT_A_TOKEN_FOR_OUTPUT"
        result=json.dumps(report(d),ensure_ascii=False)
        self.assertNotIn("NOT_A_TOKEN_FOR_OUTPUT",result)

    def test_excessive_observations_refused(self):
        d=self.two()
        d["observations"]=[observation("obs-"+str(i)) for i in range(41)]
        with self.assertRaises(SnapshotError):
            report(d)

    def test_malformed_snapshot_refused(self):
        self.fail(lambda d: d["observations"][0]["snapshot"].update(scope="unknown"))

    def test_cli_does_not_write_even_when_reporting(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"input.json"
            path.write_text(json.dumps(self.two()),encoding="utf-8")
            before=set(Path(tmp).iterdir())
            stream=StringIO()
            with redirect_stdout(stream):
                self.assertEqual(main([str(path)]),0)
            data=json.loads(stream.getvalue())
            self.assertEqual(data["observation_count"],2)
            self.assertEqual(before,set(Path(tmp).iterdir()))

    def test_cli_rejects_duplicate_json_keys_without_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"input.json"
            path.write_text('{"schema":1,"schema":2}',encoding="utf-8")
            stderr=StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(main([str(path)]),2)
            self.assertIn("OPS_REPORT_REFUSED",stderr.getvalue())

    def test_cli_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            stderr=StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(main([str(Path(tmp)/"missing.json")]),2)

if __name__ == "__main__":
    unittest.main()
