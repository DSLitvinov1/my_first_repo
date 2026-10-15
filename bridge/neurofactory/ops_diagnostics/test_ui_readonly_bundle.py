"""Only new OPS/UI compatibility contract tests, no CORE or network."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO

from diagnose import SnapshotError
from status_adapter import snapshot_to_status
from test_status_adapter import sample
from ui_readonly_bundle import join_readonly_views, main, LANES

OPS_SHA = "a" * 40

def board(sha=OPS_SHA):
    items=[]
    for lane in LANES:
        if lane=="OPS":
            items.append({
                "lane": "OPS", "reported_phase": "waiting_review",
                "evidence_status": "not_verified", "release_allowed": False,
                "commit": sha,
                "issue_url": "https://github.com/DSLitvinov1/my_first_repo/issues/6",
                "source": {"repository": "DSLitvinov1/my_first_repo",
                           "branch": "neurofactory-ops-completion-20261015"}})
        elif lane=="HANDOFF":
            items.append({
                "lane": lane, "reported_phase": "paused",
                "evidence_status": "not_verified", "release_allowed": False,
                "commit": "b"*40,
                "issue_url": "https://github.com/DSLitvinov1/my_first_repo/issues/4",
                "source": {"repository": "DSLitvinov1/my_first_repo",
                           "branch": "neurofactory-model-handoff-owned-20261013"}})
        else:
            items.append({
                "lane": lane, "reported_phase": "unknown",
                "evidence_status": "not_verified", "release_allowed": False,
                "commit": None, "issue_url": None, "source": None})
    return {
        "schema": 1, "kind": "read_only_coordination_board",
        "provenance": "self_reported_git_refs_not_attested",
        "cost_authorized_usd": 0,
        "external_execution_allowed": False,
        "external_publication_allowed": False,
        "automatic_retry_allowed": False,
        "lanes": items
    }


class CombinedViewTests(unittest.TestCase):
    def data(self):
        return snapshot_to_status(sample())

    def test_missing_both_layers_is_explicit_unknown(self):
        view=join_readonly_views()
        self.assertEqual(view["project_detail"]["bridge"]["display_state"],"UNKNOWN")
        self.assertIsNone(view["project_detail"]["last_reported_success"])
        self.assertEqual(view["board"]["lanes"][0]["reported_phase"],"unknown")
        self.assertEqual(view["consistency"]["status"],"SOURCE_MISSING")
        self.assertFalse(any(view["actions_allowed"].values()))

    def test_matching_layers_not_claimed_attested(self):
        view=join_readonly_views(board(),self.data())
        self.assertTrue(view["consistency"]["board_project_match"])
        self.assertEqual(view["consistency"]["status"],"MATCHES_UNVERIFIED_DECLARATIONS")
        self.assertFalse(view["trust"]["live_source_verified"])
        self.assertFalse(view["trust"]["release_authorized"])
        self.assertEqual(view["project_detail"]["bridge"]["display_state"],"UNKNOWN")
        self.assertEqual(view["project_detail"]["bridge"]["reported_state"],"RUNNING")
        self.assertEqual(view["project_detail"]["workers"][0]["display_state"],"UNKNOWN")

    def test_stale_board_sha_reports_conflict(self):
        result=join_readonly_views(board("c"*40),self.data())
        self.assertEqual(result["consistency"]["status"],"DECLARATIONS_DIFFER")
        self.assertFalse(result["consistency"]["board_project_match"])
        self.assertFalse(result["trust"]["release_authorized"])

    def test_project_without_board_is_still_useful(self):
        v=join_readonly_views(None,self.data())
        self.assertEqual(v["project_detail"]["checkpoint_counts"],{"PARTIAL":1})
        self.assertEqual(v["project_detail"]["stopped_tasks"],["NF-OPS-EXAMPLE-1"])
        self.assertEqual(v["consistency"]["status"],"SOURCE_MISSING")

    def test_board_without_project_does_not_fabricate_live_workers(self):
        v=join_readonly_views(board(),None)
        self.assertEqual(v["project_detail"]["queue"],[])
        self.assertIsNone(v["project_detail"]["last_reported_failure"])
        self.assertIsNone(v["consistency"]["board_project_match"])

    def test_reported_last_success_failure_by_id_with_exact_source_only(self):
        d=sample()
        d["runs"].extend([
            {"id": 104,"state":"COMPLETED","conclusion":"SUCCESS","head_sha":OPS_SHA},
            {"id": 105,"state":"COMPLETED","conclusion":"FAILURE","head_sha":OPS_SHA},
            {"id": 200,"state":"COMPLETED","conclusion":"SUCCESS","head_sha":"f"*40}
        ])
        v=join_readonly_views(board(),snapshot_to_status(d))
        highlights=v["project_detail"]
        self.assertEqual(highlights["last_reported_success"]["id"],104)
        self.assertEqual(highlights["last_reported_failure"]["id"],105)
        self.assertEqual(highlights["last_reported_run"]["id"],105)
        self.assertIn("NOT_GITHUB_ATTESTED",highlights["last_run_sort"])
        self.assertFalse(highlights["last_reported_success"]["source_verified"])

    def test_not_running_live_despite_recent_untrusted_heartbeat(self):
        v=join_readonly_views(board(),self.data())
        self.assertEqual(v["project_detail"]["bridge"]["display_state"],"UNKNOWN")
        self.assertEqual(v["project_detail"]["queue"][0]["display_state"],"BLOCKED")
        self.assertTrue(v["project_detail"]["queue"][0]["possibly_stalled"])

    def test_duplicate_run_does_not_create_fake_latest(self):
        d=sample()
        d["runs"].append(copy.deepcopy(d["runs"][0]))
        with self.assertRaises(SnapshotError):
            snapshot_to_status(d)

    def test_boolean_snapshot_schema_rejected_before_ui_projection(self):
        # JSON true must not be accepted as integer schema=1.
        bad = sample()
        bad["schema"] = True
        with self.assertRaises(SnapshotError):
            snapshot_to_status(bad)
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "untrusted.json"
            project.write_text(json.dumps(bad), encoding="utf-8")
            errors = StringIO()
            with redirect_stderr(errors):
                self.assertEqual(main(["--project", str(project)]), 2)
            self.assertIn("OPS_UI_REFUSED", errors.getvalue())

    def test_board_forged_approval_refused(self):
        b=board()
        b["lanes"][4]["release_allowed"]=True
        with self.assertRaises(SnapshotError):
            join_readonly_views(b,self.data())

    def test_board_forged_external_permission_refused(self):
        b=board()
        b["external_publication_allowed"]=True
        with self.assertRaises(SnapshotError):
            join_readonly_views(b,self.data())

    def test_board_forged_approved_provenance_refused(self):
        b=board()
        b["lanes"][4]["evidence_status"]="APPROVE"
        with self.assertRaises(SnapshotError):
            join_readonly_views(b,self.data())

    def test_unknown_lane_raises(self):
        b=board()
        b["lanes"][0]["lane"]="FOREIGN"
        with self.assertRaises(SnapshotError):
            join_readonly_views(b,self.data())

    def test_duplicate_lane_raises(self):
        b=board()
        b["lanes"][1]["lane"]="CORE"
        with self.assertRaises(SnapshotError):
            join_readonly_views(b,self.data())

    def test_handoff_cannot_claim_active(self):
        b=board()
        next(x for x in b["lanes"] if x["lane"]=="HANDOFF")["reported_phase"]="implementation"
        with self.assertRaises(SnapshotError):
            join_readonly_views(b,self.data())

    def test_fake_verified_ops_snapshot_refused(self):
        bad=self.data()
        bad["source"]["verified"]=True
        with self.assertRaises(SnapshotError):
            join_readonly_views(board(),bad)

    def test_ops_status_cannot_permit_publisher(self):
        bad=self.data()
        bad["actions_allowed"]["publish"]=True
        with self.assertRaises(SnapshotError):
            join_readonly_views(board(),bad)

    def test_cli_real_files_preserves_only_readonly_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"project.json"
            b=Path(td)/"board.json"
            p.write_text(json.dumps(sample()),encoding="utf-8")
            b.write_text(json.dumps(board()),encoding="utf-8")
            output=StringIO()
            with redirect_stdout(output):
                result=main(["--board",str(b),"--project",str(p)])
            self.assertEqual(result,0)
            decoded=json.loads(output.getvalue())
            self.assertEqual(decoded["kind"],"neurofactory_ops_ui_readonly_bundle")
            self.assertFalse(any(decoded["actions_allowed"].values()))
            self.assertEqual(set(Path(td).iterdir()),{p,b})

    def test_cli_rejects_duplicate_json_field(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"board.json"
            p.write_text('{"schema":1,"schema":2}',encoding="utf-8")
            error=StringIO()
            with redirect_stderr(error):
                code=main(["--board",str(p)])
            self.assertEqual(code,2)
            self.assertIn("OPS_UI_REFUSED",error.getvalue())


if __name__=="__main__":
    unittest.main()
