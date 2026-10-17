"""Small targeted contract checks; no network, Qwen, GitHub writes or runner restarts."""
import json
import io
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from mvp_status_projection import projection, projection_v2, InvalidSnapshot, read_fixture, main

def sample(lane="CORE", phase="implementation"):
    return {
      "lane": lane, "repository": "DSLitvinov1/my_first_repo",
      "branch": "neurofactory-core-queue-owned-20261013",
      "sha": "a"*40,
      "issue_url": "https://github.com/DSLitvinov1/my_first_repo/issues/9",
      "phase": phase
    }
class ProjectionTests(unittest.TestCase):
    def test_unknown_stays_unknown_and_not_authorized(self):
        r=projection([])
        self.assertEqual(len(r["lanes"]), 9)
        self.assertEqual(r["lanes"][0]["reported_phase"], "unknown")
        self.assertFalse(r["external_execution_allowed"])
        self.assertFalse(r["external_publication_allowed"])
        self.assertEqual(r["cost_authorized_usd"], 0)
    def test_present_candidate_does_not_create_approval(self):
        r=projection([sample()])
        self.assertEqual(r["lanes"][0]["reported_phase"], "implementation")
        self.assertEqual(r["lanes"][0]["evidence_status"], "not_verified")
        self.assertFalse(r["lanes"][0]["release_allowed"])
    def test_v2_shows_trusted_host_without_breaking_v1(self):
        old=projection([])
        new=projection_v2([])
        self.assertEqual((old["schema"],len(old["lanes"])),(1,9))
        self.assertNotIn("TRUSTED_HOST",[x["lane"] for x in old["lanes"]])
        self.assertEqual((new["schema"],len(new["lanes"])),(2,10))
        host=new["lanes"][1]
        self.assertEqual(host["lane"],"TRUSTED_HOST")
        self.assertEqual((host["reported_phase"],host["evidence_status"]),("unknown","not_verified"))
        self.assertIs(host["release_allowed"],False)
        for key in ("external_execution_allowed","external_publication_allowed","automatic_retry_allowed"):
            self.assertIs(new[key],False)

    def test_v2_host_candidate_is_not_approved(self):
        row=sample(lane="TRUSTED_HOST",phase="blocked")
        row["branch"]="neurofactory-trusted-host-owned-20261015"
        row["issue_url"]="https://github.com/DSLitvinov1/my_first_repo/issues/14"
        output=projection_v2([row])
        host=output["lanes"][1]
        self.assertEqual(host["reported_phase"],"blocked")
        self.assertEqual(host["evidence_status"],"not_verified")
        self.assertIs(host["release_allowed"],False)
        self.assertEqual(output["provenance"],"self_reported_git_refs_not_attested")

    def test_v2_rejects_wrong_host_issue(self):
        row=sample(lane="TRUSTED_HOST")
        for url in ("https://github.com/DSLitvinov1/my_first_repo/issues/9",
                    "https://github.com/DSLitvinov1/my_first_repo/pull/12",
                    "https://github.com/DSLitvinov1/lesson3.1/pull/558"):
            with self.subTest(url=url),self.assertRaises(InvalidSnapshot):
                projection_v2([row | {"issue_url":url}])

    def test_v2_rejects_duplicate_and_oversized_board(self):
        row=sample(lane="TRUSTED_HOST")
        row["issue_url"]="https://github.com/DSLitvinov1/my_first_repo/pull/15"
        with self.assertRaises(InvalidSnapshot): projection_v2([row,row])
        with self.assertRaises(InvalidSnapshot): projection_v2([row]*11)

    def test_v2_cli_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"snapshot.json"
            p.write_text("[]",encoding="utf-8")
            with redirect_stdout(io.StringIO()) as output:
                main([str(p)])
            self.assertEqual(json.loads(output.getvalue())["schema"],1)
            with redirect_stdout(io.StringIO()) as output:
                main([str(p),"--with-trusted-host"])
            report=json.loads(output.getvalue())
            self.assertEqual((report["schema"],len(report["lanes"])),(2,10))

    def test_v2_pinned_snapshot_displays_blocked_trusted_host(self):
        fixture=Path(__file__).with_name("mvp_status_snapshot_v2_20261018.json")
        rows=read_fixture(fixture)
        report=projection_v2(rows)
        self.assertEqual(report["schema"],2)
        self.assertEqual(len(report["lanes"]),10)
        self.assertEqual(len(rows),8)
        host=next(x for x in report["lanes"] if x["lane"]=="TRUSTED_HOST")
        self.assertEqual(host["reported_phase"],"blocked")
        self.assertEqual(host["commit"],"02972424eefabcd61d21100611e3eace4c6c3d5e")
        self.assertEqual(host["evidence_status"],"not_verified")
        self.assertIs(host["release_allowed"],False)
        self.assertTrue(all(x["release_allowed"] is False for x in report["lanes"]))
        self.assertEqual(report["provenance"],"self_reported_git_refs_not_attested")
        self.assertIs(report["external_execution_allowed"],False)
        self.assertIs(report["external_publication_allowed"],False)
        self.assertIs(report["automatic_retry_allowed"],False)
        self.assertEqual(report["cost_authorized_usd"],0)
        self.assertEqual(next(x for x in report["lanes"] if x["lane"]=="REVIEW")["reported_phase"],"unknown")
        handoff=next(x for x in report["lanes"] if x["lane"]=="HANDOFF")
        self.assertEqual(handoff["reported_phase"],"paused")

    def test_duplicate_lane_rejected(self):
        with self.assertRaises(InvalidSnapshot): projection([sample(), sample()])
    def test_spoofed_release_denied(self):
        with self.assertRaises(InvalidSnapshot): projection([sample()|{"release_allowed":True}])
    def test_disallowed_phase_denied(self):
        for phase in ("APPROVED", "verified_done", "released"):
            with self.subTest(phase=phase), self.assertRaises(InvalidSnapshot):
                projection([sample(phase=phase)])
    def test_handoff_must_remain_paused(self):
        with self.assertRaises(InvalidSnapshot): projection([sample(lane="HANDOFF")])
        p=projection([sample(lane="HANDOFF", phase="paused")])
        self.assertEqual(p["lanes"][7]["reported_phase"], "paused")
    def test_cross_repo_url_denied(self):
        with self.assertRaises(InvalidSnapshot):
            projection([sample()|{"issue_url":"https://github.com/DSLitvinov1/lesson3.1/pull/542"}])
    def test_path_or_unknown_branch_denied(self):
        with self.assertRaises(InvalidSnapshot): projection([sample()|{"branch":"../../main"}])
    def test_pinned_sha_required(self):
        with self.assertRaises(InvalidSnapshot): projection([sample()|{"sha":"main"}])
    def test_duplicate_json_and_oversize_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"fixture.json"
            p.write_text('[{"a":1,"a":2}]',encoding="utf-8")
            with self.assertRaises(InvalidSnapshot): read_fixture(p)
            p.write_bytes(b"x"*32769)
            with self.assertRaises(InvalidSnapshot): read_fixture(p)
if __name__=="__main__": unittest.main()
