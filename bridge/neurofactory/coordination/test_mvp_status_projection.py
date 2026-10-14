"""Small targeted contract checks; no network, Qwen, GitHub writes or runner restarts."""
import json
from pathlib import Path
import tempfile
import unittest
from mvp_status_projection import projection, InvalidSnapshot, read_fixture

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
