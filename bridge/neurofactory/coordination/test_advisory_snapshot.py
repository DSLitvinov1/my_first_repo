"""Targeted UI projection / no authority regression cases on actual intake records."""
import hashlib
import hmac
import json
import sqlite3
import unittest

from advisory_snapshot import AdvisorySnapshotError, preview_advisory_cards
from offline_autointake import ingest_signed_event

SECRET=b"A"*40
REPO="DSLitvinov1/my_first_repo"
OTHER="AnotherOrg/other_repo"
REG={
 REPO:{"project_id":"nf-sandbox","owner_id":"operator-1","mode":"AUTOMATIC",
       "profile":"web","sources":["authorized_api"],"preapproved":True},
 OTHER:{"project_id":"other-sandbox","owner_id":"operator-2","mode":"MANUAL",
        "profile":"crm","sources":["authorized_api"],"preapproved":False},
}
class AdvisorySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.con=sqlite3.connect(":memory:",isolation_level=None)
        self.addCleanup(self.con.close)
    def event(self,event_id="event-001",*,repo=REPO,delivery=None,kind="TASK_CREATED"):
        body={"schema":"neurofactory.intake.event.v1",
              "event_id":event_id,"kind":kind,"repository":repo,
              "project_id":REG[repo]["project_id"],
              "description":"A safe read only project task"}
        raw=json.dumps(body,sort_keys=True).encode("utf8")
        sig="sha256="+hmac.new(SECRET,raw,hashlib.sha256).hexdigest()
        return ingest_signed_event(
            self.con,source="authorized_api",raw=raw,
            headers={"X-NF-Signature-256":sig,"X-NF-Delivery":delivery or event_id},
            secrets={"authorized_api":SECRET},project_registry=REG)
    def cards(self,*,repos=None,limit=20,before=None,project=None):
        return preview_advisory_cards(
           self.con,allowed_repositories=[REPO] if repos is None else repos,
           limit=limit,before_rowid=before,project_id=project)
    def test_real_signed_input_projects_into_readonly_card(self):
        self.event()
        result=self.cards()
        self.assertEqual(len(result["cards"]),1)
        card=result["cards"][0]
        self.assertEqual(card["advisory_status"],"ADVISORY_READY_NO_EXECUTION")
        self.assertEqual(card["profile"],"web")
        for k in ("authentic_owner_approval_verified","execution_allowed",
                  "queue_write_allowed","publication_allowed","paid_api_allowed"):
            self.assertIs(card[k],False)
        self.assertFalse(result["live_execution_allowed"])
        self.assertFalse(result["approval_from_snapshot_allowed"])
    def test_foreign_repo_filtered_out(self):
        self.event("one")
        self.event("other",repo=OTHER)
        self.assertEqual(len(self.cards()["cards"]),1)
        self.assertEqual(self.cards()["cards"][0]["repository"],REPO)
    def test_absent_repo_scoping_is_denied(self):
        self.event()
        for value in ([],(),[REPO,REPO],"*",["*"],[True],None):
            with self.subTest(value=str(value)[:30]),self.assertRaises(AdvisorySnapshotError):
                preview_advisory_cards(self.con,allowed_repositories=value)
    def test_real_cursor_pages_are_stable(self):
        for i in range(7):
            self.event(f"event-{i:03d}")
        first=self.cards(limit=3)
        self.assertEqual(len(first["cards"]),3)
        self.assertTrue(first["has_more"])
        second=self.cards(limit=3,before=first["next_before_rowid"])
        self.assertTrue(second["has_more"])
        last=self.cards(limit=3,before=second["next_before_rowid"])
        self.assertEqual(len(last["cards"]),1)
        self.assertFalse(last["has_more"])
        events=[x["event_key"] for part in (first,second,last) for x in part["cards"]]
        self.assertEqual(len(set(events)),7)
    def test_nonnumeric_or_large_limit_denied(self):
        self.event()
        for value in (0,51,True,False,1.0,"10",-2):
            with self.subTest(v=value),self.assertRaises(AdvisorySnapshotError):
                self.cards(limit=value)
    def test_invalid_cursor_denied(self):
        self.event()
        for value in (0,-1,True,3.0,"7",2**63):
            with self.subTest(v=value),self.assertRaises(AdvisorySnapshotError):
                self.cards(before=value)
    def test_project_filter_is_enforced(self):
        self.event()
        self.assertEqual(len(self.cards(project="nf-sandbox")["cards"]),1)
        self.assertEqual(len(self.cards(project="other-sandbox")["cards"]),0)
    def test_sql_like_project_filter_cannot_inject(self):
        self.event()
        for text in ("%","nf-sandbox' OR 1=1","\x00",""):
            with self.subTest(value=repr(text)),self.assertRaises(AdvisorySnapshotError):
                self.cards(project=text)
    def test_empty_table_returns_empty_snapshot(self):
        from offline_autointake import init_advisory_store
        init_advisory_store(self.con)
        r=self.cards()
        self.assertEqual(r["cards"],[])
        self.assertFalse(r["has_more"])
    def test_corrupted_status_rejects_entire_projection(self):
        self.event()
        self.con.execute("UPDATE nf_coord_intake_v1 SET advisory_status='EXECUTION_APPROVED'")
        with self.assertRaises(AdvisorySnapshotError):
            self.cards()
    def test_corrupted_project_profile_rejects(self):
        for field,value in (("profile","root"),("mode","LIVE"),("kind","DELETE_PROJECT"),
                            ("description","bad\nmalicious")):
            self.con.execute("DELETE FROM nf_coord_intake_v1") if self.con.execute(
                  "SELECT name FROM sqlite_master WHERE name='nf_coord_intake_v1'").fetchone() else None
            self.event()
            self.con.execute(f"UPDATE nf_coord_intake_v1 SET {field}=?",(value,))
            with self.subTest(field=field),self.assertRaises(AdvisorySnapshotError):
                self.cards()
    def test_no_sqlite_mutation_from_readonly_projection(self):
        self.event()
        initial=list(self.con.execute("SELECT * FROM nf_coord_intake_v1"))
        self.cards()
        self.cards(limit=1,project="nf-sandbox")
        self.assertEqual(list(self.con.execute("SELECT * FROM nf_coord_intake_v1")),initial)
    def test_after_signed_duplicate_cards_stay_unique(self):
        first=self.event()
        second=self.event()
        self.assertEqual((first["result"],second["result"]),("REGISTERED","DUPLICATE"))
        self.assertEqual(len(self.cards()["cards"]),1)
    def test_missing_store_denied_without_creating_new_table(self):
        with self.assertRaises(AdvisorySnapshotError):
            self.cards()
        self.assertEqual(list(self.con.execute("SELECT name FROM sqlite_master")),[])
    def test_readonly_response_carries_no_raw_signatures(self):
        self.event()
        encoded=json.dumps(self.cards(),ensure_ascii=False)
        self.assertNotIn("fencing_token",encoded)
        self.assertNotIn("signature",encoded)
        self.assertNotIn("owner_id",encoded)
        self.assertNotIn("SECRET",encoded)

if __name__=="__main__":
    unittest.main()
