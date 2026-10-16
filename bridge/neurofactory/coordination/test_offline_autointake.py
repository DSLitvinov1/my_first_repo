"""Targeted disposable SQLite + signed-event coordinator intake tests. No dispatch."""
import hashlib
import hmac
import json
import sqlite3
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from offline_autointake import IntakeRejected, ingest_signed_event

KEYS={"github_issues":b"G"*40,"authorized_api":b"A"*40,"signed_import":b"I"*40}
PROJECTS={"DSLitvinov1/my_first_repo":{
    "project_id":"nf-sandbox","owner_id":"operator-1",
    "mode":"AUTOMATIC","profile":"web",
    "sources":["github_issues","authorized_api","signed_import"],"preapproved":True}}

class IntakeTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path=Path(temp.name)/"advisory.sqlite3"
        self.con=sqlite3.connect(self.path, timeout=5)
        self.addCleanup(self.con.close)
    def sign(self,source,body,*,delivery=None,raw=None):
        if raw is None:
            raw=json.dumps(body,ensure_ascii=False,separators=(",",":")).encode("utf8")
        key="X-Hub-Signature-256" if source=="github_issues" else "X-NF-Signature-256"
        headers={key:"sha256="+hmac.new(KEYS[source],raw,hashlib.sha256).hexdigest()}
        if source=="github_issues":
            headers["X-GitHub-Event"]="issues"
            headers["X-GitHub-Delivery"]=delivery or str(uuid.uuid4())
        else:
            headers["X-NF-Delivery"]=delivery or uuid.uuid4().hex
        return raw,headers
    def gh(self,*,number=17,repo="DSLitvinov1/my_first_repo",title="Improve isolated button",delivery=None):
        body={"action":"opened","repository":{"full_name":repo},
              "issue":{"number":number,"state":"open","title":title}}
        return self.sign("github_issues",body,delivery=delivery)
    def api(self,*,event_id="task-001",kind="TASK_CREATED",repo="DSLitvinov1/my_first_repo",
            project_id="nf-sandbox",delivery=None,source="authorized_api"):
        body={"schema":"neurofactory.intake.event.v1","event_id":event_id,
              "kind":kind,"repository":repo,"project_id":project_id,
              "description":"Prepare a bounded offline preview"}
        return self.sign(source,body,delivery=delivery)
    def ingest(self,source="github_issues",pair=None,registry=PROJECTS):
        raw,headers=self.gh() if pair is None else pair
        return ingest_signed_event(self.con,source=source,raw=raw,headers=headers,
                                   secrets=KEYS,project_registry=registry)
    def count(self):
        return self.con.execute("SELECT COUNT(*) FROM nf_coord_intake_v1").fetchone()[0]

    def test_native_github_issue_is_registered_without_execution(self):
        result=self.ingest(pair=self.gh(number=20))
        self.assertEqual(result["result"],"REGISTERED")
        self.assertEqual(result["profile"],"web")
        self.assertEqual(result["mode"],"AUTOMATIC")
        self.assertEqual(result["advisory_status"],"ADVISORY_READY_NO_EXECUTION")
        for k in ("execution_allowed","queue_write_allowed","publication_allowed","paid_api_allowed"):
            self.assertIs(result[k],False)
        self.assertEqual(self.count(),1)
    def test_exact_delivery_retry_dedupes(self):
        pair=self.gh()
        self.ingest(pair=pair)
        self.assertEqual(self.ingest(pair=pair)["result"],"DUPLICATE")
        self.assertEqual(self.count(),1)
    def test_conflicting_delivery_for_same_issue_denied(self):
        self.ingest(pair=self.gh(number=23))
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=self.gh(number=23))
        self.assertEqual(self.count(),1)
    def test_second_issue_not_a_duplicate(self):
        self.ingest(pair=self.gh(number=23))
        self.ingest(pair=self.gh(number=24))
        self.assertEqual(self.count(),2)
    def test_hmac_tamper_denied(self):
        raw,headers=self.gh()
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=(raw.replace(b"button",b"attack"),headers))
    def test_hmac_missing_denied(self):
        raw,headers=self.gh()
        headers.pop("X-Hub-Signature-256")
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=(raw,headers))
    def test_spoofed_approval_flags_cannot_enter_api_schema(self):
        raw,headers=self.api()
        body=json.loads(raw)
        body["owner_approval"]=True
        raw,headers=self.sign("authorized_api",body)
        with self.assertRaises(IntakeRejected):
            self.ingest("authorized_api",(raw,headers))
    def test_api_registration_and_signed_import(self):
        for source,identifier in (("authorized_api","task-one"),("signed_import","task-two")):
            pair=self.api(source=source,event_id=identifier)
            r=self.ingest(source,pair)
            self.assertFalse(r["execution_allowed"])
        self.assertEqual(self.count(),2)
    def test_import_new_project_remains_advisory(self):
        pair=self.api(kind="PROJECT_CREATED",event_id="proj-one",source="signed_import")
        r=self.ingest("signed_import",pair)
        self.assertEqual(r["result"],"REGISTERED")
        self.assertFalse(r["queue_write_allowed"])
    def test_unknown_project_pending_owner_approval(self):
        r=self.ingest(pair=self.gh(repo="OtherUser/new_repo"))
        self.assertIsNone(r["project_id"])
        self.assertEqual(r["advisory_status"],"PENDING_OWNER_APPROVAL")
        self.assertFalse(r["execution_allowed"])
    def test_unapproved_registered_project_pending(self):
        reg={"DSLitvinov1/my_first_repo":dict(PROJECTS["DSLitvinov1/my_first_repo"],preapproved=False)}
        r=self.ingest(pair=self.gh(),registry=reg)
        self.assertEqual(r["advisory_status"],"PENDING_OWNER_APPROVAL")
    def test_api_forged_project_rejected(self):
        with self.assertRaises(IntakeRejected):
            self.ingest("authorized_api",self.api(project_id="wrong-project"))
    def test_source_not_allowlisted_rejected(self):
        entry=dict(PROJECTS["DSLitvinov1/my_first_repo"],sources=["authorized_api"])
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=self.gh(),registry={"DSLitvinov1/my_first_repo":entry})
    def test_unknown_event_source_rejected(self):
        with self.assertRaises(IntakeRejected):
            self.ingest(source="slack")
    def test_github_edit_ignored(self):
        body={"action":"edited","repository":{"full_name":"DSLitvinov1/my_first_repo"},
              "issue":{"number":1,"state":"open","title":"Test"}}
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=self.sign("github_issues",body))
    def test_duplicate_json_keys_denied(self):
        raw=b'{"action":"opened","action":"opened","repository":{"full_name":"DSLitvinov1/my_first_repo"},"issue":{"number":1,"state":"open","title":"Test"}}'
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=self.sign("github_issues",{},raw=raw))
    def test_bool_issue_number_denied(self):
        body={"action":"opened","repository":{"full_name":"DSLitvinov1/my_first_repo"},
              "issue":{"number":True,"state":"open","title":"Test"}}
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=self.sign("github_issues",body))
    def test_large_event_denied(self):
        raw,headers=self.sign("github_issues",{},raw=b"x"*32769)
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=(raw,headers))
    def test_bad_issue_title_denied(self):
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=self.gh(title="Line\nBreak"))
    def test_payload_reuses_delivery_for_different_issue_denied(self):
        d=str(uuid.uuid4())
        self.ingest(pair=self.gh(number=1,delivery=d))
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=self.gh(number=2,delivery=d))
        self.assertEqual(self.count(),1)
    def test_parallel_duplicate_delivery_yields_single_row(self):
        pair=self.gh(number=44)
        self.con.close()
        # Separate SQLite connections and journal locks exercise true durable dedup.
        results=[]
        guard=threading.Lock()
        def run():
            con=sqlite3.connect(self.path,timeout=5,isolation_level=None)
            try:
                result=ingest_signed_event(con,source="github_issues",raw=pair[0],
                      headers=pair[1],secrets=KEYS,project_registry=PROJECTS)
                with guard: results.append(result["result"])
            finally: con.close()
        workers=[threading.Thread(target=run) for _ in range(2)]
        for x in workers:x.start()
        for x in workers:x.join()
        self.assertEqual(sorted(results),["DUPLICATE","REGISTERED"])
        self.con=sqlite3.connect(self.path)
        self.assertEqual(self.count(),1)

    def test_api_unhashable_event_kind_denied(self):
        raw,_=self.api()
        body=json.loads(raw)
        body["kind"]=["TASK_CREATED"]
        with self.assertRaises(IntakeRejected):
            self.ingest("authorized_api",self.sign("authorized_api",body))
    def test_registry_bad_mode_and_profile_types_denied(self):
        for field in ("mode","profile"):
            reg=dict(PROJECTS["DSLitvinov1/my_first_repo"])
            reg[field]=["AUTOMATIC"]
            with self.subTest(field=field),self.assertRaises(IntakeRejected):
                self.ingest(pair=self.gh(),registry={"DSLitvinov1/my_first_repo":reg})
    def test_invalid_unicode_rejected_before_sqlite(self):
        body={"action":"opened","repository":{"full_name":"DSLitvinov1/my_first_repo"},
              "issue":{"number":32,"state":"open","title":"Bad\\ud800"}}
        with self.assertRaises(IntakeRejected):
            self.ingest(pair=self.sign("github_issues",body))
if __name__=="__main__":
    unittest.main()
