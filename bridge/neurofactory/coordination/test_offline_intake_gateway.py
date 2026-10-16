"""Localhost HTTP smoke for authenticated coordinator candidate intake only."""
import hashlib
import hmac
import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from offline_intake_gateway import start_local_gateway

KEYS={"github_issues":b"G"*40,"authorized_api":b"A"*40,"signed_import":b"I"*40}
REG={"DSLitvinov1/my_first_repo":{
    "project_id":"nf-sandbox","owner_id":"operator-1","mode":"SEMI_AUTOMATIC",
    "profile":"web","sources":["github_issues","authorized_api","signed_import"],
    "preapproved":False}}

class LocalGatewayTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)/"offline_advisory.sqlite3"
        self.srv=start_local_gateway(db_path=self.path,secrets=KEYS,project_registry=REG)
        self.thread=threading.Thread(target=self.srv.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.url=f"http://127.0.0.1:{self.srv.server_port}"
    def close_server(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=3)
    def payload(self,source="authorized_api",*,event_id="work-1",kind="TASK_CREATED",repo="DSLitvinov1/my_first_repo"):
        if source=="github_issues":
            body={"action":"opened","repository":{"full_name":repo},
                  "issue":{"number":71,"state":"open","title":"Review local fixture"}}
            route="/intake/github/issues"
            headers={"X-GitHub-Event":"issues","X-GitHub-Delivery":str(uuid.uuid4())}
            sig="X-Hub-Signature-256"
        else:
            body={"schema":"neurofactory.intake.event.v1","event_id":event_id,
                  "kind":kind,"repository":repo,"project_id":"nf-sandbox",
                  "description":"Prepare one readonly test plan"}
            route="/intake/import" if source=="signed_import" else "/intake/api/tasks"
            headers={"X-NF-Delivery":uuid.uuid4().hex}
            sig="X-NF-Signature-256"
        raw=json.dumps(body,separators=(",",":")).encode()
        headers[sig]="sha256="+hmac.new(KEYS[source],raw,hashlib.sha256).hexdigest()
        headers["Content-Type"]="application/json"
        return route,raw,headers
    def send(self,route,raw,headers):
        req=urllib.request.Request(self.url+route,data=raw,headers=headers,method="POST")
        try:
            with urllib.request.urlopen(req,timeout=3) as res:
                return res.status,json.load(res)
        except urllib.error.HTTPError as e:
            return e.code,json.loads(e.read().decode("utf8"))
    def count(self):
        with sqlite3.connect(self.path) as conn:
            return conn.execute("SELECT count(*) FROM nf_coord_intake_v1").fetchone()[0]

    def test_localhost_only_binding(self):
        self.assertEqual(self.srv.server_address[0],"127.0.0.1")
    def test_real_signed_api_post_registered_no_dispatch(self):
        status,r=self.send(*self.payload())
        self.assertEqual(status,202)
        self.assertEqual(r["result"],"REGISTERED")
        self.assertEqual(r["advisory_status"],"PENDING_OWNER_APPROVAL")
        self.assertFalse(r["execution_allowed"])
        self.assertFalse(r["queue_write_allowed"])
        self.assertEqual(self.count(),1)
    def test_real_signed_github_issue_post(self):
        status,r=self.send(*self.payload("github_issues"))
        self.assertEqual(status,202)
        self.assertEqual(r["event_key"],"github-issue:DSLitvinov1/my_first_repo:71")
        self.assertFalse(r["paid_api_allowed"])
    def test_real_signed_project_import_stays_pending(self):
        status,r=self.send(*self.payload("signed_import",kind="PROJECT_CREATED"))
        self.assertEqual(status,202)
        self.assertEqual(r["advisory_status"],"PENDING_OWNER_APPROVAL")
        self.assertFalse(r["execution_allowed"])
    def test_exact_http_delivery_idempotent(self):
        pair=self.payload()
        self.assertEqual(self.send(*pair)[0],202)
        status,r=self.send(*pair)
        self.assertEqual(status,200)
        self.assertEqual(r["result"],"DUPLICATE")
        self.assertEqual(self.count(),1)
    def test_wrong_signature_http_rejected(self):
        route,raw,headers=self.payload()
        headers["X-NF-Signature-256"]="sha256="+"0"*64
        status,r=self.send(route,raw,headers)
        self.assertEqual(status,403)
        self.assertFalse(r["execution_allowed"])
    def test_wrong_project_unauthorized_http_rejected(self):
        route,raw,headers=self.payload()
        raw=raw.replace(b"nf-sandbox",b"fake-xxxx")
        status,r=self.send(route,raw,headers)
        self.assertEqual(status,403)
    def test_unknown_endpoint_no_mutation(self):
        status,r=self.send("/queue/execute",b"{}",{"Content-Type":"application/json"})
        self.assertEqual(status,404)
        self.assertFalse(self.path.stat().st_size > 1000000)
    def test_content_type_denied(self):
        route,raw,headers=self.payload()
        headers["Content-Type"]="text/plain"
        self.assertEqual(self.send(route,raw,headers)[0],415)
    def test_overlong_body_denied(self):
        route,raw,headers=self.payload()
        self.assertEqual(self.send(route,b"x"*32769,headers)[0],413)
    def test_get_does_not_list_private_tasks(self):
        try:
            urllib.request.urlopen(self.url+"/intake/api/tasks",timeout=3)
            self.fail("unsafe GET accepted")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code,405)

if __name__=="__main__":
    unittest.main()
