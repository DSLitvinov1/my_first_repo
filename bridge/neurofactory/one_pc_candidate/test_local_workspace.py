"""One-PC persistent local workspace integration tests, no release/queue or model execution."""
from __future__ import annotations
import http.client
from contextlib import closing
from http.server import HTTPServer
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
from threading import Thread
import unittest

from local_workspace import WorkspaceStore,handler,WorkspaceDenied

class RealLocalWorkspace(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="nf-local-workspace-")
        self.dir=Path(self.temp.name)
        self.data=self.dir/"data"
        self.store=WorkspaceStore(self.data)
        self.ui=Path(__file__).resolve().parent.parent/"control_ui"
        with socket.socket() as s:
            s.bind(("127.0.0.1",0))
            self.port=s.getsockname()[1]
        self.token="random-reviewer-test-token"
        self.server=HTTPServer(("127.0.0.1",self.port),
                              handler(self.store,self.ui,self.token,self.port))
        self.thread=Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=4)
        self.temp.cleanup()

    def http(self,method,path,body=None,headers=None):
        c=http.client.HTTPConnection("127.0.0.1",self.port,timeout=5)
        h=dict(headers or {})
        if body is not None and "Content-Type" not in h:
            h["Content-Type"]="application/json"
        if isinstance(body,dict):
            body=json.dumps(body).encode()
        if isinstance(body,str):
            body=body.encode()
        try:
            c.request(method,path,body=body,headers=h)
            resp=c.getresponse()
            raw=resp.read()
            content_type=resp.getheader("Content-Type")
            try:
                payload=json.loads(raw) if content_type.startswith("application/json") else raw
            except Exception:
                payload=raw
            return resp.status,payload,resp.getheaders()
        finally:
            c.close()

    def authorized(self,path,body):
        return self.http("POST",path,body,
                         {"X-NF-Local-Token":self.token})

    def project(self):
        status,obj,_=self.authorized("/api/projects",
                      {"name":"Локальный проект","description":"Test project"})
        self.assertEqual(status,201,obj)
        return obj

    def test_real_http_ui_bootstrap_and_status(self):
        status,html,headers=self.http("GET","/")
        self.assertEqual(status,200)
        self.assertIn(b"workspace.js",html)
        self.assertTrue(any(x[0].lower()=="content-security-policy" and
                            "connect-src 'self'" in x[1] for x in headers))
        self.assertEqual(self.http("GET","/workspace.js")[0],200)
        st,b,_=self.http("GET","/api/bootstrap")
        self.assertEqual(st,200);self.assertEqual(b["mode"],"LOCAL_DRAFT_ONLY")
        self.assertFalse(b["live_execution_allowed"])
        st,b,_=self.http("GET","/api/status")
        self.assertEqual(st,200);self.assertTrue(b["database_connected"])
        self.assertFalse(b["real_core_dispatch_enabled"])
        self.assertFalse(b["model_inference_enabled"])
        print("NF_LOCAL_WORKSPACE_HTTP_AND_DB=PASS_DRAFT_ONLY")

    def test_live_persistent_project_task_and_history(self):
        project=self.project()
        payload={"project_id":project["id"],
                 "objective":"Create harmless documentation without any real publication.",
                 "model_preference":"qwen3:0.6b"}
        st,task,_=self.authorized("/api/tasks",payload)
        self.assertEqual(st,201)
        self.assertEqual(task["state"],"DRAFT_PENDING_OWNER_AUTH")
        restart=WorkspaceStore(self.data)
        self.assertEqual(restart.list_projects()[0]["id"],project["id"])
        self.assertEqual(restart.list_tasks()[0]["id"],task["id"])
        self.assertEqual(len(restart.history()),2)
        self.assertEqual(self.http("GET","/api/tasks")[1]["tasks"][0]["state"],
                         "DRAFT_PENDING_OWNER_AUTH")
        print("NF_LOCAL_PROJECTS_TASKS_RESTART=PASS_NOT_QUEUED")

    def test_mutations_require_token_and_local_origin(self):
        data={"name":"Denied project","description":""}
        self.assertEqual(self.http("POST","/api/projects",data)[0],403)
        self.assertEqual(self.http("POST","/api/projects",data,
                        {"X-NF-Local-Token":self.token,"Origin":"https://evil.invalid"})[0],403)
        self.assertEqual(self.http("POST","/api/projects",data,
                        {"X-NF-Local-Token":"fake"})[0],403)
        self.assertEqual(self.http("PUT","/api/projects",data)[0],405)
        self.assertEqual(self.http("DELETE","/api/tasks")[0],405)
        self.assertEqual(self.http("POST","/api/execute",{},
                        {"X-NF-Local-Token":self.token})[0],404)
        self.assertEqual(len(self.store.list_projects()),0)
        print("NF_LOCAL_CSRF_AND_EXECUTE=DENIED")

    def test_input_limits_duplicates_unknown_project(self):
        self.assertEqual(self.authorized("/api/projects",
                         {"name":"x","description":""})[0],400)
        self.assertEqual(self.authorized("/api/projects",
                         '{"name":"Valid","name":"Override","description":""}')[0],400)
        bad={"project_id":"a"*32,"objective":"A harmless objective with length",
             "model_preference":"auto"}
        self.assertEqual(self.authorized("/api/tasks",bad)[0],400)
        proj=self.project()
        bad["project_id"]=proj["id"];bad["model_preference"]="remote-paid"
        self.assertEqual(self.authorized("/api/tasks",bad)[0],400)
        self.assertEqual(self.http("GET","/api/tasks?execute=1")[0],404)
        self.assertEqual(len(self.store.list_tasks()),0)

    def test_consistent_sqlite_backup_and_readback(self):
        original=self.project()
        st,result,_=self.authorized("/api/backup",{})
        self.assertEqual(st,201)
        backup=self.data/"backups"/result["filename"]
        self.assertTrue(backup.is_file())
        # Restore test in another untouched location. Never overwrite a live DB.
        recovered=self.dir/"recovered.sqlite3"
        recovered.write_bytes(backup.read_bytes())
        with closing(sqlite3.connect(recovered)) as con:
            name=con.execute("SELECT name FROM projects WHERE id=?",
                             (original["id"],)).fetchone()
        self.assertEqual(name,("Локальный проект",))
        print("NF_LOCAL_SQLITE_BACKUP_RESTORE=PASS_TEST_ONLY")

    def test_backup_rejects_injected_paths(self):
        self.project()
        self.assertEqual(self.authorized("/api/backup",{"path":"../bad"})[0],400)
        self.assertEqual(len(list((self.data/"backups").glob("*.sqlite3")))
                         if (self.data/"backups").exists() else 0,0)

if __name__=="__main__":
    unittest.main()
