import tempfile
import unittest
from pathlib import Path
from private_flow_one import PrivateFlowOne
from work_core import WorkStore,WorkDenied

SCRIPT="Открой https://example.org/\nПроверь текст «Example Domain»\nСделай снимок"
ACTION="google.tasks.create"
FIELDS={"list_id":"@default","title":"Тестовая задача"}

class FakeWorkflow:
    def __init__(self):
        self.browser=type("B",(),{"allowed_hosts":frozenset(("example.org",))})()
        self.current="RUNNING"
        self.calls=[]
    def prepare(self, project, script):
        self.calls.append("prepare")
        return {"run_id":"a"*32}
    def start(self, project, run_id, script):
        self.calls.append("start")
    def get(self, project, run_id):
        return {"state":self.current}

class FakeService:
    def __init__(self,fail=False):
        self.calls=[]
        self.fail=fail
    def prepare(self, project, action, fields):
        self.calls.append("prepare")
        return {"id":"b"*32}
    def commit(self,project,rid,action,fields):
        self.calls.append("commit")
        if self.fail:raise OSError("network unknown")
        return {"state":"VERIFIED"}

class PrivateFlowTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store=WorkStore(Path(tmp.name)/"p",Path(tmp.name)/"d")
        self.project=self.store.create_project("One private test","empty")["id"]
        self.workflow=FakeWorkflow()
        self.service=FakeService()
        self.flow=PrivateFlowOne(self.store,self.workflow,self.service)

    def test_two_approvals_and_verified_write(self):
        p=self.flow.prepare(self.project,SCRIPT,ACTION,FIELDS)
        rid=p["id"]
        self.assertEqual(self.service.calls,[])
        with self.assertRaises(WorkDenied):
            self.flow.confirm(self.project,rid,SCRIPT,ACTION,FIELDS)
        self.flow.start(self.project,rid,SCRIPT,ACTION,FIELDS)
        self.assertEqual(self.flow.status(self.project,rid)["state"],"READING")
        self.workflow.current="DONE"
        self.assertEqual(self.flow.status(self.project,rid)["state"],"AWAITING_WRITE")
        self.assertEqual(self.service.calls,[])
        r=self.flow.confirm(self.project,rid,SCRIPT,ACTION,FIELDS)
        self.assertEqual(r["state"],"VERIFIED")
        self.assertEqual(self.service.calls,["prepare","commit"])
        with self.assertRaises(WorkDenied):
            self.flow.confirm(self.project,rid,SCRIPT,ACTION,FIELDS)

    def test_tampered_fields_denied(self):
        rid=self.flow.prepare(self.project,SCRIPT,ACTION,FIELDS)["id"]
        altered={**FIELDS,"title":"Другая задача"}
        with self.assertRaises(WorkDenied):
            self.flow.start(self.project,rid,SCRIPT,ACTION,altered)
        self.flow.start(self.project,rid,SCRIPT,ACTION,FIELDS)
        self.workflow.current="DONE"
        with self.assertRaises(WorkDenied):
            self.flow.confirm(self.project,rid,SCRIPT,ACTION,altered)

    def test_browser_writes_prohibited(self):
        script="Открой https://example.org/\nНажми «Удалить»"
        with self.assertRaisesRegex(WorkDenied,"READ_ONLY"):
            self.flow.prepare(self.project,script,ACTION,FIELDS)
        script="Открой https://example.org/\nНапечатай в поле «Пароль» «пароль»"
        with self.assertRaisesRegex(WorkDenied,"READ_ONLY"):
            self.flow.prepare(self.project,script,ACTION,FIELDS)

    def test_failure_cannot_write(self):
        rid=self.flow.prepare(self.project,SCRIPT,ACTION,FIELDS)["id"]
        self.flow.start(self.project,rid,SCRIPT,ACTION,FIELDS)
        self.workflow.current="FAILED"
        self.assertEqual(self.flow.status(self.project,rid)["state"],"FAILED")
        with self.assertRaises(WorkDenied):
            self.flow.confirm(self.project,rid,SCRIPT,ACTION,FIELDS)
        self.assertEqual(self.service.calls,[])

    def test_ambiguous_write_never_retries(self):
        self.flow.services=FakeService(fail=True)
        rid=self.flow.prepare(self.project,SCRIPT,ACTION,FIELDS)["id"]
        self.flow.start(self.project,rid,SCRIPT,ACTION,FIELDS)
        self.workflow.current="DONE"
        r=self.flow.confirm(self.project,rid,SCRIPT,ACTION,FIELDS)
        self.assertEqual(r["state"],"UNKNOWN_NO_RETRY")
        with self.assertRaises(WorkDenied):
            self.flow.confirm(self.project,rid,SCRIPT,ACTION,FIELDS)
        self.assertEqual(self.flow.services.calls,["prepare","commit"])

    def test_restart_drops_all_pending_approvals(self):
        rid=self.flow.prepare(self.project,SCRIPT,ACTION,FIELDS)["id"]
        restarted=PrivateFlowOne(self.store,self.workflow,self.service)
        with self.assertRaises(WorkDenied):
            restarted.start(self.project,rid,SCRIPT,ACTION,FIELDS)

    def test_isolation_by_project(self):
        rid=self.flow.prepare(self.project,SCRIPT,ACTION,FIELDS)["id"]
        other=self.store.create_project("Other","empty")["id"]
        with self.assertRaises(WorkDenied):
            self.flow.status(other,rid)

    def test_local_api_requires_owner_and_two_explicit_calls(self):
        import json
        import socket
        import threading
        from http.server import ThreadingHTTPServer
        from urllib.error import HTTPError
        from urllib.request import Request,urlopen
        from work_server import make_handler
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0))
            port=sock.getsockname()[1]
        token="private-flow-test-owner-token"
        server=ThreadingHTTPServer(("127.0.0.1",port),
           make_handler(self.store,Path(__file__).parent,token,port,
                        private_flow=self.flow))
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        def call(path,method="GET",data=None,auth=True):
            headers={"Host":f"127.0.0.1:{port}"}
            if auth:headers["X-NF-Work-Token"]=token
            if method=="POST":
                headers["Content-Type"]="application/json"
                headers["Origin"]=f"http://127.0.0.1:{port}"
            raw=json.dumps(data).encode() if data is not None else None
            req=Request(f"http://127.0.0.1:{port}"+path,method=method,
                        data=raw,headers=headers)
            try:
                with urlopen(req,timeout=3) as response:
                    return response.status,json.load(response)
            except HTTPError as e:
                return e.code,json.load(e)
        data={"project_id":self.project,"script":SCRIPT,
              "action":ACTION,"fields":FIELDS}
        bad,_=call("/api/private/flow/prepare","POST",data,auth=False)
        self.assertEqual(bad,400)
        code,preview=call("/api/private/flow/prepare","POST",data)
        self.assertEqual(code,201)
        rid=preview["id"]
        code,refusal=call("/api/private/flow/confirm","POST",{**data,"id":rid})
        self.assertEqual(code,400)
        code,started=call("/api/private/flow/start","POST",{**data,"id":rid})
        self.assertEqual(code,202)
        self.workflow.current="DONE"
        qs=f"?project_id={self.project}&id={rid}"
        code,status=call("/api/private/flow/status"+qs)
        self.assertEqual(code,200)
        self.assertEqual(status["state"],"AWAITING_WRITE")
        denied,_=call("/api/private/flow/status"+qs,auth=False)
        self.assertEqual(denied,400)
        self.assertEqual(self.service.calls,[])
        code,verified=call("/api/private/flow/confirm","POST",{**data,"id":rid})
        self.assertEqual(code,200)
        self.assertEqual(verified["state"],"VERIFIED")
        self.assertEqual(self.service.calls,["prepare","commit"])
        code,_=call("/api/private/flow/confirm","POST",{**data,"id":rid})
        self.assertEqual(code,400)

    def test_invalid_action_denied(self):
        with self.assertRaises(WorkDenied):
            self.flow.prepare(self.project,SCRIPT,"shell.execute",FIELDS)

if __name__=="__main__":
    unittest.main()
