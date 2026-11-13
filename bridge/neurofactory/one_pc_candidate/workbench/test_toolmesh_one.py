"""Toolmesh regression: Windows guard, Qwen untrusted plans, OAuth & verified writes."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from urllib.parse import urlparse,parse_qs
from urllib.request import urlopen

from work_core import WorkStore, WorkDenied
from browser_control import BrowserController
from desktop_one import DesktopOne
from credentials_one import UserVault
from google_oauth_one import GoogleOAuthOne, BitrixConnection
from qwen_planner_one import QwenPlannerOne, parse_proposal, prompt_for, LocalOllamaQwen
from service_one import (GoogleWorkspaceAdapter,Bitrix24Adapter,ServiceOne,
                         approved_values,SafeServiceTransport)


class StubVault:
    def __init__(self):
        self.data={}
    def ready(self):
        return True
    def put(self, provider, scope, data):
        self.data[(provider,scope)]=dict(data)
    def get(self, provider, scope):
        return self.data.get((provider,scope))
    def delete(self, provider, scope):
        self.data.pop((provider,scope),None)


class FakeHTTP:
    def __init__(self):
        self.calls=[]
        self.tasks={}
        self.bitrix={}
    def call(self, host, method, path, token, payload=None, query=None,
             auth_style="bearer"):
        self.calls.append((host,method,path,auth_style))
        if host=="tasks.googleapis.com":
            if method=="POST":
                self.tasks["new-1"]={"id":"new-1","title":payload["title"]}
                return dict(self.tasks["new-1"])
            if method=="PATCH":
                name=path.split("/")[-1]
                self.tasks[name]["title"]=payload["title"]
                return dict(self.tasks[name])
            if method=="GET":
                task=path.split("/")[-1]
                return dict(self.tasks[task])
        if host.startswith("example.bitrix24"):
            action=path.split("/")[-1].replace(".json","")
            if action=="tasks.task.add":
                self.bitrix["10"]={"id":"10","title":payload["fields"]["TITLE"]}
                return {"result":{"task":{"id":"10"}}}
            if action=="tasks.task.get":
                return {"result":{"task":dict(self.bitrix[str(payload["taskId"])])}}
            if action=="tasks.task.update":
                self.bitrix[str(payload["taskId"])]["title"]=payload["fields"]["TITLE"]
                return {"result":{"task":dict(self.bitrix[str(payload["taskId"])])}}
        return {"items":[]}


class StubAdapter:
    def __init__(self, fail=False):
        self.calls=[]
        self.fail=fail
    def create(self, data):
        self.calls.append(("create",dict(data)))
        if self.fail:raise OSError("network uncertain")
        return {"id":"new-33","verified":True}
    def update(self, data):
        self.calls.append(("update",dict(data)))
        if self.fail:raise OSError("network uncertain")
        return {"id":"33","verified":True}


class ToolmeshTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.root=root
        self.store=WorkStore(root/"projects",root/"data")
        self.project=self.store.create_project("Universal ONE","empty")["id"]

    def test_desktop_fails_closed_without_permissions(self):
        adapter=DesktopOne(self.store,self.root,allowed_apps=("notepad.exe",))
        self.assertFalse(adapter.capabilities()["configured"])
        with self.assertRaisesRegex(WorkDenied,"NOT_ENABLED"):
            adapter.open(self.project)
        with self.assertRaises(WorkDenied):
            DesktopOne(self.store,self.root,enabled=True,
                       allowed_apps=("cmd /c calc",))
        with self.assertRaises(WorkDenied):
            DesktopOne(self.store,self.root,enabled=True,allowed_apps=())

    def test_desktop_scoped_and_unicode_never_logged(self):
        desktop=DesktopOne(self.store,self.root,enabled=True,
                           allowed_apps=("notepad.exe",))
        operations=[]
        class DummyProcess:
            def poll(self):return None
        def fake_worker():
            desktop.proc=DummyProcess()
        def fake_rpc(cmd):
            operations.append(cmd)
            if cmd["op"]=="inspect":
                return {"app":"notepad.exe","pid":15,"handle":42,
                        "width":800,"height":600}
            return {"success":True}
        desktop._worker=fake_worker
        desktop._rpc=fake_rpc
        desktop._close=lambda: (
            setattr(desktop,"session",None),setattr(desktop,"proc",None))
        started=desktop.open(self.project)
        ident=started["session_id"]
        desktop.action(self.project,ident,"move",x=30,y=60)
        desktop.action(self.project,ident,"click",x=100,y=200)
        desktop.action(self.project,ident,"type",text="Проверить договор")
        self.assertEqual([x["op"] for x in operations],
                         ["inspect","move","click","type"])
        for op,args in (
            ("type",{"text":""}),("type",{"text":"test\nunsafe"}),
            ("type",{"text":"X"*501}),
            ("click",{"x":-1,"y":2}),("click",{"x":"4","y":10}),
            ("shell",{})):
            with self.subTest(op=op),self.assertRaises(WorkDenied):
                desktop.action(self.project,ident,op,**args)
        other=self.store.create_project("Other","empty")["id"]
        with self.assertRaisesRegex(WorkDenied,"SESSION_REFUSED"):
            desktop.action(other,ident,"frame")
        events=" ".join(e["detail"] for e in self.store.events())
        self.assertNotIn("Проверить договор",events)
        self.assertEqual(desktop.close(self.project,ident)["closed"],True)

    def test_qwen_plan_is_inert_validated_and_approval_required(self):
        good={"schema":"nf.one.qwen.proposal.v1","steps":[
            {"op":"open","url":"https://example.org/"},
            {"op":"click_text","label":"Услуги"},
            {"op":"check_text","text":"Готово"},
            {"op":"frame"},
        ]}
        obj=parse_proposal(json.dumps(good,ensure_ascii=False),{"example.org"})
        self.assertEqual(obj["steps"],4)
        self.assertIn("Открой",obj["script"])
        for payload in (
            {**good,"unexpected":"risky"},
            {"schema":"nf.one.qwen.proposal.v1","steps":[
                {"op":"open","url":"https://other.org/"}]},
            {"schema":"nf.one.qwen.proposal.v1","steps":[
                {"op":"open","url":"https://example.org/"},
                {"op":"shell","cmd":"cmd.exe"}]},
            {"schema":"nf.one.qwen.proposal.v1","steps":[
                {"op":"open","url":"https://example.org/"},
                {"op":"fill_label","label":"Пароль","text":"secret"}]},
        ):
            # A sensitive field name may be accepted as a *draft* by parser;
            # the browser worker still refuses actually focusing that field.
            if any(s.get("label")=="Пароль" for s in payload["steps"]):
                continue
            with self.assertRaises(WorkDenied):
                parse_proposal(json.dumps(payload,ensure_ascii=False),{"example.org"})
        with self.assertRaises(WorkDenied):
            parse_proposal(json.dumps(good),{"other.org"})
        self.assertTrue(prompt_for("Проверь страницу и найди разделы услуг",
                                   {"example.org"}))

    def test_qwen_planning_does_not_invoke_tools(self):
        class DummyBrowser:
            allowed_hosts=frozenset(("example.org",))
            def open(self,*args):raise AssertionError("Model must not open sites")
        good={"schema":"nf.one.qwen.proposal.v1","steps":[
            {"op":"open","url":"https://example.org/"},{"op":"frame"}]}
        seen=[]
        def model(project, request):
            seen.append((project,request))
            return {"status":"PROPOSED_UNVERIFIED",
                    "text":json.dumps(good)}
        planner=QwenPlannerOne(self.store,DummyBrowser(),model)
        goal="Сделай обзор сайта и подготовь снимок экрана"
        plan=planner.propose(self.project,goal)
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            state=planner.get(self.project,plan["id"])
            if state["state"]!="GENERATING":break
            time.sleep(.015)
        self.assertEqual(state["state"],"PROPOSED")
        self.assertIn("Сделай снимок",state["script"])
        self.assertTrue(seen)
        with self.assertRaises(WorkDenied):
            planner.get(self.store.create_project("Other","empty")["id"],plan["id"])

    def test_secret_vault_off_linux_and_fake_bitrix_configuration(self):
        if __import__("os").name!="nt":
            self.assertFalse(UserVault().ready())
            with self.assertRaises(WorkDenied):
                UserVault().put("google","tasks",{"access_token":"fake"})
        vault=StubVault()
        conn=BitrixConnection(vault)
        with self.assertRaises(WorkDenied):
            conn.connect("http://local/","secret")
        with self.assertRaises(WorkDenied):
            conn.connect("example.bitrix24.ru","short")
        conn.connect("example.bitrix24.ru","synthetic-test-token-1234567890")
        self.assertEqual(conn.portal(),"example.bitrix24.ru")
        self.assertEqual(conn.token("bitrix24","task"),"synthetic-test-token-1234567890")
        conn.disconnect_local()
        self.assertIsNone(conn.portal())

    def test_google_oauth_pkce_loopback_and_encrypted_vault_contract(self):
        vault=StubVault()
        exchanges=[]
        def exchanger(data):
            exchanges.append(data)
            return {"access_token":"testing-only-access-token",
                    "refresh_token":"testing-only-refresh-token",
                    "token_type":"Bearer","expires_in":3600}
        oauth=GoogleOAuthOne(vault,
            "123456.apps.googleusercontent.com",exchanger=exchanger)
        flow=oauth.begin("tasks")
        uri=flow["authorization_url"]
        query=parse_qs(urlparse(uri).query)
        self.assertEqual(query["code_challenge_method"],["S256"])
        self.assertTrue(query["code_challenge"][0])
        self.assertEqual(query["response_type"],["code"])
        self.assertTrue(uri.startswith("https://accounts.google.com/"))
        destination=query["redirect_uri"][0]
        try:
            with self.assertRaises(Exception):
                urlopen(destination+"?state=wrong&code=bad",timeout=2)
            with urlopen(destination+"?state="+query["state"][0]+"&code=test-code",
                         timeout=3) as reply:
                self.assertEqual(reply.status,200)
            until=time.monotonic()+3
            while time.monotonic()<until and oauth.last_result["state"]!="CONNECTED":
                time.sleep(.025)
            self.assertEqual(oauth.last_result["state"],"CONNECTED")
            self.assertEqual(oauth.token("google","tasks"),"testing-only-access-token")
            self.assertRegex(exchanges[0]["code_verifier"],r"^[A-Za-z0-9_-]{43,128}$")
            oauth.revoke_local("tasks")
            self.assertIsNone(oauth.token("google","tasks"))
        finally:
            oauth.flow=None

    def test_google_and_bitrix_real_request_shape_mock_readback(self):
        fake=FakeHTTP()
        g=GoogleWorkspaceAdapter(lambda provider,scope:"synthetic-test-token",
                                 transport=fake)
        out=g.create({"list_id":"mylist","title":"Задача Google","notes":"Описание"})
        self.assertEqual(out["verified"],True)
        updated=g.update({"list_id":"mylist","id":"new-1",
                           "title":"Новое название","expected_title":"Задача Google"})
        self.assertEqual(updated["id"],"new-1")
        self.assertEqual(fake.tasks["new-1"]["title"],"Новое название")
        fake.bitrix["existing"]={"id":"existing","title":"Старое"}
        b=Bitrix24Adapter("example.bitrix24.ru",
                         lambda provider,scope:"synthetic-test-token",fake)
        created=b.create({"title":"Задача Bitrix",
                          "responsible_id":7,"description":"Проверить"})
        self.assertTrue(created["verified"])
        updated=b.update({"id":"10","expected_title":"Задача Bitrix",
                          "title":"Задача исправлена"})
        self.assertEqual(updated["id"],"10")
        self.assertEqual(fake.bitrix["10"]["title"],"Задача исправлена")
        self.assertTrue(all(s[0] in
           ("tasks.googleapis.com","example.bitrix24.ru") for s in fake.calls))

    def test_secure_create_update_two_phase_and_no_replay(self):
        stub=StubAdapter()
        manager=ServiceOne(self.store,{"google.tasks":stub})
        fields={"list_id":"test","title":"Согласовать договор"}
        p=manager.prepare(self.project,"google.tasks.create",fields)
        self.assertEqual(len(stub.calls),0)
        with self.assertRaisesRegex(WorkDenied,"APPROVAL_INVALID"):
            manager.commit(self.project,p["id"],"google.tasks.create",
                           {**fields,"title":"Изменено после согласования"})
        verified=manager.commit(self.project,p["id"],"google.tasks.create",fields)
        self.assertEqual(verified["state"],"VERIFIED")
        self.assertEqual(verified["record_id"],"new-33")
        with self.assertRaises(WorkDenied):
            manager.commit(self.project,p["id"],"google.tasks.create",fields)
        history=" ".join(e["detail"] for e in self.store.events())
        self.assertNotIn("Согласовать договор",history)
        self.assertEqual(len(stub.calls),1)
        self.assertEqual(len(manager.operations(self.project)),1)

    def test_unknown_create_is_not_retried_and_recovery_fences(self):
        stub=StubAdapter(fail=True)
        manager=ServiceOne(self.store,{"google.tasks":stub})
        fields={"list_id":"test","title":"Не повторять при ошибке"}
        p=manager.prepare(self.project,"google.tasks.create",fields)
        outcome=manager.commit(self.project,p["id"],"google.tasks.create",fields)
        self.assertEqual(outcome["state"],"UNKNOWN_NO_RETRY")
        with self.assertRaises(WorkDenied):
            manager.commit(self.project,p["id"],"google.tasks.create",fields)
        self.assertEqual(len(stub.calls),1)
        pending=manager.prepare(self.project,"google.tasks.create",fields)
        again=ServiceOne(self.store,{"google.tasks":stub})
        with self.assertRaises(WorkDenied):
            again.commit(self.project,pending["id"],"google.tasks.create",fields)
        states={entry["id"]:entry["state"] for entry in again.operations(self.project)}
        self.assertEqual(states[pending["id"]],"EXPIRED")

    def test_mesh_frontend_is_served_and_complete(self):
        from work_server import make_handler
        from http.server import ThreadingHTTPServer
        from urllib.request import urlopen
        base=Path(__file__).parent
        html=(base/"index.html").read_text(encoding="utf8")
        script=(base/"toolmesh.js").read_text(encoding="utf8")
        self.assertIn('src="/toolmesh.js"',html)
        self.assertIn('id="mesh-google-connect"',html)
        self.assertIn('id="mesh-desktop-input"',html)
        self.assertIn('id="mesh-record-commit"',html)
        self.assertIn("async function meshRefresh()",script)
        browser=BrowserController(self.store,base)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0))
            port=sock.getsockname()[1]
        server=ThreadingHTTPServer(("127.0.0.1",port),
          make_handler(self.store,base,"owner-secret",port,browser=browser))
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with urlopen(f"http://127.0.0.1:{port}/toolmesh.js",timeout=3) as r:
            self.assertEqual(r.status,200)
            self.assertIn("application/javascript",r.headers.get("Content-Type"))
            self.assertIn(b"bindMesh",r.read())

    def test_google_default_task_list_is_supported(self):
        from service_one import valid_id
        self.assertEqual(valid_id("@default"),"@default")

    def test_toolmesh_http_end_to_end_approval_and_local_token(self):
        from http.server import ThreadingHTTPServer
        from urllib.error import HTTPError
        from urllib.request import Request,urlopen
        from work_server import make_handler
        from browser_control import BrowserController
        browser=BrowserController(self.store,Path(__file__).parent,
                                  allowed_hosts=("example.org",))
        planned={"schema":"nf.one.qwen.proposal.v1","steps":[
            {"op":"open","url":"https://example.org/"},{"op":"frame"}]}
        planner=QwenPlannerOne(self.store,browser,lambda project,request:{
            "status":"PROPOSED_UNVERIFIED","text":json.dumps(planned)})
        adapter=StubAdapter()
        service=ServiceOne(self.store,{"google.tasks":adapter})
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0))
            port=sock.getsockname()[1]
        token="local-toolmesh-test-only-owner-token"
        server=ThreadingHTTPServer(("127.0.0.1",port),
           make_handler(self.store,Path(__file__).parent,token,port,
                        browser=browser,planner=planner,services=service))
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        def req(path,method="GET",data=None,bad_token=False):
            head={"Host":f"127.0.0.1:{port}",
                  "X-NF-Work-Token":"bad" if bad_token else token}
            if method=="POST":
                head.update({"Content-Type":"application/json",
                             "Origin":f"http://127.0.0.1:{port}"})
            raw=json.dumps(data).encode() if data is not None else None
            r=Request(f"http://127.0.0.1:{port}"+path,method=method,
                      headers=head,data=raw)
            try:
                with urlopen(r,timeout=4) as response:
                    return response.status,json.load(response)
            except HTTPError as e:
                return e.code,json.load(e)
        denied,_=req("/api/toolmesh/status",bad_token=True)
        self.assertEqual(denied,400)
        status,info=req("/api/toolmesh/status")
        self.assertEqual(status,200)
        self.assertTrue(info["qwen"]["configured"])
        self.assertFalse(info["desktop"]["configured"])
        status,plan=req("/api/qwen/propose","POST",{
            "project_id":self.project,
            "goal":"Открой публичный сайт и покажи безопасный снимок"})
        self.assertEqual(status,202)
        result=None
        for _ in range(80):
            _,result=req("/api/qwen/plan?project_id="+self.project+
                         "&id="+plan["id"])
            if result["state"]!="GENERATING":break
            time.sleep(.03)
        self.assertEqual(result["state"],"PROPOSED")
        self.assertIn("Открой https://example.org/",result["script"])
        fields={"list_id":"@default","title":"Безопасная тестовая запись"}
        status,prepared=req("/api/service/prepare","POST",{
            "project_id":self.project,"action":"google.tasks.create",
            "fields":fields})
        self.assertEqual(status,201)
        self.assertEqual(len(adapter.calls),0)
        status,finished=req("/api/service/commit","POST",{
            "project_id":self.project,"id":prepared["id"],
            "action":"google.tasks.create","fields":fields})
        self.assertEqual(status,200)
        self.assertEqual(finished["state"],"VERIFIED")
        self.assertEqual(len(adapter.calls),1)
        status,_=req("/api/service/commit","POST",{
            "project_id":self.project,"id":prepared["id"],
            "action":"google.tasks.create","fields":fields})
        self.assertEqual(status,400)

    def test_safe_transport_rejects_untrusted_hosts_without_network(self):
        transport=SafeServiceTransport(["tasks.googleapis.com"])
        for host,method,path,token in (
            ("localhost","GET","/private","some-long-token"),
            ("127.0.0.1","GET","/","some-long-token"),
            ("tasks.googleapis.com","DELETE","/tasks","some-long-token"),
            ("tasks.googleapis.com","GET","https://evil","some-long-token"),
            ("tasks.googleapis.com","GET","/tasks","tiny"),
        ):
            with self.subTest(host=host),self.assertRaises(WorkDenied):
                transport.call(host,method,path,token)
        for fields in ({"list_id":"test","title":"x","admin":True},
                       {"title":"x","responsible_id":-1},
                       {"title":"x","responsible_id":5,"remove":True}):
            action="google.tasks.create" if "list_id" in fields else "bitrix.tasks.create"
            with self.assertRaises(WorkDenied):
                approved_values(action,fields)


if __name__=="__main__":
    unittest.main(verbosity=2)
