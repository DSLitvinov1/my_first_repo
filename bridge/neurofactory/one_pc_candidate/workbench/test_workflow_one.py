"""Work ONE multi-step execution tests: explicit approval, durability, privacy."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from work_core import WorkStore, WorkDenied
from work_server import make_handler
from workflow_one import WorkflowOne, parse_scenario


SCENARIO = ("\u041e\u0442\u043a\u0440\u043e\u0439 https://example.org/\n"
            "\u041d\u0430\u0436\u043c\u0438 \u00ab\u0423\u0441\u043b\u0443\u0433\u0438\u00bb\n"
            "\u041d\u0430\u043f\u0435\u0447\u0430\u0442\u0430\u0439 \u0432 \u043f\u043e\u043b\u0435 \u00ab\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435\u00bb \u00ab\u041f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u00bb\n"
            "\u041f\u0440\u043e\u0432\u0435\u0440\u044c \u0442\u0435\u043a\u0441\u0442 \u00ab\u0413\u043e\u0442\u043e\u0432\u043e\u00bb\n"
            "\u0421\u0434\u0435\u043b\u0430\u0439 \u0441\u043d\u0438\u043c\u043e\u043a")


class FakeBrowser:
    def __init__(self):
        self.allowed_hosts = frozenset(["example.org"])
        self.calls = []
        self.session = "a"*32
        self.fail_at = None
        self.started = threading.Event()
        self.resume = threading.Event()
        self.block = False

    def open(self, project, url):
        self.calls.append(("open",url))
        self.started.set()
        if self.block:
            assert self.resume.wait(timeout=6)
        return {"session_id":self.session,
                "frame":{"image":"aGVsbG8=","title":"Тестовый сайт"}}

    def action(self, project, session, op, **kwargs):
        assert session == self.session
        self.calls.append((op, kwargs))
        if op == self.fail_at:
            raise WorkDenied("SYNTHETIC_FAIL")
        return {"session_id":session,
                "frame":{"image":"aGVsbG8=","title":"Тестовая страница"}}

    def close(self, project, session):
        self.calls.append(("close", session))
        return {"closed":True}


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path=Path(self.tmp.name)
        self.store=WorkStore(path/"projects",path/"data")
        self.project=self.store.create_project("Сценарии","empty")["id"]
        self.browser=FakeBrowser()
        self.runner=WorkflowOne(self.store,self.browser)

    def until(self,run_id, states, timeout=6):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            run=self.runner.get(self.project,run_id)
            if run["state"] in states:return run
            time.sleep(.025)
        self.fail("TIMEOUT_WAITING_FOR_SCENARIO")

    def test_parse_verified_russian_commands(self):
        steps=parse_scenario(SCENARIO,{"example.org"})
        self.assertEqual([x["op"] for x in steps],
            ["open","click_text","fill_label","check_text","frame"])
        self.assertEqual(steps[2]["text"],"Проверить договор")
        self.assertEqual(steps[0]["host"],"example.org")
        for value in ("Открой http://example.org", "Открой https://other.org",
                      "Открой https://localhost",
                      "Запусти powershell",
                      "Открой https://example.org\nОтправь форму",
                      "Открой https://example.org\nНажми «Удалить»\n"
                      "Открой https://example.org"):
            with self.subTest(value=value),self.assertRaises(WorkDenied):
                parse_scenario(value,{"example.org"})

    def test_durable_approval_execution_and_privacy(self):
        preview=self.runner.prepare(self.project,SCENARIO)
        self.assertEqual(len(preview["steps"]),5)
        run_id=preview["run_id"]
        with self.assertRaisesRegex(WorkDenied,"APPROVAL_INVALID"):
            self.runner.start(self.project,run_id,SCENARIO+" ")
        outcome=self.runner.start(self.project,run_id,SCENARIO)
        self.assertEqual(outcome["state"],"ACCEPTED")
        after=self.until(run_id,{"DONE"})
        self.assertEqual([s["state"] for s in after["steps"]],["DONE"]*5)
        self.assertEqual([x[0] for x in self.browser.calls],
            ["open","click_text","fill_label","check_text","frame","close"])
        self.assertEqual(self.runner.get(self.project,run_id,with_image=True)["frame"]["image"],
                         "aGVsbG8=")
        with self.assertRaisesRegex(WorkDenied,"APPROVAL_INVALID|REPLAY_REFUSED"):
            self.runner.start(self.project,run_id,SCENARIO)
        with self.store.db() as c:
            dbtext=" ".join(str(tuple(x)) for x in c.execute(
                "SELECT * FROM one_workflows").fetchall())
            dbtext+=" ".join(str(tuple(x)) for x in c.execute(
                "SELECT * FROM one_workflow_steps").fetchall())
        self.assertNotIn("Проверить договор",dbtext)
        self.assertNotIn("Проверить договор",
                         " ".join(x["detail"] for x in self.store.events()))

    def test_failure_stops_remaining_steps_and_is_not_replayed(self):
        self.browser.fail_at="click_text"
        pre=self.runner.prepare(self.project,SCENARIO)
        self.runner.start(self.project,pre["run_id"],SCENARIO)
        after=self.until(pre["run_id"],{"FAILED"})
        self.assertEqual(after["steps"][0]["state"],"DONE")
        self.assertEqual(after["steps"][1]["state"],"FAILED")
        self.assertEqual(after["steps"][2]["state"],"READY")
        self.assertEqual(self.browser.calls[-1][0],"close")
        self.assertEqual(after["error"],"ONE_STEP_FAILED_NO_AUTO_RETRY")

    def test_one_job_at_a_time_and_other_project_isolation(self):
        self.browser.block=True
        p=self.runner.prepare(self.project,SCENARIO)
        self.runner.start(self.project,p["run_id"],SCENARIO)
        self.assertTrue(self.browser.started.wait(timeout=3))
        try:
            second=self.runner.prepare(self.project,SCENARIO)
            with self.assertRaisesRegex(WorkDenied,"BUSY"):
                self.runner.start(self.project,second["run_id"],SCENARIO)
            other=self.store.create_project("Чужой проект","empty")["id"]
            with self.assertRaisesRegex(WorkDenied,"NOT_FOUND"):
                self.runner.get(other,p["run_id"])
        finally:
            self.browser.resume.set()
        self.assertEqual(self.until(p["run_id"],{"DONE"})["state"],"DONE")

    def test_recovery_invalidates_unfinished_and_pending(self):
        pending=self.runner.prepare(self.project,SCENARIO)
        running=self.runner.prepare(self.project,SCENARIO)
        with self.store.db() as c:
            c.execute("UPDATE one_workflows SET state='RUNNING' WHERE id=?",
                      (running["run_id"],))
        restarted=WorkflowOne(self.store,self.browser)
        self.assertEqual(restarted.get(self.project,pending["run_id"])["state"],"EXPIRED")
        self.assertEqual(restarted.get(self.project,running["run_id"])["state"],
                         "UNKNOWN_NO_RETRY")
        self.assertFalse(restarted.capabilities()["model_can_execute_tools"])


class ScenarioHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.store=WorkStore(root/"projects",root/"data")
        self.project=self.store.create_project("API сценария","empty")["id"]
        self.browser=FakeBrowser()
        workflow=WorkflowOne(self.store,self.browser)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0))
            self.port=sock.getsockname()[1]
        self.token="owner-secret-for-local-test"
        self.server=ThreadingHTTPServer(
            ("127.0.0.1",self.port),
            make_handler(self.store,Path(__file__).parent,
                         self.token,self.port,browser=self.browser,workflow=workflow))
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self,path,method="GET",data=None,token=None,origin=None):
        headers={"Host":f"127.0.0.1:{self.port}","X-NF-Work-Token":
                 self.token if token is None else token}
        if method!="GET":
            headers.update({"Content-Type":"application/json",
                    "Origin":f"http://127.0.0.1:{self.port}" if origin is None else origin})
        req=Request(f"http://127.0.0.1:{self.port}"+path,
                    data=json.dumps(data).encode() if data is not None else None,
                    headers=headers,method=method)
        try:
            with urlopen(req,timeout=4) as response:
                return response.status,json.load(response)
        except HTTPError as e:
            return e.code,json.load(e)

    def test_http_approval_csrf_and_snapshot(self):
        payload={"project_id":self.project,"script":SCENARIO}
        code,_=self.call("/api/one/prepare","POST",payload,token="wrong")
        self.assertEqual(code,400)
        code,_=self.call("/api/one/prepare","POST",payload,origin="http://other.invalid")
        self.assertEqual(code,400)
        code,p=self.call("/api/one/prepare","POST",payload)
        self.assertEqual(code,201)
        code,started=self.call("/api/one/start","POST",
            {"project_id":self.project,"run_id":p["run_id"],"script":SCENARIO})
        self.assertEqual(code,202)
        self.assertEqual(started["state"],"ACCEPTED")
        uri="/api/one/run?project_id="+self.project+"&run_id="+p["run_id"]
        for _ in range(120):
            code,run=self.call(uri)
            if run["state"]!="RUNNING":break
            time.sleep(.04)
        self.assertEqual(run["state"],"DONE")
        self.assertIn("frame",run)
        denied,_=self.call(uri,token="invalid")
        self.assertEqual(denied,400)
        code,_=self.call("/api/one/runs?project_id="+self.project)
        self.assertEqual(code,200)


class AssetRegressionTests(unittest.TestCase):
    def test_stylesheet_and_ui_files_are_not_cross_written(self):
        base=Path(__file__).parent
        css=(base/"styles.css").read_text("utf8")
        markup=(base/"index.html").read_text("utf8")
        script=(base/"app.js").read_text("utf8")
        self.assertTrue(css.lstrip().startswith(":root{"))
        self.assertNotIn("<!doctype",css.lower())
        self.assertIn(".one-scenario",css)
        self.assertIn('id="one-instructions"',markup)
        self.assertIn('id="one-prepare"',markup)
        self.assertIn("function onePrepare()",script)


if __name__=="__main__":
    unittest.main(verbosity=2)
