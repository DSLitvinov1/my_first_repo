"""Browser controller regression: sandbox, project ownership, CSRF, action boundaries."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from browser_control import BrowserController
from work_core import WorkStore, WorkDenied
from work_server import make_handler


class FakeProcess:
    def poll(self):
        return None


class BrowserCtrlTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.root = root
        self.store = WorkStore(root / "projects", root / "data")
        self.project = self.store.create_project("Браузерное тестирование", "empty")["id"]
        self.exe = root / "chrome"
        self.exe.write_text("unused", encoding="utf-8")
        self.browser = BrowserController(
            self.store, Path(__file__).parent,
            allowed_hosts=["example.org"], executable=self.exe)
        self.commands = []
        def start():
            self.browser.proc = FakeProcess()
        def rpc(data):
            self.commands.append(data)
            return {"url":"https://example.org/","title":"Example","width":1100,"height":720,
                    "image":"aGVsbG8="}
        self.browser._start = start
        self.browser._rpc = rpc
        self.browser._close_process = lambda: (
            setattr(self.browser, "proc", None),
            setattr(self.browser, "session", None))
        self.dns = patch("browser_control.socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443))])
        self.dns.start()
        self.addCleanup(self.dns.stop)

    def test_owner_approved_browser_mouse_and_close(self):
        started = self.browser.open(self.project, "https://example.org/")
        self.assertEqual(started["frame"]["title"], "Example")
        ident = started["session_id"]
        self.assertEqual(self.browser.status(self.project)["session"]["id"], ident)
        moved = self.browser.action(self.project, ident, "move", x=24, y=300)
        self.assertEqual(moved["frame"]["width"], 1100)
        self.browser.action(self.project, ident, "click", x=80, y=43)
        self.browser.action(self.project, ident, "scroll", delta=400)
        self.browser.action(self.project, ident, "back")
        self.assertEqual([x["op"] for x in self.commands],
                         ["open", "move", "click", "scroll", "back"])
        self.assertTrue(self.browser.close(self.project, ident)["closed"])
        self.assertIsNone(self.browser.status(self.project)["session"])
        with self.assertRaises(WorkDenied):
            self.browser.action(self.project, ident, "click", x=12, y=30)

    def test_denied_hosts_and_project_isolation(self):
        for site in ("http://example.org/","https://localhost/",
                     "https://127.0.0.1/", "https://other.org/",
                     "https://example.org:8443/", "https://example.org/#secret"):
            with self.subTest(site=site), self.assertRaises(WorkDenied):
                self.browser.open(self.project,site)
        self.assertEqual(self.commands,[])
        result=self.browser.open(self.project,"https://example.org/")
        other=self.store.create_project("Другой клиент", "empty")["id"]
        with self.assertRaisesRegex(WorkDenied,"PROJECT_SESSION_REFUSED"):
            self.browser.action(other,result["session_id"],"frame")
        with self.assertRaisesRegex(WorkDenied,"TOKEN_MISMATCH"):
            self.browser.action(self.project,"0"*32,"frame")

    def test_coordinates_and_commands_fail_closed(self):
        ident=self.browser.open(self.project,"https://example.org/")["session_id"]
        before=len(self.commands)
        cases=[("click",{"x":1100,"y":0}),("move",{"x":-2,"y":5}),
               ("click",{"x":True,"y":1}),("scroll",{"delta":999999}),
               ("scroll",{"delta":False}),("keyboard",{}),
               ("frame",{"url":"https://example.org"})]
        for op,options in cases:
            with self.subTest(op=op,options=options),self.assertRaises(WorkDenied):
                self.browser.action(self.project,ident,op,**options)
        self.assertEqual(len(self.commands),before)

    def test_private_dns_denied_without_worker(self):
        self.dns.stop()
        with patch("browser_control.socket.getaddrinfo",return_value=[
            (socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",443))]):
            with self.assertRaisesRegex(WorkDenied,"PRIVATE_NETWORK"):
                self.browser.open(self.project,"https://example.org/")
        self.assertEqual(self.commands,[])


class BrowserApiTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        store=WorkStore(root/"projects",root/"data")
        self.project=store.create_project("API браузера","empty")["id"]
        browser=BrowserController(store,Path(__file__).parent,allowed_hosts=())
        with socket.socket() as s:
            s.bind(("127.0.0.1",0))
            self.port=s.getsockname()[1]
        self.token="test-owner-only-token"
        self.server=ThreadingHTTPServer(("127.0.0.1",self.port),
                      make_handler(store,Path(__file__).parent,self.token,self.port,browser=browser))
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self,path,method="GET",data=None,token=None,origin=None):
        headers={"Host":f"127.0.0.1:{self.port}"}
        if method!="GET":
            headers.update({"Content-Type":"application/json",
                            "X-NF-Work-Token":self.token if token is None else token,
                            "Origin":f"http://127.0.0.1:{self.port}" if origin is None else origin})
        req=Request(f"http://127.0.0.1:{self.port}"+path,method=method,headers=headers,
                    data=json.dumps(data).encode("utf8") if data is not None else None)
        try:
            with urlopen(req,timeout=3) as r: return r.status,json.load(r)
        except HTTPError as e: return e.code,json.load(e)

    def test_browser_api_default_disabled_and_csrf(self):
        code,info=self.call("/api/browser/status?project_id="+self.project)
        self.assertEqual(code,200)
        self.assertFalse(info["configured"])
        params={"project_id":self.project,"url":"https://example.org"}
        code,_=self.call("/api/browser/open","POST",params,token="invalid")
        self.assertEqual(code,400)
        code,_=self.call("/api/browser/open","POST",params,origin="https://evil.example")
        self.assertEqual(code,400)
        code,data=self.call("/api/browser/open","POST",params)
        self.assertEqual(code,400)
        self.assertEqual(data["error"],"BROWSER_HOST_NOT_APPROVED")
        code,_=self.call("/api/browser/action","POST",
                         {"project_id":self.project,"session_id":"x",
                          "op":"click","x":20,"y":20,"unexpected":"payload"})
        self.assertEqual(code,400)


if __name__=="__main__":
    unittest.main(verbosity=2)
