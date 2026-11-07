"""Focused Neurofactory Work regression: durable state, sandbox and local auth."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import socket
import tempfile
import threading
import unittest
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer

from work_core import WorkStore,WorkDenied,sha
from work_server import make_handler

HERE=Path(__file__).resolve().parent

class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.root=root/"projects"
        self.data=root/"data"
        self.store=WorkStore(self.root,self.data)
        self.project=self.store.create_project("Мой веб-сайт","web")["id"]
    def test_actual_file_edit_and_durable_restart(self):
        initial=self.store.read(self.project,"index.html")
        updated=self.store.save(self.project,"index.html",initial["text"]+"<!-- reviewed -->\n",initial["sha256"])
        self.assertFalse(updated["unchanged"])
        self.assertEqual(self.store.read(self.project,"index.html")["sha256"],updated["sha256"])
        with self.assertRaises(WorkDenied):
            self.store.save(self.project,"index.html","stale",initial["sha256"])
        restored=self.store.undo(self.project,"index.html",updated["sha256"])
        self.assertEqual(restored["sha256"],initial["sha256"])
        reloaded=WorkStore(self.root,self.data)
        self.assertEqual(reloaded.read(self.project,"index.html")["sha256"],initial["sha256"])
        self.assertEqual(len(reloaded.files(self.project)),4)
        self.assertGreaterEqual(len(reloaded.versions(self.project,"index.html")),2)
    def test_project_sandbox_rejects_traversal_and_executable(self):
        for name in ("../outside.txt","sub/../oops.py","C:/escape.py","sub\\evil.js",
                     ".env","secrets.exe","folder/CON.txt",
                     "/absolute.js","other/.git/config"):
            with self.subTest(name=name):
                with self.assertRaises(WorkDenied):
                    self.store.save(self.project,name,"unsafe",None)
        outside=Path(self.tmp.name)/"outside.txt"
        outside.write_text("DO_NOT_MODIFY",encoding="utf-8")
        link=self.root/self.project/"linked.txt"
        try:
            link.symlink_to(outside)
        except (OSError,NotImplementedError):
            pass
        else:
            with self.assertRaises(WorkDenied):
                self.store.save(self.project,"linked.txt","BAD",None)
        self.assertEqual(outside.read_text("utf-8"),"DO_NOT_MODIFY")
    def test_unknown_write_fences_all_future_changes(self):
        with self.store.db() as c:
            c.execute("INSERT INTO writes VALUES(?,?,?,?,?,?,?)",
                      ("a"*32,self.project,"unknown.py",None,"c"*64,"PENDING",100))
            c.commit()
        after=WorkStore(self.root,self.data)
        self.assertEqual(after.status()["uncertain_writes"],1)
        with self.assertRaisesRegex(WorkDenied,"UNKNOWN_PREVIOUS_WRITE"):
            after.save(self.project,"fresh.py","print(1)",None)
        self.assertFalse((self.root/self.project/"fresh.py").exists())
    def test_model_draft_one_attempt_and_no_auto_apply(self):
        task=self.store.create_task(self.project,"Документация","Подготовь короткий список изменений для локального приложения.")
        self.store.reserve_generation(task["id"])
        concurrent=self.store.create_task(self.project,"Вторая модель","Ещё одна задача, которая должна дождаться завершения первой.")
        with self.assertRaisesRegex(WorkDenied,"MODEL_BUSY_ONE_GENERATION_AT_A_TIME"):
            self.store.reserve_generation(concurrent["id"])
        with self.assertRaises(WorkDenied):
            self.store.reserve_generation(task["id"])
        suggestion="Qwen: только предложение, файл не создан."
        self.store.finish_generation(task["id"],{
            "status":"PROPOSED_UNVERIFIED","model":"qwen3.5:9b",
            "text":suggestion,"content_sha256":sha(suggestion.encode("utf-8"))
        })
        self.assertEqual(self.store.task(task["id"])["state"],"REVIEW")
        self.assertFalse((self.root/self.project/"suggestion.md").exists())
        interrupted=concurrent
        self.store.reserve_generation(interrupted["id"])
        restored=WorkStore(self.root,self.data)
        self.assertEqual(restored.task(interrupted["id"])["state"],"UNKNOWN_NO_RETRY")
        with self.assertRaises(WorkDenied):
            restored.reserve_generation(interrupted["id"])
    def test_templates_and_event_history(self):
        self.store.create_project("Питон-проект","python")
        items=self.store.projects()
        self.assertEqual(len(items),2)
        self.assertIn("PROJECT_CREATED",[e["kind"] for e in self.store.events()])

class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.store=WorkStore(root/"projects",root/"data")
        sock=socket.socket()
        sock.bind(("127.0.0.1",0))
        self.port=sock.getsockname()[1]
        sock.close()
        self.token="test-only-random-local-header"
        self.server=ThreadingHTTPServer(("127.0.0.1",self.port),
                         make_handler(self.store,HERE,self.token,self.port))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
    def request(self,path,method="GET",body=None,token=None,origin=None,raw=None):
        header={"Host":"127.0.0.1:"+str(self.port)}
        if method!="GET":
            header.update({"X-NF-Work-Token":token or self.token,
                           "Origin":origin or "http://127.0.0.1:"+str(self.port),
                           "Content-Type":"application/json"})
        payload=raw if raw is not None else json.dumps(body).encode("utf-8") if body is not None else None
        request=Request("http://127.0.0.1:"+str(self.port)+path,
                        method=method,headers=header,data=payload)
        try:
            with urlopen(request,timeout=5) as r:
                return r.status,r.read().decode("utf-8")
        except HTTPError as e:
            return e.code,e.read().decode("utf-8")
    def test_http_creation_readback_and_local_security(self):
        code,body=self.request("/")
        self.assertEqual(code,200)
        self.assertIn(self.token,body)
        self.assertIn("Нейрозавод Work",body)
        denied,_=self.request("/api/projects","POST",
                              {"name":"Bad project","template":"empty"},token="wrong")
        self.assertEqual(denied,400)
        denied,_=self.request("/api/projects","POST",
                              {"name":"Bad project","template":"empty"},
                              origin="https://untrusted.example")
        self.assertEqual(denied,400)
        ok,reply=self.request("/api/projects","POST",{"name":"Личный проект","template":"web"})
        self.assertEqual(ok,201)
        ident=json.loads(reply)["id"]
        ok,reply=self.request("/api/projects/"+ident+"/files")
        self.assertEqual(ok,200)
        self.assertEqual(len(json.loads(reply)["files"]),4)
        ok,reply=self.request("/api/projects/"+ident+"/tasks","POST",
                              {"title":"Первый запрос","goal":"Подготовить простой план работы с файлами проекта."})
        self.assertEqual(ok,201)
        forbidden,_=self.request("/api/execute","POST",{})
        self.assertEqual(forbidden,400)
        invalid,_=self.request("/api/projects","POST",raw=b'{"name":"x","name":"duplicate","template":"empty"}')
        self.assertEqual(invalid,400)
        self.assertEqual(len(self.store.projects()),1)
        ok,reply=self.request("/api/projects/"+ident+"/file?path=index.html")
        self.assertEqual(ok,200)
        existing=json.loads(reply)
        ok,reply=self.request("/api/projects/"+ident+"/file","PUT",
                              {"path":"index.html","text":"Reviewed content",
                               "previous_sha":existing["sha256"]})
        self.assertEqual(ok,200)

if __name__=="__main__":
    unittest.main(verbosity=2)
