"""Focused ephemeral localhost Ollama probe: fake HTTP only, never genuine weights."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

from local_workspace import (
    WorkspaceStore, WorkspaceDenied, QWEN_PROBE_PROMPT,
    local_models, probe_local_qwen,
)

class FakeOllama(BaseHTTPRequestHandler):
    generate_calls=0
    request_model=None
    mode="valid"

    def json_reply(self,obj,status=200):
        data=json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path!="/api/tags":
            self.json_reply({"error":"not found"},404)
            return
        self.json_reply({"models":[{"name":"qwen3:0.6b","digest":"a"*64}]})

    def do_POST(self):
        if self.path!="/api/generate":
            self.json_reply({"error":"not found"},404)
            return
        size=int(self.headers.get("Content-Length","0"))
        if not 0<size<=4096:
            self.json_reply({"error":"bad size"},400)
            return
        value=json.loads(self.rfile.read(size))
        type(self).generate_calls+=1
        type(self).request_model=value.get("model")
        assert value["prompt"]==QWEN_PROBE_PROMPT
        assert value["stream"] is False
        assert value["options"]["num_predict"]==128
        assert value["think"] is False
        if self.mode=="bad":
            self.json_reply({"model":"qwen3:0.6b","done":False,"response":""})
        elif self.mode=="oversize":
            self.json_reply({"model":"qwen3:0.6b","done":True,"response":"x"*20000})
        else:
            self.json_reply({"model":"qwen3:0.6b","done":True,
                             "response":"Четыре. ТЕСТОВАЯ ЗАГЛУШКА"})

    def log_message(self,*args):
        pass


class IsolatedQwenProbe(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory(prefix="nf-model-probe-test-")
        self.directory=Path(self.temp.name)/"data"
        self.store=WorkspaceStore(self.directory)
        FakeOllama.generate_calls=0
        FakeOllama.request_model=None
        FakeOllama.mode="valid"
        self.http=HTTPServer(("127.0.0.1",0),FakeOllama)
        self.port=self.http.server_address[1]
        self.thread=Thread(target=self.http.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def test_explicit_fake_http_reply_is_never_weight_attestation(self):
        result=probe_local_qwen("auto",port=self.port)
        self.assertEqual(result["reported_model"],"qwen3:0.6b")
        self.assertEqual(result["response_sha256"],hashlib.sha256(
            "Четыре. ТЕСТОВАЯ ЗАГЛУШКА".encode("utf-8")).hexdigest())
        self.assertEqual(result["status"],"OLLAMA_LOCAL_RESPONSE_UNATTESTED")
        for k in ("model_provenance_attested","real_weights_independently_verified",
                  "core_dispatch_allowed","host_write_allowed",
                  "automatic_retry_allowed","publication_allowed"):
            self.assertIs(result[k],False)
        self.assertEqual(FakeOllama.generate_calls,1)
        self.assertEqual(FakeOllama.request_model,"qwen3:0.6b")
        self.store.record_model_check(result)
        reopened=WorkspaceStore(self.directory)
        checks=reopened.model_checks()
        self.assertEqual(len(checks),1)
        self.assertEqual(checks[0]["response_sha256"],result["response_sha256"])
        self.assertEqual(checks[0]["provenance_attested"],0)
        self.assertEqual(reopened.history()[0]["event"],
                         "OLLAMA_LOCAL_RESPONSE_NOT_ATTESTED")
        self.assertFalse(reopened.diag()["model_inference_enabled"])
        print("NF_QWEN_PROBE_FAKE_HTTP_UNATTESTED_PERSISTED=PASS_TEST_ONLY")

    def test_refuses_noninstalled_or_unknown_model_before_generation(self):
        for value in ("qwen2.5-coder:1.5b","remote-llama",None,True):
            with self.subTest(value=value),self.assertRaises(WorkspaceDenied):
                probe_local_qwen(value,port=self.port)
        self.assertEqual(FakeOllama.generate_calls,0)
        self.assertEqual(self.store.model_checks(),[])

    def test_invalid_model_reply_never_persisted(self):
        FakeOllama.mode="bad"
        with self.assertRaises(WorkspaceDenied):
            probe_local_qwen("auto",port=self.port)
        FakeOllama.mode="oversize"
        with self.assertRaises(WorkspaceDenied):
            probe_local_qwen("auto",port=self.port)
        self.assertEqual(self.store.model_checks(),[])
        print("NF_QWEN_PROBE_INCOMPLETE_AND_OVERSIZE_REJECTED=YES")

    def test_untrusted_positive_authority_flags_refused_before_db(self):
        probe=probe_local_qwen("auto",port=self.port)
        for flag in ("model_provenance_attested",
                     "real_weights_independently_verified",
                     "core_dispatch_allowed","host_write_allowed",
                     "automatic_retry_allowed","publication_allowed"):
            changed=dict(probe,**{flag:True})
            with self.subTest(flag=flag),self.assertRaises(WorkspaceDenied):
                self.store.record_model_check(changed)
        self.assertEqual(len(self.store.model_checks()),0)

    def test_old_sqlite_schema_migrates_without_erasing_projects(self):
        self.store.create_project({"name":"Существующий проект","description":""})
        with self.store.connect() as con:
            con.execute("PRAGMA user_version=1")
        reopened=WorkspaceStore(self.directory)
        self.assertEqual(reopened.list_projects()[0]["name"],"Существующий проект")
        with reopened.connect() as con:
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0],3)
        self.assertEqual(reopened.model_checks(),[])

    def test_future_unknown_schema_denied(self):
        with self.store.connect() as con:
            con.execute("PRAGMA user_version=100")
        with self.assertRaises(WorkspaceDenied):
            WorkspaceStore(self.directory)
        print("NF_QWEN_PROBE_SQLITE_FUTURE_VERSION_FAIL_CLOSED=YES")

if __name__=="__main__":
    unittest.main()
