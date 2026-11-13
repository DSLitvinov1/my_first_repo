"""One-shot live inference + real browser + isolated test account E2E.

This is NOT a Google or Bitrix account. A loopback-only, short-lived test
service with its own bearer key proves the approval, HTTP write and
read-after-write contract without touching third-party customer data.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import threading
import time
from urllib.request import Request, urlopen

from browser_control import BrowserController
from llama_connector_one import LlamaCppQwenOne
from qwen_planner_one import QwenPlannerOne
from service_one import ServiceOne
from work_core import WorkStore
from workflow_one import WorkflowOne


def test_account(data_dir):
    token=secrets.token_urlsafe(32)
    connection=sqlite3.connect(str(data_dir/"test_task_account.sqlite3"))
    connection.execute("CREATE TABLE tasks(id TEXT PRIMARY KEY,title TEXT NOT NULL)")
    connection.commit()
    connection.close()
    class Handler(BaseHTTPRequestHandler):
        def _answer(self, status, result):
            payload=json.dumps(result).encode("utf8")
            self.send_response(status)
            self.send_header("Content-Type","application/json")
            self.send_header("Cache-Control","no-store")
            self.send_header("Content-Length",str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _auth(self):
            if self.headers.get("Authorization")!="Bearer "+token:
                self._answer(403,{"error":"NOT_AUTHORIZED"})
                return False
            return True

        def do_POST(self):
            if not self._auth():return
            if self.path!="/v1/tasks":
                self._answer(404,{"error":"NO_ACTION"});return
            try:
                size=int(self.headers.get("Content-Length","0"))
                if not 2<=size<=3000:raise ValueError()
                body=json.loads(self.rfile.read(size).decode("utf8"))
                title=body.get("title")
                if type(title) is not str or not title.startswith("NF-ONE-TEST-") or len(title)>180:
                    raise ValueError()
                ident=secrets.token_hex(12)
                with sqlite3.connect(str(data_dir/"test_task_account.sqlite3")) as db:
                    db.execute("INSERT INTO tasks VALUES (?,?)",(ident,title))
                self._answer(201,{"id":ident,"title":title})
            except (ValueError,TypeError):
                self._answer(400,{"error":"INVALID_TEST_TASK"})

        def do_GET(self):
            if not self._auth():return
            if not self.path.startswith("/v1/tasks/"):
                self._answer(404,{"error":"NOT_FOUND"});return
            ident=self.path.removeprefix("/v1/tasks/")
            with sqlite3.connect(str(data_dir/"test_task_account.sqlite3")) as db:
                result=db.execute("SELECT title FROM tasks WHERE id=?",(ident,)).fetchone()
            if result:self._answer(200,{"id":ident,"title":result[0]})
            else:self._answer(404,{"error":"NOT_FOUND"})

        def log_message(self,*args):
            pass

    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()

    class Adapter:
        def ready(self):return True
        def _call(self,method,url,payload=None):
            data=json.dumps(payload).encode("utf8") if payload else None
            request=Request("http://127.0.0.1:"+str(server.server_address[1])+url,
                data=data,method=method,headers={
                    "Authorization":"Bearer "+token,
                    "Content-Type":"application/json",
                })
            with urlopen(request,timeout=4) as res:
                return json.load(res)
        def create(self,fields):
            title=fields["title"]
            record=self._call("POST","/v1/tasks",{"title":title})
            observed=self._call("GET","/v1/tasks/"+record["id"])
            if observed.get("title")!=title:
                raise ValueError("READBACK_FAILED")
            return {"id":record["id"],"verified":True}
        def update(self,fields):
            raise ValueError("DEMO_UPDATE_NOT_IMPLEMENTED")

    return server, Adapter()


def await_result(check, expected_terminal, limit):
    start=time.monotonic()
    while time.monotonic()-start<limit:
        result=check()
        if result["state"] in expected_terminal:
            return result
        time.sleep(.2)
    raise RuntimeError("UNKNOWN_NO_RETRY")


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--key-file",type=Path,required=True)
    parser.add_argument("--browser-executable",type=Path,required=True)
    parser.add_argument("--approved-synthetic-test",action="store_true")
    args=parser.parse_args()
    if not args.approved_synthetic_test:
        raise SystemExit("Explicit test-only approval flag required")
    model=LlamaCppQwenOne(key_file=args.key_file)
    if not model.available():
        raise SystemExit("LIVE_QWEN_NOT_READY")
    print("STAGE_A_REAL_QWEN_READY",flush=True)

    with tempfile.TemporaryDirectory(prefix="nf-one-e2e-") as temp:
        root=Path(temp)
        store=WorkStore(root/"workspace",root/"data")
        project=store.create_project("Authorized synthetic test","empty")["id"]
        browser=BrowserController(store,Path(__file__).resolve().parent,
                                  allowed_hosts=("www.wikipedia.org",),
                                  executable=args.browser_executable)
        plan=QwenPlannerOne(store,browser,model_fn=model)
        workflow=WorkflowOne(store,browser)
        service, adapter=test_account(root)
        service_manager=ServiceOne(store,{"google.tasks":adapter})
        start=time.monotonic()
        try:
            instruction=("Открой публичную страницу https://www.wikipedia.org/, "
                         "проверь наличие текста Wikipedia, сделай снимок и "
                         "ничего не отправляй, не меняй.")
            proposed=plan.propose(project,instruction)
            result=await_result(lambda:plan.get(project,proposed["id"]),
                                {"PROPOSED","UNKNOWN_NO_RETRY"},120)
            if result["state"]!="PROPOSED":
                print("STAGE_B_QWEN_PLAN_REJECTED",result.get("error"),flush=True)
                raise SystemExit(3)
            print("STAGE_B_QWEN_PLAN_VALID",result["steps"],flush=True)
            # In this isolated test only, explicit CLI flag authorizes a
            # read-only public browser scenario generated by the model.
            prepared=workflow.prepare(project,result["script"])
            workflow.start(project,prepared["run_id"],result["script"])
            completed=await_result(
                lambda:workflow.get(project,prepared["run_id"],with_image=True),
                {"DONE","FAILED","UNKNOWN_NO_RETRY"},35)
            if completed["state"]!="DONE":
                print("STAGE_C_BROWSER_FAILED",completed["state"],
                      [(x["action"],x["state"]) for x in completed["steps"]],
                      flush=True)
                raise SystemExit(4)
            if not completed.get("frame",{}).get("image"):
                raise SystemExit("STAGE_C_NO_SCREENSHOT")
            print("STAGE_C_REAL_BROWSER_VERIFIED",
                  len(completed["steps"]),flush=True)

            title="NF-ONE-TEST-WIKIPEDIA"
            content={"list_id":"local-test-account","title":title}
            pending=service_manager.prepare(project,"google.tasks.create",content)
            print("STAGE_D_ACCOUNT_WRITE_PREPARED",flush=True)
            saved=service_manager.commit(
                project,pending["id"],"google.tasks.create",content)
            if saved["state"]!="VERIFIED":
                print("STAGE_E_WRITE_UNKNOWN",saved["state"],flush=True)
                raise SystemExit(5)
            print("STAGE_E_ACCOUNT_CREATED_READBACK_VERIFIED",flush=True)
            try:
                service_manager.commit(project,pending["id"],
                                       "google.tasks.create",content)
                raise SystemExit("STAGE_F_DUPLICATE_NOT_BLOCKED")
            except Exception as err:
                if "APPROVAL_INVALID" not in str(err) and "REPLAY_REFUSED" not in str(err):
                    raise
            print("STAGE_F_REPLAY_PREVENTED",flush=True)
            print("E2E_PASS_SYNTHETIC_ACCOUNT_ONLY",round(time.monotonic()-start,2),
                  flush=True)
        finally:
            browser._close_process()
            service.shutdown()
            service.server_close()


if __name__=="__main__":
    main()
