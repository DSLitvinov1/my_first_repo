"""Local-only HTTP UI for Neurofactory Work. No public/network listener.

The independent Work UI creates bounded workspaces and Qwen *drafts*,
not protected CORE9 grants and not arbitrary code execution.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import threading
from urllib.parse import parse_qs,urlsplit
from work_core import WorkStore,WorkDenied,denied
from agent_one import AgentOne
from browser_control import BrowserController

MIME={"/":"text/html; charset=utf-8",
      "/styles.css":"text/css; charset=utf-8",
      "/app.js":"application/javascript; charset=utf-8"}
ID="[0-9a-f]{32}"
PROJECT_RE=re.compile(rf"^/api/projects/({ID})/(files|tasks|file|versions|undo)$")
TASK_RE=re.compile(rf"^/api/tasks/({ID})/generate$")
# Reuse the user's existing, already working cloud Qwen UI release.
# Never import this untrusted model client from an arbitrary project path.
INSTALLED_QWEN=Path(r"C:\ChatGPTProjects\NeurofactoryReview-20261105-verified")
PINNED_QWEN_PROVIDER_SHA="60cc46c07960e09aa64e55403e875e0b72d5f66bd274d3fa29855ea41ad5dbe3"
OWNER_DATA=Path(os.environ.get("LOCALAPPDATA",""))/"NeurofactoryData"

class ServerDenied(ValueError):
    pass

def unique(items):
    result={}
    for k,v in items:
        if k in result:
            raise ServerDenied("DUPLICATE_JSON_KEY")
        result[k]=v
    return result

def model_module():
    """Only the *existing pinned SSH draft client*, without copying its key."""
    manifest=INSTALLED_QWEN/"release-manifest.json"
    file=INSTALLED_QWEN/"app"/"cloud_ssh_draft_provider.py"
    if (not manifest.is_file() or not file.is_file() or
        manifest.is_symlink() or file.is_symlink()):
        raise ServerDenied("PINNED_MODEL_PROVIDER_MISSING")
    data=json.loads(manifest.read_text("utf-8-sig"))
    entries=[x for x in data["entries"] if x.get("path")=="app/cloud_ssh_draft_provider.py"]
    if (len(entries)!=1 or entries[0]["sha256"]!=PINNED_QWEN_PROVIDER_SHA or
        sha256(file.read_bytes()).hexdigest()!=PINNED_QWEN_PROVIDER_SHA):
        raise ServerDenied("PINNED_MODEL_PLUGIN_MUTATED")
    spec=importlib.util.spec_from_file_location("_nf_work_pinned_qwen",file)
    if spec is None or spec.loader is None:
        raise ServerDenied("PINNED_MODEL_IMPORT_FAILED")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not module.available(OWNER_DATA):
        raise ServerDenied("EXISTING_QWEN_NOT_AVAILABLE")
    return module

def make_handler(store,assets,token,port,agent=None,browser=None):
    agent=agent or AgentOne(store)
    browser=browser or BrowserController(store,assets)
    home=assets/"index.html"
    stylesheet=assets/"styles.css"
    script=assets/"app.js"
    if not all(p.is_file() and not p.is_symlink() for p in (home,stylesheet,script)):
        raise ServerDenied("FRONTEND_ASSETS_MISSING")
    origin=f"http://127.0.0.1:{port}"

    class Handler(BaseHTTPRequestHandler):
        server_version="NeurofactoryWork/0.1"
        sys_version=""
        def _headers(self,status,size,mime):
            self.send_response(status)
            self.send_header("Content-Type",mime)
            self.send_header("Content-Length",str(size))
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("X-Frame-Options","DENY")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; font-src 'none'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.end_headers()
        def send_bytes(self,status,data,mime):
            self._headers(status,len(data),mime)
            self.wfile.write(data)
        def out(self,status,obj):
            try:
                raw=json.dumps(obj,ensure_ascii=False,separators=(",",":")).encode("utf-8")
            except (TypeError,ValueError):
                raw=b'{"error":"INTERNAL_SERIALIZATION"}'
                status=500
            self.send_bytes(status,raw,"application/json; charset=utf-8")
        def guard(self,method):
            if self.headers.get("Host")!=f"127.0.0.1:{port}":
                raise ServerDenied("HOST_HEADER_DENIED")
            if method not in ("GET","HEAD"):
                if (self.headers.get("Origin")!=origin or
                    self.headers.get("X-NF-Work-Token")!=token):
                    raise ServerDenied("LOCAL_OWNER_TOKEN_REQUIRED")
        def parse(self):
            if self.headers.get("Content-Type")!="application/json":
                raise ServerDenied("JSON_REQUIRED")
            try:
                length=int(self.headers.get("Content-Length","0"))
            except ValueError:
                raise ServerDenied("CONTENT_LENGTH_INVALID")
            if not 2<=length<=400000:
                raise ServerDenied("REQUEST_SIZE_REFUSED")
            obj=json.loads(self.rfile.read(length).decode("utf-8"),
                           object_pairs_hook=unique)
            if type(obj) is not dict:
                raise ServerDenied("OBJECT_REQUIRED")
            return obj
        def _get(self):
            path=urlsplit(self.path)
            if path.fragment:
                raise ServerDenied("URL_FRAGMENT")
            if path.path in MIME and not path.query:
                if path.path=="/":
                    body=home.read_text("utf-8").replace("__NF_WORK_TOKEN__",
                                                         html.escape(token,quote=True))
                    self.send_bytes(200,body.encode("utf-8"),MIME[path.path])
                else:
                    source=stylesheet if path.path=="/styles.css" else script
                    self.send_bytes(200,source.read_bytes(),MIME[path.path])
                return
            if path.path=="/api/status" and not path.query:
                state=store.status()
                try:
                    model_module()
                    state["qwen_available"]=True
                except (ServerDenied,OSError,ValueError):
                    state["qwen_available"]=False
                self.out(200,state)
            elif path.path=="/api/projects" and not path.query:
                self.out(200,{"projects":store.projects()})
            elif path.path=="/api/activity" and not path.query:
                self.out(200,{"events":store.events()})
            elif path.path=="/api/agent/capabilities" and not path.query:
                self.out(200,agent.capabilities())
            elif path.path=="/api/browser/status":
                vals=parse_qs(path.query)
                if set(vals)!={"project_id"} or len(vals["project_id"])!=1:
                    raise ServerDenied("BROWSER_PROJECT_REQUIRED")
                store.project(vals["project_id"][0])
                self.out(200,browser.status(vals["project_id"][0]))
            elif path.path=="/api/agent/runs":
                vals=parse_qs(path.query)
                if set(vals)!={"project_id"} or len(vals["project_id"])!=1:
                    raise ServerDenied("AGENT_PROJECT_REQUIRED")
                self.out(200,{"runs":agent.runs(vals["project_id"][0])})
            elif re.fullmatch(r"/api/agent/runs/[0-9a-f]{32}",path.path) and not path.query:
                # Project binding is required to avoid exposing another project's audit.
                raise ServerDenied("AGENT_PROJECT_REQUIRED")
            else:
                match=PROJECT_RE.fullmatch(path.path)
                if not match:
                    raise WorkDenied("ENDPOINT_NOT_FOUND")
                project,action=match.groups()
                if action=="files" and not path.query:
                    self.out(200,{"files":store.files(project)})
                elif action=="tasks" and not path.query:
                    self.out(200,{"tasks":store.tasks(project)})
                elif action in ("file","versions"):
                    vals=parse_qs(path.query,keep_blank_values=True)
                    if set(vals)!={"path"} or len(vals["path"])!=1:
                        raise ServerDenied("PATH_QUERY_REQUIRED")
                    rel=vals["path"][0]
                    if action=="file":
                        self.out(200,store.read(project,rel))
                    else:
                        self.out(200,{"versions":store.versions(project,rel)})
                else:
                    raise ServerDenied("QUERY_NOT_ALLOWED")
        def _mutation(self,method):
            url=urlsplit(self.path)
            if url.query:
                raise ServerDenied("MUTATION_QUERY_REFUSED")
            data=self.parse()
            if method=="POST" and url.path=="/api/browser/open" and set(data)=={"project_id","url"}:
                self.out(201,browser.open(data["project_id"],data["url"]))
                return
            if method=="POST" and url.path=="/api/browser/close" and set(data)=={"project_id","session_id"}:
                self.out(200,browser.close(data["project_id"],data["session_id"]))
                return
            if method=="POST" and url.path=="/api/browser/action" and isinstance(data.get("op"),str):
                operation=data["op"]
                required={"project_id","session_id","op"}
                if operation in ("click","move"):
                    required|={"x","y"}
                elif operation=="scroll":
                    required|={"delta"}
                if set(data)!=required:
                    raise ServerDenied("BROWSER_ACTION_FIELDS_INVALID")
                opts={k:data[k] for k in required-{"project_id","session_id","op"}}
                self.out(200,browser.action(data["project_id"],data["session_id"],operation,**opts))
                return
            if method=="POST" and url.path=="/api/agent/audits" and set(data)=={"project_id","urls"}:
                run=agent.create_audit(data["project_id"],data["urls"])
                self.out(201,agent.execute(run["id"],data["project_id"]))
                return
            if method=="POST" and url.path=="/api/projects" and set(data)=={"name","template"}:
                self.out(201,store.create_project(data["name"],data["template"]))
                return
            m=PROJECT_RE.fullmatch(url.path)
            if m:
                project,action=m.groups()
                if method=="POST" and action=="tasks" and set(data)=={"title","goal"}:
                    self.out(201,store.create_task(project,data["title"],data["goal"]))
                    return
                if method=="PUT" and action=="file" and set(data)=={"path","text","previous_sha"}:
                    self.out(200,store.save(project,data["path"],data["text"],data["previous_sha"]))
                    return
                if method=="POST" and action=="undo" and set(data)=={"path","sha256"}:
                    self.out(200,store.undo(project,data["path"],data["sha256"]))
                    return
            m=TASK_RE.fullmatch(url.path)
            if method=="POST" and m and data=={}:
                taskid=m.group(1)
                info=store.reserve_generation(taskid)
                def runner():
                    try:
                        provider=model_module()
                        reply=provider.generate(OWNER_DATA,{
                            "id":info["id"],"project_id":info["project_id"],
                            "objective":info["goal"]},model="qwen3.5:9b")
                    except Exception:
                        reply={"status":"UNKNOWN","error_code":"MODEL_OR_TRANSPORT_UNKNOWN"}
                    try:
                        store.finish_generation(taskid,reply)
                    except Exception:
                        # Existing durable GENERATING becomes UNKNOWN on restart.
                        pass
                threading.Thread(target=runner,daemon=True,
                                 name=f"nf-qwen-{taskid[:6]}").start()
                self.out(202,{"status":"GENERATING","task_id":taskid,
                              "no_auto_retry":True})
                return
            raise ServerDenied("MUTATION_NOT_SUPPORTED")
        def dispatch(self,method):
            try:
                self.guard(method)
                if method=="GET":
                    self._get()
                elif method in ("POST","PUT"):
                    self._mutation(method)
                else:
                    self.out(405,{"error":"METHOD_DENIED"})
            except (ServerDenied,WorkDenied,ValueError,UnicodeError) as e:
                self.out(400,{"error":str(e)})
            except (sqlite3.Error,OSError):
                self.out(503,{"error":"STORAGE_UNAVAILABLE"})
        def do_GET(self):self.dispatch("GET")
        def do_POST(self):self.dispatch("POST")
        def do_PUT(self):self.dispatch("PUT")
        def do_DELETE(self):self.dispatch("DELETE")
        def log_message(self,*args):pass
    return Handler

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--root",type=Path,required=True)
    ap.add_argument("--data",type=Path,required=True)
    ap.add_argument("--port",type=int,default=8770)
    ap.add_argument("--browser-allow-hosts",default="",
                    help="Comma-separated explicitly approved exact HTTPS hosts")
    ap.add_argument("--browser-executable",type=Path,default=None)
    args=ap.parse_args()
    if not 1024<=args.port<=65535:
        raise ServerDenied("PORT_REFUSED")
    store=WorkStore(args.root,args.data)
    token=secrets.token_urlsafe(36)
    browser=BrowserController(
        store,Path(__file__).resolve().parent,
        allowed_hosts=args.browser_allow_hosts.split(",") if args.browser_allow_hosts else (),
        executable=args.browser_executable)
    server=ThreadingHTTPServer(("127.0.0.1",args.port),
                              make_handler(store,Path(__file__).resolve().parent,
                                           token,args.port,browser=browser))
    print(f"NEIROZAVOD_WORK_LOCAL_READY http://127.0.0.1:{args.port}/",flush=True)
    print("ISOLATED_USER_PROJECTS_ONLY; MODEL_OUTPUT_UNTRUSTED; NO_SHELL",flush=True)
    try:server.serve_forever(poll_interval=0.25)
    finally:
        browser._close_process()
        server.server_close()

if __name__=="__main__":
    import sqlite3
    main()
