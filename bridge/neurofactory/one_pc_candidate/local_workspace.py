"""One-PC loopback-only durable workspace (DRAFT data, no queue execution).

Real SQLite projects/tasks/history/backups. Never acts on a model proposal,
calls external services or authorizes CORE/HOST effects. Import existing UI.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import urllib.request
from urllib.parse import urlsplit
import uuid

PROJECT_ID = re.compile(r"[a-f0-9]{32}\Z")
NAME_LIMIT = 80
TASK_LIMIT = 1200
FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/styles.css": "styles.css",
    "/demo-data.js": "demo-data.js",
    "/app.js": "app.js",
    "/workspace.js": "workspace.js",
}
MIMES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
}

class WorkspaceDenied(ValueError):
    pass

def _safe_dir(value: Path, *, create=False) -> Path:
    value = Path(value)
    if not value.is_absolute() or value.is_symlink():
        raise WorkspaceDenied("Local directory must be absolute and not linked")
    if create:
        if not value.parent.is_dir() or value.parent.is_symlink():
            raise WorkspaceDenied("Data directory parent must already exist")
        value.mkdir(mode=0o700, exist_ok=True)
    if not value.is_dir() or value.is_symlink():
        raise WorkspaceDenied("Unsafe local data directory")
    details = value.lstat()
    if os.name == "nt" and details.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise WorkspaceDenied("Windows reparse data directory denied")
    if os.name != "nt" and details.st_mode & 0o077:
        raise WorkspaceDenied("User data directory must be private")
    return value

def _utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _json_unique(pairs):
    data={}
    for key,val in pairs:
        if key in data:
            raise WorkspaceDenied("Duplicate JSON keys")
        data[key]=val
    return data

class WorkspaceStore:
    def __init__(self, directory: Path):
        self.directory=_safe_dir(directory,create=True)
        self.database=self.directory/"workspace.sqlite3"
        if self.database.is_symlink():
            raise WorkspaceDenied("Linked database refused")
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS projects(
              id TEXT PRIMARY KEY, name TEXT NOT NULL,
              description TEXT NOT NULL, created_utc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tasks(
              id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
              objective TEXT NOT NULL, model_preference TEXT NOT NULL,
              state TEXT NOT NULL CHECK(state='DRAFT_PENDING_OWNER_AUTH'),
              created_utc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS history(
              id INTEGER PRIMARY KEY AUTOINCREMENT, event_utc TEXT NOT NULL,
              event TEXT NOT NULL, record_id TEXT NOT NULL);
            """)
            version=conn.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0,1):
                raise WorkspaceDenied("Unknown newer database version")
            if version==0:
                conn.execute("PRAGMA user_version=1")
            conn.commit()

    def connect(self):
        conn=sqlite3.connect(str(self.database),timeout=8)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=8000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def list_projects(self):
        with self.connect() as db:
            return [dict(zip(("id","name","description","created_utc"),r))
                    for r in db.execute(
                        "SELECT id,name,description,created_utc FROM projects ORDER BY created_utc,id"
                    ).fetchall()]

    def list_tasks(self):
        with self.connect() as db:
            return [dict(zip(("id","project_id","objective","model_preference","state","created_utc"),r))
                    for r in db.execute(
                        "SELECT id,project_id,objective,model_preference,state,created_utc "
                        "FROM tasks ORDER BY created_utc,id").fetchall()]

    def create_project(self,obj):
        if (type(obj) is not dict or set(obj)!={"name","description"}
                or type(obj["name"]) is not str or
                not 3<=len(obj["name"].strip())<=NAME_LIMIT or
                type(obj["description"]) is not str or
                len(obj["description"])>400 or
                any(ord(c)<32 for c in obj["name"]+obj["description"])):
            raise WorkspaceDenied("Invalid project fields")
        row=(uuid.uuid4().hex,obj["name"].strip(),obj["description"],_utc())
        with self.connect() as db:
            db.execute("INSERT INTO projects VALUES(?,?,?,?)",row)
            db.execute("INSERT INTO history(event_utc,event,record_id) VALUES(?,?,?)",
                       (_utc(),"PROJECT_CREATED_DRAFT",row[0]))
            db.commit()
        return {"id":row[0],"name":row[1],"description":row[2],"created_utc":row[3]}

    def create_task(self,obj):
        if (type(obj) is not dict or set(obj)!={"project_id","objective","model_preference"} or
                type(obj["project_id"]) is not str or not PROJECT_ID.fullmatch(obj["project_id"]) or
                type(obj["objective"]) is not str or
                not 15<=len(obj["objective"].strip())<=TASK_LIMIT or
                any(ord(x)<32 and x not in ("\n","\t") for x in obj["objective"]) or
                obj["model_preference"] not in ("auto","qwen3:0.6b","qwen2.5-coder:1.5b")):
            raise WorkspaceDenied("Invalid task fields")
        row=(uuid.uuid4().hex,obj["project_id"],obj["objective"].strip(),
             obj["model_preference"],"DRAFT_PENDING_OWNER_AUTH",_utc())
        with self.connect() as db:
            if not db.execute("SELECT 1 FROM projects WHERE id=?",(row[1],)).fetchone():
                raise WorkspaceDenied("Unknown project")
            db.execute("INSERT INTO tasks VALUES(?,?,?,?,?,?)",row)
            db.execute("INSERT INTO history(event_utc,event,record_id) VALUES(?,?,?)",
                       (_utc(),"TASK_CREATED_NOT_QUEUED",row[0]))
            db.commit()
        return dict(zip(("id","project_id","objective","model_preference","state","created_utc"),row))

    def history(self):
        with self.connect() as db:
            return [dict(zip(("event_utc","event","record_id"),r))
                    for r in db.execute(
                        "SELECT event_utc,event,record_id FROM history ORDER BY id DESC LIMIT 100"
                    ).fetchall()]

    def backup(self):
        backups=self.directory/"backups"
        backups.mkdir(mode=0o700,exist_ok=True)
        _safe_dir(backups)
        target=backups/("workspace-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")+
                       "-"+secrets.token_hex(4)+".sqlite3")
        with self.connect() as src, sqlite3.connect(target) as dst:
            src.backup(dst)
            assert dst.execute("PRAGMA integrity_check").fetchone()[0]=="ok"
        return {"filename":target.name,
                "bytes":target.stat().st_size,
                "sha256":hashlib.sha256(target.read_bytes()).hexdigest(),
                "created_utc":_utc()}

    def diag(self):
        with self.connect() as db:
            good=db.execute("PRAGMA quick_check").fetchone()[0]=="ok"
        return {"database_connected":good,"projects":len(self.list_projects()),
                "tasks":len(self.list_tasks()),"real_core_dispatch_enabled":False,
                "model_inference_enabled":False,"external_publish_enabled":False,
                "handoff":"PAUSED_BY_USER"}

def local_models():
    try:
        req=urllib.request.Request("http://127.0.0.1:11434/api/tags",
                                   headers={"Accept":"application/json"})
        with urllib.request.urlopen(req,timeout=1) as response:
            raw=response.read(32769)
        if len(raw)>32768:
            raise ValueError("oversize model inventory")
        items=json.loads(raw.decode("utf-8"))["models"]
        if type(items) is not list:
            raise ValueError("bad model inventory")
        installed=[x["name"] for x in items if type(x) is dict and
                   type(x.get("name")) is str and x["name"].startswith("qwen")]
        return {"ollama_reachable":True,"installed_qwen":installed[:20],
                "inference_tested":False}
    except (OSError,ValueError,KeyError,TypeError,TimeoutError):
        return {"ollama_reachable":False,"installed_qwen":[],"inference_tested":False}

def handler(store,ui,token,port):
    origin="http://127.0.0.1:"+str(port)
    class Local(BaseHTTPRequestHandler):
        def _secure_request(self):
            # Prevent cross-site form/CSRF, browser DNS-rebinding and remote Host.
            if self.headers.get("Host")!="127.0.0.1:"+str(port):
                return False
            incoming=self.headers.get("Origin")
            if incoming is not None and incoming!=origin:
                return False
            return True

        def _send(self,status,body,mime="application/json; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type",mime)
            self.send_header("Content-Length",str(len(body)))
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "img-src 'self' data:; form-action 'self'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self,status,data):
            self._send(status,json.dumps(data,ensure_ascii=False,
                      separators=(",",":")).encode("utf-8"))

        def do_GET(self):
            if not self._secure_request():
                self._json(403,{"error":"HOST_OR_ORIGIN_DENIED"});return
            p=urlsplit(self.path)
            if p.query or p.fragment:
                self._json(404,{"error":"NOT_FOUND"});return
            if p.path=="/api/bootstrap":
                self._json(200,{"schema":"nf.local.workspace.v1",
                   "csrf_token":token,"mode":"LOCAL_DRAFT_ONLY",
                   "live_execution_allowed":False});return
            if p.path=="/api/projects":
                self._json(200,{"projects":store.list_projects()});return
            if p.path=="/api/tasks":
                self._json(200,{"tasks":store.list_tasks()});return
            if p.path=="/api/history":
                self._json(200,{"history":store.history()});return
            if p.path=="/api/status":
                self._json(200,store.diag());return
            if p.path=="/api/models":
                self._json(200,local_models());return
            fn=FILES.get(p.path)
            if not fn:
                self._json(404,{"error":"NOT_FOUND"});return
            path=ui/fn
            if path.is_symlink() or not path.is_file():
                self._json(404,{"error":"STATIC_FILE_NOT_FOUND"});return
            data=path.read_bytes()
            if len(data)>500_000:
                self._json(503,{"error":"UI_TOO_LARGE"});return
            self._send(200,data,MIMES[path.suffix])

        def do_POST(self):
            if not self._secure_request() or self.headers.get("X-NF-Local-Token")!=token:
                self._json(403,{"error":"LOCAL_AUTH_REQUIRED"});return
            if self.headers.get("Content-Type")!="application/json":
                self._json(415,{"error":"JSON_REQUIRED"});return
            p=urlsplit(self.path)
            if p.query or p.path not in ("/api/projects","/api/tasks","/api/backup"):
                self._json(404,{"error":"WRITE_NOT_ALLOWED"});return
            try:
                size=int(self.headers.get("Content-Length","0"))
                if not 2<=size<=4096:
                    raise WorkspaceDenied("Invalid request size")
                body=json.loads(self.rfile.read(size).decode("utf-8"),
                                object_pairs_hook=_json_unique)
                if p.path=="/api/projects":
                    result=store.create_project(body)
                elif p.path=="/api/tasks":
                    result=store.create_task(body)
                else:
                    if body!={}:
                        raise WorkspaceDenied("No backup arguments allowed")
                    result=store.backup()
            except (WorkspaceDenied,UnicodeError,ValueError,TypeError,sqlite3.Error):
                self._json(400,{"error":"REQUEST_DENIED"});return
            self._json(201,result)

        def do_PUT(self):
            self._json(405,{"error":"IMMUTABLE_DRAFT_ONLY"})
        def do_DELETE(self):
            self._json(405,{"error":"IMMUTABLE_DRAFT_ONLY"})
        def log_message(self,*args):
            pass
    return Local

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--data-dir",type=Path,required=True)
    p.add_argument("--ui-dir",type=Path,required=True)
    p.add_argument("--port",type=int,default=8766)
    args=p.parse_args(argv)
    if not 1024<=args.port<=65535:
        raise WorkspaceDenied("Port denied")
    ui=_safe_dir(args.ui_dir)
    app=WorkspaceStore(args.data_dir)
    one_time_token=secrets.token_urlsafe(32)
    with HTTPServer(("127.0.0.1",args.port),
                    handler(app,ui,one_time_token,args.port)) as srv:
        print("NEUROFACTORY_LOCAL_DRAFT_WORKSPACE=127.0.0.1:"+str(args.port),flush=True)
        srv.serve_forever(poll_interval=0.2)

if __name__=="__main__":
    main()
