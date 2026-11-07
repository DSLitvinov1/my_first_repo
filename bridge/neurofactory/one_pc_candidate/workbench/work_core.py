"""NEIROZAVOD Work — isolated user-owned projects and persistent tasks.

Safety: no shell/model-code execution, no paths outside a single root.
Each mutation is an explicit UI operation. Model drafts remain inert. Crash
after a file-write intent becomes UNKNOWN_NO_RETRY, never auto-applied again.
"""
from __future__ import annotations
from pathlib import Path
from contextlib import contextmanager
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import threading
import time
import uuid

HEX32=re.compile(r"[0-9a-f]{32}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
EXTS={".md",".txt",".py",".html",".css",".js",".ts",".tsx",".json",
      ".yaml",".yml",".toml",".csv",".xml",".svg"}
FORBIDDEN={"CON","PRN","AUX","NUL",*(f"COM{i}" for i in range(1,10)),
           *(f"LPT{i}" for i in range(1,10))}
MAX_FILE=128*1024
MAX_FILES=250
TEMPLATES={
 "empty":{"README.md":"# Новый проект\n\nРабочая папка Нейрозавод Work.\n"},
 "python":{"main.py":"def main():\n    print('Нейрозавод Work')\n\nif __name__ == '__main__':\n    main()\n",
           "README.md":"# Python-проект\n\nАвтоматический запуск кода пока отключён.\n"},
 "web":{"index.html":'<!doctype html>\n<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Новый проект</title><link rel="stylesheet" href="styles.css"></head><body><main><h1>Мой новый проект</h1><p>Создан через Нейрозавод Work.</p><button id="go">Проверить</button></main><script src="app.js"></script></body></html>\n',
        "styles.css":"body{font-family:system-ui,sans-serif;background:#101827;color:#fff;margin:0;padding:4rem}main{max-width:720px;margin:auto}button{border:0;border-radius:8px;padding:12px 18px;cursor:pointer}\n",
        "app.js":"document.querySelector('#go')?.addEventListener('click',()=>{document.querySelector('p').textContent='Работает!'});\n",
        "README.md":"# Веб-проект\n\nЛокальный проект. Публикация отключена.\n"},
}

class WorkDenied(ValueError):
    pass

def denied(message):
    raise WorkDenied(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def ensure_plain(path):
    if path.is_symlink():
        denied("SYMLINK_REFUSED")
    if os.name=="nt" and path.exists() and path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        denied("NTFS_REPARSE_REFUSED")
    return path

def relative(value):
    if not isinstance(value,str) or not 1<=len(value)<=180 or "\\" in value or ":" in value or value.startswith("/"):
        denied("INVALID_RELATIVE_PATH")
    parts=value.split("/")
    if len(parts)>6 or any(
        not item or item in (".","..") or item.startswith(".") or
        item.endswith((" ",".")) or len(item)>75 or
        item.split(".")[0].upper() in FORBIDDEN or
        any(ord(c)<32 or c in '<>:"|?*' for c in item)
        for item in parts
    ):
        denied("INVALID_PATH_COMPONENT")
    if Path(parts[-1]).suffix.lower() not in EXTS:
        denied("FILE_TYPE_REFUSED")
    return value

def safe_title(title,limit=100):
    if not isinstance(title,str) or not 3<=len(title.strip())<=limit or any(ord(c)<32 for c in title):
        denied("INVALID_TITLE")
    return title.strip()

@contextmanager
def dbopen(dbpath):
    c=sqlite3.connect(dbpath,timeout=5)
    try:
        c.row_factory=sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA busy_timeout=5000")
        yield c
        c.commit()
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()

def stamp():
    return int(time.time())

class WorkStore:
    def __init__(self,root:Path,data:Path):
        if not root.is_absolute() or not data.is_absolute():
            denied("ABSOLUTE_ROOT_REQUIRED")
        self.root=ensure_plain(root)
        self.data=ensure_plain(data)
        self.root.mkdir(parents=True,exist_ok=True)
        self.data.mkdir(parents=True,exist_ok=True)
        ensure_plain(self.root);ensure_plain(self.data)
        self.dbpath=self.data/"work.sqlite3"
        self.lock=threading.RLock()
        with self.db() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS tasks(
              id TEXT PRIMARY KEY,project_id TEXT NOT NULL REFERENCES projects(id),title TEXT NOT NULL,
              goal TEXT NOT NULL,state TEXT NOT NULL,draft TEXT,draft_sha TEXT,model TEXT,
              error TEXT,created INTEGER NOT NULL,updated INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS writes(
              id TEXT PRIMARY KEY,project_id TEXT NOT NULL,path TEXT NOT NULL,
              before_sha TEXT,after_sha TEXT NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS versions(
              id TEXT PRIMARY KEY,project_id TEXT NOT NULL,path TEXT NOT NULL,
              prior_sha TEXT,prior_text BLOB,after_sha TEXT NOT NULL,created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,
              project_id TEXT,detail TEXT NOT NULL,created INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS tasks_project ON tasks(project_id,created);
            CREATE INDEX IF NOT EXISTS versions_project ON versions(project_id,created);
            """)
            c.execute("UPDATE tasks SET state='UNKNOWN_NO_RETRY',error='INTERRUPTED_QWEN' WHERE state='GENERATING'")
            c.execute("UPDATE writes SET state='UNKNOWN_NO_RETRY' WHERE state='PENDING'")
            c.commit()
    def db(self):
        return dbopen(self.dbpath)
    def event(self,c,kind,project_id,details):
        c.execute("INSERT INTO events(kind,project_id,detail,created) VALUES(?,?,?,?)",
                  (kind,project_id,json.dumps(details,ensure_ascii=False),stamp()))
    def project(self,ident):
        if not isinstance(ident,str) or not HEX32.fullmatch(ident):
            denied("PROJECT_ID_INVALID")
        with self.db() as c:
            p=c.execute("SELECT * FROM projects WHERE id=?",(ident,)).fetchone()
        if p is None:
            denied("PROJECT_NOT_FOUND")
        folder=ensure_plain(self.root/ident)
        if not folder.is_dir():
            denied("PROJECT_DIRECTORY_MISSING")
        return dict(p),folder
    def target(self,ident,path,needs_file=False):
        _,folder=self.project(ident)
        rel=relative(path)
        parts=rel.split("/")
        parent=folder
        for item in parts[:-1]:
            parent=ensure_plain(parent/item)
            if parent.exists() and not parent.is_dir():
                denied("UNSAFE_FILE_PARENT")
        target=ensure_plain(parent/parts[-1])
        if target.exists() and not target.is_file():
            denied("NOT_A_FILE")
        if needs_file and not target.is_file():
            denied("FILE_NOT_FOUND")
        return target,rel
    def status(self):
        with self.db() as c:
            p=c.execute("SELECT count(*) FROM projects").fetchone()[0]
            t=c.execute("SELECT count(*) FROM tasks").fetchone()[0]
            unknown=c.execute("SELECT count(*) FROM writes WHERE state='UNKNOWN_NO_RETRY'").fetchone()[0]
        return {"projects":p,"tasks":t,"uncertain_writes":unknown,"model_executes_code":False,
                "auto_apply":False,"mode":"PERSONAL_WORKBENCH"}
    def projects(self):
        with self.db() as c:
            return [dict(r) for r in c.execute("SELECT * FROM projects ORDER BY created DESC,id")]
    def create_project(self,title,kind):
        title=safe_title(title,80)
        if kind not in TEMPLATES:
            denied("PROJECT_TEMPLATE_REFUSED")
        with self.lock:
            ident=uuid.uuid4().hex
            folder=self.root/ident
            folder.mkdir(mode=0o700)
            try:
                for file,text in TEMPLATES[kind].items():
                    (folder/file).write_text(text,encoding="utf-8",newline="\n")
                with self.db() as c:
                    c.execute("INSERT INTO projects VALUES(?,?,?,?)",(ident,title,kind,stamp()))
                    self.event(c,"PROJECT_CREATED",ident,{"title":title,"kind":kind})
                    c.commit()
            except Exception:
                shutil.rmtree(folder)
                raise
            return {"id":ident,"name":title,"kind":kind}
    def files(self,ident):
        _,folder=self.project(ident)
        output=[]
        for base,dirs,files in os.walk(folder,followlinks=False):
            base=Path(base)
            ensure_plain(base)
            dirs[:]=sorted(x for x in dirs if not x.startswith(".") and
                           not (base/x).is_symlink() and
                           not (os.name=="nt" and (base/x).lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT))
            if len(base.relative_to(folder).parts)>=5:
                dirs.clear()
            for name in sorted(files):
                file=base/name
                rel=file.relative_to(folder).as_posix()
                try:
                    relative(rel);ensure_plain(file)
                    if file.stat().st_size<=MAX_FILE:
                        output.append({"path":rel,"size":file.stat().st_size})
                except (WorkDenied,OSError):
                    pass
                if len(output)>=MAX_FILES:return output
        return output
    def read(self,ident,path):
        target,rel=self.target(ident,path,True)
        if target.stat().st_size>MAX_FILE:
            denied("FILE_EXCEEDS_LIMIT")
        raw=target.read_bytes()
        try:
            text=raw.decode("utf-8")
        except UnicodeDecodeError:
            denied("BINARY_REFUSED")
        return {"path":rel,"text":text,"sha256":sha(raw)}
    def _atomic_write(self,target,raw):
        target.parent.mkdir(parents=True,exist_ok=True)
        ensure_plain(target.parent)
        tmp=target.parent/("nf-tmp-"+secrets.token_hex(12)+".tmp")
        try:
            with tmp.open("xb") as file:
                file.write(raw);file.flush();os.fsync(file.fileno())
            os.replace(tmp,target)
        finally:
            if tmp.exists():tmp.unlink()
    def save(self,ident,path,text,previous=None):
        if not isinstance(text,str):
            denied("TEXT_REQUIRED")
        content=text.encode("utf-8")
        if len(content)>MAX_FILE or (previous is not None and
            (not isinstance(previous,str) or not HEX64.fullmatch(previous))):
            denied("FILE_OR_REVISION_INVALID")
        with self.lock:
            if self.status()["uncertain_writes"]:
                denied("UNKNOWN_PREVIOUS_WRITE_REQUIRES_REVIEW")
            target,rel=self.target(ident,path)
            before=target.read_bytes() if target.exists() else None
            if before is not None and len(before)>MAX_FILE:
                denied("OLD_FILE_EXCEEDS_LIMIT")
            oldsha=sha(before) if before is not None else None
            if oldsha!=previous:
                denied("REVISION_STALE_RELOAD")
            if before is None and len(self.files(ident))>=MAX_FILES:
                denied("FILE_COUNT_LIMIT")
            newsha=sha(content)
            if newsha==oldsha:return {"path":rel,"sha256":newsha,"unchanged":True}
            intent=uuid.uuid4().hex
            with self.db() as c:
                c.execute("INSERT INTO writes VALUES(?,?,?,?,?,?,?)",
                          (intent,ident,rel,oldsha,newsha,"PENDING",stamp()))
                c.commit()
            # No rollback or retry on ambiguous interruption: durable PENDING
            # is promoted to UNKNOWN on restart and blocks further writes.
            self._atomic_write(target,content)
            if sha(target.read_bytes())!=newsha:
                denied("POSTWRITE_INTEGRITY_FAILED")
            with self.db() as c:
                c.execute("UPDATE writes SET state='DONE' WHERE id=? AND state='PENDING'",(intent,))
                c.execute("INSERT INTO versions VALUES(?,?,?,?,?,?,?)",
                          (uuid.uuid4().hex,ident,rel,oldsha,before,newsha,stamp()))
                self.event(c,"FILE_SAVED",ident,{"path":rel,"sha256":newsha})
                c.commit()
            return {"path":rel,"sha256":newsha,"unchanged":False}
    def versions(self,ident,path):
        self.project(ident)
        rel=relative(path)
        with self.db() as c:
            return [{"sha256":r["after_sha"],"previous_sha256":r["prior_sha"],"created":r["created"]}
                    for r in c.execute("SELECT * FROM versions WHERE project_id=? AND path=? ORDER BY rowid DESC LIMIT 15",(ident,rel))]
    def undo(self,ident,path,previous):
        with self.lock:
            target,rel=self.target(ident,path,True)
            with self.db() as c:
                record=c.execute("SELECT * FROM versions WHERE project_id=? AND path=? ORDER BY rowid DESC LIMIT 1",
                                 (ident,rel)).fetchone()
            if record is None or record["prior_text"] is None or record["after_sha"]!=previous:
                denied("UNDO_REQUIRES_LATEST_EDIT_AND_BACKUP")
            return self.save(ident,rel,bytes(record["prior_text"]).decode("utf-8"),previous)
    def tasks(self,ident):
        self.project(ident)
        with self.db() as c:
            return [dict(r) for r in c.execute("SELECT * FROM tasks WHERE project_id=? ORDER BY created DESC,id DESC",(ident,))]
    def task(self,ident):
        if not isinstance(ident,str) or not HEX32.fullmatch(ident):
            denied("TASK_ID_INVALID")
        with self.db() as c:
            r=c.execute("SELECT * FROM tasks WHERE id=?",(ident,)).fetchone()
        if r is None:
            denied("TASK_NOT_FOUND")
        return dict(r)
    def create_task(self,project,title,goal):
        self.project(project)
        title=safe_title(title)
        if not isinstance(goal,str) or not 15<=len(goal.strip())<=1200:
            denied("TASK_GOAL_INVALID")
        with self.lock,self.db() as c:
            ident=uuid.uuid4().hex
            c.execute("INSERT INTO tasks(id,project_id,title,goal,state,created,updated) VALUES(?,?,?,?,?,?,?)",
                      (ident,project,title,goal.strip(),"DRAFT",stamp(),stamp()))
            self.event(c,"TASK_CREATED",project,{"task":ident})
            c.commit()
        return {"id":ident,"state":"DRAFT"}
    def reserve_generation(self,ident):
        with self.lock,self.db() as c:
            row=c.execute("SELECT * FROM tasks WHERE id=?",(ident,)).fetchone()
            if row is None or row["state"]!="DRAFT":
                denied("GENERATION_ALREADY_ATTEMPTED_NO_RETRY")
            if c.execute("SELECT count(*) FROM tasks WHERE state='GENERATING'").fetchone()[0]:
                denied("MODEL_BUSY_ONE_GENERATION_AT_A_TIME")
            c.execute("UPDATE tasks SET state='GENERATING',updated=? WHERE id=?",(stamp(),ident))
            self.event(c,"MODEL_ATTEMPT_RESERVED",row["project_id"],{"task":ident})
            c.commit()
        return dict(row)
    def finish_generation(self,ident,reply):
        with self.lock,self.db() as c:
            row=c.execute("SELECT * FROM tasks WHERE id=?",(ident,)).fetchone()
            if row is None or row["state"]!="GENERATING":
                denied("GENERATION_STATE_MISMATCH")
            body=reply.get("text")
            if (reply.get("status")=="PROPOSED_UNVERIFIED" and
                isinstance(body,str) and len(body.encode("utf-8"))<=12000 and
                sha(body.encode("utf-8"))==reply.get("content_sha256")):
                c.execute("UPDATE tasks SET state='REVIEW',draft=?,draft_sha=?,model=?,updated=? WHERE id=?",
                          (body,reply["content_sha256"],reply.get("model"),stamp(),ident))
                event="MODEL_DRAFT_READY"
            else:
                c.execute("UPDATE tasks SET state='UNKNOWN_NO_RETRY',error='MODEL_RESULT_UNKNOWN',updated=? WHERE id=?",(stamp(),ident))
                event="MODEL_RESULT_UNKNOWN"
            self.event(c,event,row["project_id"],{"task":ident})
            c.commit()
    def events(self):
        with self.db() as c:
            return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50")]
