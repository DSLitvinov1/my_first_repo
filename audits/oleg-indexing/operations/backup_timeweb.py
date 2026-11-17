#!/usr/bin/env python3
"""Daily protected backup of Oleg's *currently active* two site trees.

Runs as Timeweb cl664853. No network calls, no client messages, no deletion
or overwrite of any backups. Includes integrity and restore-format checks.
"""
from __future__ import annotations
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time

HOME=Path("/home/c/cl664853")
SITES=("potrebpravo.ru","semya-yurist.ru")
BACKUPS=HOME/".oleg-safe-backups/oleg-managed-daily"
MAX_BACKUPS_BEFORE_ALERT=90

def sha(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(131072),b""):h.update(b)
    return h.hexdigest()
def write_atomic(path:Path, data:bytes):
    temp=path.with_name(path.name+".tmp")
    fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
    finally:
        if temp.exists():temp.unlink()
def safe_inventory():
    files=[]
    for site in SITES:
        folder=HOME/site/"public_html"
        if not folder.is_dir() or folder.is_symlink():raise RuntimeError("invalid live docroot")
        for parent,dirs,names in os.walk(folder,followlinks=False):
            for d in dirs:
                if (Path(parent)/d).is_symlink():raise RuntimeError("symlink in backup tree")
            for n in names:
                p=Path(parent)/n
                if not p.is_file() or p.is_symlink() or not stat.S_ISREG(p.stat().st_mode):
                    raise RuntimeError("unsupported backup file")
                files.append((p,p.relative_to(HOME).as_posix()))
    if len(files)<100:raise RuntimeError("missing website files")
    return files
def main():
    if not HOME.is_dir():raise RuntimeError("unexpected hosting account")
    old=os.umask(0o077)
    try:
        BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
        if BACKUPS.is_symlink():raise RuntimeError("unsafe backup folder")
        os.chmod(BACKUPS,0o700)
        with (BACKUPS/".lock").open("a+") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            existing=list(BACKUPS.glob("oleg-sites-auto-*.json"))
            if len(existing)>=MAX_BACKUPS_BEFORE_ALERT:
                raise RuntimeError("backup retention threshold reached; operator review required")
            files=safe_inventory()
            timestamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            random_part=os.urandom(5).hex()
            stem=f"oleg-sites-auto-{timestamp}-{random_part}"
            archive=BACKUPS/(stem+".tar.gz")
            if archive.exists():raise RuntimeError("duplicate filename")
            # Tarfile writes directly to a private temporary file. Only publish
            # the completed and tested archive by atomic rename.
            tmp=archive.with_name(archive.name+".partial")
            fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            try:
                with os.fdopen(fd,"wb") as raw:
                    with tarfile.open(fileobj=raw,mode="w:gz",dereference=False) as tar:
                        for filename,rel in files:
                            tar.add(filename,arcname=rel,recursive=False)
                    raw.flush();os.fsync(raw.fileno())
                with tarfile.open(tmp,mode="r:gz") as tar:
                    entries=tar.getmembers()
                    if len(entries)!=len(files) or not all(e.isfile() for e in entries):
                        raise RuntimeError("backup cannot be safely restored")
                    for e in entries:
                        if e.name.startswith("/") or ".." in Path(e.name).parts:
                            raise RuntimeError("unsafe archive path")
                os.replace(tmp,archive)
            finally:
                if tmp.exists():tmp.unlink()
            os.chmod(archive,0o600)
            digest=sha(archive)
            manifest={
                "utc":datetime.now(timezone.utc).isoformat(),
                "archive":archive.name,
                "sha256":digest,
                "files":len(files),
                "sites":list(SITES),
                "recoverable_tar_integrity":True,
                "customer_data_exposed":False,
                "backup_deletion_automated":False,
            }
            write_atomic(BACKUPS/(stem+".json"),(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n").encode("utf8"))
            print(json.dumps({"status":"PRIVATE_BACKUP_VERIFIED","utc":manifest["utc"],"files":manifest["files"],"hash":digest,"archive":archive.name}))
    finally:
        os.umask(old)
if __name__=="__main__":main()
