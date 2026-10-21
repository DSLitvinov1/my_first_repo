"""Offline one-PC SQLite restore into a NEW user-chosen directory.

Never modifies the active workspace, never replays tasks, and cannot start CORE,
HOST, Qwen or a service. Stop the application before switching data directories.
"""
from __future__ import annotations
import argparse
from contextlib import closing
from hashlib import sha256
from pathlib import Path
import os
import shutil
import sqlite3
import stat

TABLES_V2=frozenset(("projects","tasks","history","model_checks"))
TABLES_V3=TABLES_V2 | {"task_proposals"}
MAX_BACKUP_BYTES=100_000_000
class RestoreDenied(ValueError): pass

def _regular(path):
    if path.is_symlink() or not path.is_file():
        raise RestoreDenied("Backup is missing, not regular or linked")
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or (
        os.name=="nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RestoreDenied("Reparse or irregular backup refused")
    if not 0<info.st_size<=MAX_BACKUP_BYTES:
        raise RestoreDenied("Backup size refused")

def _validate(con):
    con.execute("PRAGMA trusted_schema=OFF")
    if con.execute("PRAGMA integrity_check").fetchone()!=( "ok",):
        raise RestoreDenied("Backup integrity check failed")
    if con.execute("PRAGMA foreign_key_check").fetchone():
        raise RestoreDenied("Backup references damaged")
    version=con.execute("PRAGMA user_version").fetchone()[0]
    if version not in (2,3):
        raise RestoreDenied("Unsupported backup format")
    required=TABLES_V3 if version==3 else TABLES_V2
    tables=con.execute(
        "SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
    ).fetchall()
    if set(tables)!={(name,"table") for name in required}:
        raise RestoreDenied("Unknown or missing database schema objects")
    for name in required:
        if not con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)
        ).fetchone():
            raise RestoreDenied("Required table missing")
    if con.execute(
        "SELECT 1 FROM tasks WHERE state<>'DRAFT_PENDING_OWNER_AUTH' LIMIT 1"
    ).fetchone():
        raise RestoreDenied("Unexpected executable task checkpoint")
    if con.execute("SELECT 1 FROM model_checks WHERE provenance_attested<>0 LIMIT 1").fetchone():
        raise RestoreDenied("Unverified model evidence unexpectedly promoted")
    if version==3:
        from string import hexdigits
        for status,model,text,digest,response in con.execute(
            "SELECT status,model,proposal_text,content_sha256,response_sha256 "
            "FROM task_proposals"):
            if model not in ("qwen3:0.6b","qwen2.5-coder:1.5b"):
                raise RestoreDenied("Unapproved proposal model")
            if status=="PROPOSED_UNVERIFIED":
                if (type(text) is not str or not 1<=len(text.encode("utf-8"))<=12000
                    or type(digest) is not str or
                    sha256(text.encode("utf-8")).hexdigest()!=digest or
                    type(response) is not str or len(response)!=64
                    or any(ch not in "0123456789abcdef" for ch in response)):
                    raise RestoreDenied("Corrupted draft provider proposal")
            elif status in ("REQUESTED","UNKNOWN","INVALID_MODEL_OUTPUT","BLOCKED"):
                if text is not None or digest is not None or response is not None:
                    raise RestoreDenied("Untrusted proposal incorrectly checkpointed")
            else:
                raise RestoreDenied("Unknown draft provider status")

def restore(backup:Path,target_dir:Path):
    backup=Path(backup)
    target_dir=Path(target_dir)
    if not backup.is_absolute() or not target_dir.is_absolute():
        raise RestoreDenied("Paths must be absolute")
    _regular(backup)
    if target_dir.exists() or target_dir.is_symlink():
        raise RestoreDenied("Never overwrite existing data")
    parent=target_dir.parent
    if not parent.is_dir() or parent.is_symlink():
        raise RestoreDenied("Unsafe destination parent")
    if os.name=="nt" and parent.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise RestoreDenied("Reparse destination parent")
    read_only_uri=backup.as_uri()+"?mode=ro"
    with closing(sqlite3.connect(read_only_uri,uri=True,timeout=8)) as src:
        _validate(src)
        try:
            os.mkdir(target_dir,0o700)
        except FileExistsError as exc:
            raise RestoreDenied("Destination already exists") from exc
        finished=False
        try:
            newdb=target_dir/"workspace.sqlite3"
            with closing(sqlite3.connect(newdb,timeout=8)) as dest:
                src.backup(dest)
                _validate(dest)
                dest.commit()
            finished=True
        finally:
            if not finished:
                shutil.rmtree(target_dir,ignore_errors=True)
    return {"state":"RESTORED_DRAFT_DATA_ONLY","live_execution_allowed":False,
            "destination":str(target_dir/"workspace.sqlite3")}

def main():
    p=argparse.ArgumentParser(description="Restore verified draft-only workspace to NEW directory")
    p.add_argument("--backup",required=True,type=Path)
    p.add_argument("--new-data-dir",required=True,type=Path)
    args=p.parse_args()
    result=restore(args.backup,args.new_data_dir)
    print(result["state"])
    print("NF_RESTORE_NO_LIVE_QUEUE_NO_SERVICE=PASS")

if __name__=="__main__":
    main()
