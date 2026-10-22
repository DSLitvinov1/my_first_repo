"""Read-only acceptance observation for an explicitly selected Windows app.

Never installs/starts a service, signs a permit, executes model text, reads
user tasks, exposes private keys, changes SQLite, or claims reviewer APPROVE.
A local operator runs it and keeps the output locally until safe to share.
"""
from __future__ import annotations
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys

class PhysicalAcceptanceDenied(ValueError):
    pass

def _deny(reason):
    raise PhysicalAcceptanceDenied("Read-only physical acceptance blocked: "+reason)

def _regular(path, limit=250_000):
    if not path.is_file() or path.is_symlink():
        _deny("missing or linked installed file")
    st=path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_size>limit or st.st_size<1
            or (os.name=="nt" and st.st_file_attributes & 0x400)):
        _deny("oversized, empty or reparse-point file")
    return path

def _directory(path):
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        _deny("only a real absolute local directory is eligible")
    if os.name=="nt" and path.lstat().st_file_attributes & 0x400:
        _deny("linked or reparse-point installation root")
    return path

def _scm_present(name):
    if os.name!="nt":
        _deny("OS status requires real Windows")
    try:
        out=subprocess.run(["sc.exe","query",name],capture_output=True,
                           text=True,timeout=8,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise PhysicalAcceptanceDenied("Windows SCM status unavailable") from exc
    if out.returncode == 0:
        return True
    # SCM error 1060 means the named service is genuinely absent.
    if "1060" in out.stdout or "1060" in out.stderr:
        return False
    _deny("service status unknown; fail closed")

def observe(app_dir:Path, data_dir:Path):
    if os.name!="nt":
        _deny("physical Windows-only report")
    app=_directory(app_dir)
    data=_directory(data_dir)
    for file in ("app/local_workspace.py","app/installed_integrity.py",
                 "ui/index.html","ui/integrations.js",
                 "runtime/python.exe","start_neurofactory.cmd"):
        _regular(app/file, limit=30_000_000 if file.endswith("python.exe") else 500_000)
    components=_directory(app/"components")
    import_path=app/"app/installed_integrity.py"
    spec=importlib.util.spec_from_file_location("nf_physical_installed_integrity",import_path)
    if not spec or not spec.loader:
        _deny("cannot import pinned source checker")
    loaded=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    verification=loaded.verify(components)
    if (verification["files_verified"]!=15
            or verification["live_execution_allowed"] is not False):
        _deny("installed 15-file source candidate changed")
    db=data/"workspace.sqlite3"
    _regular(db,limit=100_000_000)
    # sqlite immutable mode never asks SQLite to create WAL, shm or journals.
    # We intentionally avoid querying user projects, tasks, contents or keys.
    try:
        with sqlite3.connect(db.as_uri()+"?mode=ro&immutable=1",uri=True,timeout=3) as conn:
            conn.execute("PRAGMA query_only=ON")
            schema=conn.execute("PRAGMA user_version").fetchone()[0]
            if schema not in (1,2,3):
                _deny("unknown user data database version")
    except (sqlite3.Error,ValueError,OSError) as exc:
        raise PhysicalAcceptanceDenied("Database read-only check failed") from exc
    backups=data/"backups"
    backup_count=0
    if backups.exists():
        if not backups.is_dir() or backups.is_symlink():
            _deny("untrusted backup directory")
        backup_count=sum(1 for p in backups.iterdir()
                         if p.is_file() and not p.is_symlink() and
                         p.name.startswith("workspace-") and
                         p.name.endswith(".sqlite3"))
    # Every CI-only service must be ABSENT from the owner PC. A leftover
    # disposable fixture is not a production protected service.
    ci_names=("NeurofactorySandboxReceiverCI","NeurofactoryCoreAdmissionCI")
    ci_status={name:_scm_present(name) for name in ci_names}
    if any(ci_status.values()):
        _deny("test SCM service installed on physical Windows")
    return {
        "schema":"nf.onepc.physical_readonly_acceptance.v1",
        "status":"PHYSICAL_DRAFT_INSPECTED_NO_RELEASE",
        "installed_pinned_component_count":verification["files_verified"],
        "database_schema_version":schema,
        "local_backup_file_count":backup_count,
        "test_services_absent":True,
        "installed_files_verified":True,
        "actual_qwen_inference_verified_on_this_pc":False,
        "production_scm_service_verified_on_this_pc":False,
        "owner_and_independent_reviewer_key_enrollment_verified":False,
        "signed_independent_review_approved":False,
        "separate_rollback_witness_verified":False,
        "data_restoration_on_this_pc_verified":False,
        "core_live_queue_enabled":False,
        "auto_execution_allowed":False,
        "production_handoff_allowed":False,
        "release_status":"BLOCKED_OWNER_OPERATOR_INDEPENDENT_REVIEW",
        "read_only":True,
    }

def main(args=None):
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("--installed-app",type=Path,required=True)
    parser.add_argument("--user-data",type=Path,required=True)
    opt=parser.parse_args(args)
    report=observe(opt.installed_app,opt.user_data)
    print(json.dumps(report,ensure_ascii=True,sort_keys=True))
    print("NF_PHYSICAL_LOCAL_READONLY_EVIDENCE=NO_RELEASE_AND_NO_EFFECTS")

if __name__=="__main__":
    main()
