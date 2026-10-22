"""Read-only acceptance observation for an explicitly selected Windows app.

Never installs/starts a service, signs a permit, executes model text, reads
user tasks, exposes private keys, changes SQLite, or claims reviewer APPROVE.
A local operator runs it and keeps the output locally until safe to share.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
import hashlib
from pathlib import Path
import sqlite3
import stat
import re
import subprocess

PINNED={
    "core":("1c4ccd7d64e87e284a3796b3432f13910a48679c",
            ("one_task_core.py",)),
    "host":("2c92e102efed49e62eac1bc0e434b3d412d62e40",
            ("windows_scm_sandbox_receiver.py","windows_named_pipe_pilot_receiver.py",
             "windows_scm_ci_worker.py","signed_effect_permit.py")),
    "providers":("827b654d9f7c6a10a9b90a9c97802e63116711b9",
            ("ollama_worker.py","local_qwen.py","provider_interface.py",
             "evidence_receipt.py","durable_budget.py","coordinator_adapter.py",
             "windows_private_acl.py")),
    "coordinator":("ad82e853d9db2a0567c61e8d9a3f1e5f62905271",
            ("mvp_task_exchange.py","mvp_status_projection.py","release_readiness.py")),
}
ANCHORED_BLOBS={
    "core/one_task_core.py": "b43f4217f0756154fe3d3e6fafd007762c5b5117",
    "host/windows_scm_sandbox_receiver.py": "8232aa365c9baed1b75f14fc8d47f2224e2b1487",
    "host/windows_named_pipe_pilot_receiver.py": "a3b01ad2e281eca40d13869fed6fbed5ffbe88b1",
    "host/windows_scm_ci_worker.py": "e5444b9485950cec360058b10c84331b2d60700c",
    "host/signed_effect_permit.py": "2f6cb04295536edd7d834f39d364af4786b22d23",
    "providers/windows_private_acl.py": "efc006a22c6deea911b0384a10acfe11e27d2821",
    "providers/ollama_worker.py": "8effd007628db0f144e7b5ddf9d835edd3476887",
    "providers/local_qwen.py": "278ea77977ea5c43df7fe2d60fd69222660da7ca",
    "providers/provider_interface.py": "04404e8cd992d858a77ea6f5f15124ec1e65a3c6",
    "providers/evidence_receipt.py": "8a0c73cce57f39b3738e733af16c533d2fe6f3da",
    "providers/durable_budget.py": "e7cbdc706ab1637ed0194c046bc10ec55d456552",
    "providers/coordinator_adapter.py": "f45cc3c5fa56197d8e27b19da93c3d3f59566123",
    "coordinator/mvp_task_exchange.py": "2c38b0f18f5dc6c0424748b736f448e1f4f09b2c",
    "coordinator/mvp_status_projection.py": "5c982826d3c57782396ec6385358ab3e1870428f",
    "coordinator/release_readiness.py": "1ead614c65898fc75074a41e55fd49817d639b5a",
}
MANIFEST_FIELDS={"schema","source","core_queue_wired","host_service_enrolled",
                 "model_weights_verified","release_approved","handoff_enabled",
                 "independent_review_complete","entries"}
ENTRY_FIELDS={"role","file","source_commit","git_blob","sha256","bytes"}

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

def _verify_installed_components(components):
    manifest=components/"manifest.json"
    _regular(manifest,limit=32768)
    try:
        doc=json.loads(manifest.read_bytes())
    except (UnicodeError,TypeError,ValueError,RecursionError) as exc:
        raise PhysicalAcceptanceDenied("Invalid component manifest") from exc
    if (type(doc) is not dict or set(doc)!=MANIFEST_FIELDS or
            doc.get("schema")!="neurofactory.installed_components.v1" or
            doc.get("source")!="pinned_git_blobs_only" or
            any(doc.get(field) is not False for field in (
                "core_queue_wired","host_service_enrolled","model_weights_verified",
                "release_approved","handoff_enabled","independent_review_complete")) or
            type(doc.get("entries")) is not list or
            len(doc["entries"])!=15):
        _deny("noninert or unverified pinned component list")
    required={(role,name) for role,(commit,names) in PINNED.items()
              for name in names}
    seen=set()
    for entry in doc["entries"]:
        if type(entry) is not dict or set(entry)!=ENTRY_FIELDS:
            _deny("unexpected manifest entry")
        role,name=entry.get("role"),entry.get("file")
        if (type(role) is not str or type(name) is not str or
                (role,name) not in required or (role,name) in seen):
            _deny("duplicate or unknown pinned source component")
        expected_commit=PINNED[role][0]
        expected_blob=ANCHORED_BLOBS[role+"/"+name]
        if (entry.get("source_commit")!=expected_commit or
                entry.get("git_blob")!=expected_blob or
                type(entry.get("sha256")) is not str or
                not re.fullmatch(r"[a-f0-9]{64}",entry["sha256"]) or
                type(entry.get("bytes")) is not int or
                not 0<entry["bytes"]<=250000):
            _deny("unapproved Git commit, digest or file length")
        folder=_directory(components/role)
        candidate=_regular(folder/name)
        raw=candidate.read_bytes()
        if len(raw)!=entry["bytes"] or sha256(raw).hexdigest()!=entry["sha256"]:
            _deny("installed source hash differs from pinned manifest")
        blob=hashlib.sha1(
            b"blob "+str(len(raw)).encode("ascii")+b"\x00"+raw).hexdigest()
        if blob!=expected_blob:
            _deny("installed blob differs from separately anchored Git source")
        seen.add((role,name))
    if seen!=required:
        _deny("missing mandatory pinned components")
    return len(seen)


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
    # Independent *bytes-only* verification; do NOT import or execute an
    # installed module before it has already been authenticated.
    verified_count=_verify_installed_components(components)
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
        "installed_pinned_component_count":verified_count,
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
