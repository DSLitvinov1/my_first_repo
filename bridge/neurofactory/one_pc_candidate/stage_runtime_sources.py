"""Package immutable CORE/HOST/PROVIDERS/COORDINATOR code into the existing Windows installer.

This is file inclusion, NOT service enrollment, execution approval, or a release.
Read ONLY pinned Git objects; never copy mutable working-tree source.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

SOURCES = {
    "core": ("1c4ccd7d64e87e284a3796b3432f13910a48679c",
        "bridge/neurofactory/development/core_owned/",
        ("one_task_core.py",)),
    "host": ("2c92e102efed49e62eac1bc0e434b3d412d62e40",
        "bridge/neurofactory/trusted_host/",
        ("windows_scm_sandbox_receiver.py","windows_named_pipe_pilot_receiver.py",
         "windows_scm_ci_worker.py","signed_effect_permit.py")),
    "providers": ("827b654d9f7c6a10a9b90a9c97802e63116711b9",
        "bridge/neurofactory/providers/",
        ("ollama_worker.py","local_qwen.py","provider_interface.py",
         "evidence_receipt.py","durable_budget.py","coordinator_adapter.py",
         "windows_private_acl.py")),
    "coordinator": ("ad82e853d9db2a0567c61e8d9a3f1e5f62905271",
        "bridge/neurofactory/coordination/",
        ("mvp_task_exchange.py","mvp_status_projection.py","release_readiness.py")),
}
MAX_FILE=250_000

class PackagingDenied(RuntimeError):
    pass

def run_git(repo,*args):
    try:
        p=subprocess.run(["git","-C",str(repo),*args],capture_output=True,
                         timeout=20,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise PackagingDenied("Pinned Git source unavailable") from exc
    if p.returncode or len(p.stdout)>MAX_FILE+2048:
        raise PackagingDenied("Untrusted or oversized Git object")
    return p.stdout

def stage(inputs,root):
    root=Path(root).resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise PackagingDenied("Invalid stage root")
    components=root/"components"
    if components.exists() or components.is_symlink():
        raise PackagingDenied("Never overwrite staged components")
    verified=[]
    for role,(commit,prefix,names) in SOURCES.items():
        checkout=Path(inputs[role]).resolve(strict=True)
        if checkout.is_symlink() or not checkout.is_dir():
            raise PackagingDenied("Unsafe Git source directory")
        head=run_git(checkout,"rev-parse","HEAD").decode("ascii").strip()
        if head!=commit:
            raise PackagingDenied("Immutable source SHA differs: "+role)
        for name in names:
            if not re.fullmatch(r"[a-z][a-z0-9_]*\.py",name):
                raise PackagingDenied("Invalid component filename")
            repo_path=prefix+name
            line=run_git(checkout,"ls-tree","-z",commit,"--",repo_path)
            if line.count(b"\x00")!=1 or not line.startswith(b"100644 blob "):
                raise PackagingDenied("Regular pinned Git blob not available")
            meta,sep,path=line[:-1].partition(b"\t")
            if not sep or path!=repo_path.encode("ascii"):
                raise PackagingDenied("Unexpected Git tree path")
            blob=meta.split(b" ")[2].decode("ascii")
            if not re.fullmatch(r"[a-f0-9]{40}",blob):
                raise PackagingDenied("Git blob fingerprint invalid")
            raw=run_git(checkout,"cat-file","blob",blob)
            if not 0<len(raw)<=MAX_FILE or not raw.startswith(b'"""') and not raw.startswith(b"#"):
                raise PackagingDenied("Unexpected component source")
            verified.append((role,name,commit,blob,raw))
    components.mkdir()
    try:
        entries=[]
        for role,name,commit,blob,raw in verified:
            folder=components/role
            folder.mkdir(exist_ok=True)
            (folder/name).write_bytes(raw)
            entries.append({"role":role,"file":name,"source_commit":commit,
                            "git_blob":blob,"sha256":hashlib.sha256(raw).hexdigest(),
                            "bytes":len(raw)})
        manifest={
            "schema":"neurofactory.installed_components.v1",
            "source":"pinned_git_blobs_only",
            "core_queue_wired":False,
            "host_service_enrolled":False,
            "model_weights_verified":False,
            "release_approved":False,
            "handoff_enabled":False,
            "independent_review_complete":False,
            "entries":entries,
        }
        (components/"manifest.json").write_text(
            json.dumps(manifest,ensure_ascii=False,indent=2,sort_keys=True)+"\n",
            encoding="utf-8")
        return manifest
    except BaseException:
        import shutil
        shutil.rmtree(components,ignore_errors=True)
        raise

def main():
    p=argparse.ArgumentParser()
    for role in SOURCES:
        p.add_argument("--"+role,required=True,type=Path)
    p.add_argument("--stage",required=True,type=Path)
    args=p.parse_args()
    manifest=stage({role:getattr(args,role) for role in SOURCES},args.stage)
    print("NF_ONEPC_IMMUTABLE_SOURCE_COMPONENTS_STAGED="+str(len(manifest["entries"])))
    print("NF_ONEPC_HOST_SERVICE_AND_QUEUE=NOT_ENABLED_BY_PACKAGING")

if __name__=="__main__":
    main()
