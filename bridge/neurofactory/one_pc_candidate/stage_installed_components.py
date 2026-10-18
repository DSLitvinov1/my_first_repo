"""Stage exact original integration sources for the existing Windows installer.

Staging is NOT authority to run the CI-only Windows service, CORE queue, or Qwen.
Every component byte is read from an immutable Git commit, never a working file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SOURCE_FILES = {
    "core": ("bridge/neurofactory/development/core_owned/one_task_core.py",),
    "host_ci_only": (
        "bridge/neurofactory/trusted_host/windows_scm_sandbox_receiver.py",
        "bridge/neurofactory/trusted_host/windows_named_pipe_pilot_receiver.py",
        "bridge/neurofactory/trusted_host/windows_scm_ci_worker.py",
        "bridge/neurofactory/trusted_host/windows_scm_acl_crosscheck_ci.py",
    ),
    "providers": (
        "bridge/neurofactory/providers/ollama_worker.py",
        "bridge/neurofactory/providers/local_qwen.py",
        "bridge/neurofactory/providers/provider_interface.py",
        "bridge/neurofactory/providers/coordinator_adapter.py",
        "bridge/neurofactory/providers/evidence_receipt.py",
        "bridge/neurofactory/providers/durable_budget.py",
    ),
    "coordinator": (
        "bridge/neurofactory/coordination/mvp_status_projection.py",
        "bridge/neurofactory/coordination/mvp_task_exchange.py",
        "bridge/neurofactory/coordination/release_readiness.py",
    ),
}
PINS = {
    "providers": "827b654d9f7c6a10a9b90a9c97802e63116711b9",
    "coordinator": "ad82e853d9db2a0567c61e8d9a3f1e5f62905271",
}
MAX_FILE = 250_000


def git(repo: Path, *args: str) -> bytes:
    proc = subprocess.run(["git", "-C", str(repo), *args], check=False,
                          capture_output=True, timeout=25)
    if proc.returncode or len(proc.stdout) > MAX_FILE + 1024:
        raise ValueError("Pinned Git object missing, changed or oversized")
    return proc.stdout


def stage(root: Path, providers: Path, coordinator: Path, target: Path, source_sha: str):
    if not SHA40.fullmatch(source_sha):
        raise ValueError("Unpinned source commit")
    roots = {"core":root, "host_ci_only":root,
             "providers":providers, "coordinator":coordinator}
    revisions = {"core":source_sha, "host_ci_only":source_sha, **PINS}
    if target.exists() or target.is_symlink() or not target.is_absolute():
        raise ValueError("Refuse to overwrite component stage")
    if not target.parent.is_dir() or target.parent.is_symlink():
        raise ValueError("Unsafe destination parent")
    for role, repo in roots.items():
        if repo.is_symlink() or not repo.is_dir():
            raise ValueError("Invalid source checkout")
        actual=git(repo, "rev-parse", "HEAD").decode("ascii").strip()
        if actual != revisions[role]:
            raise ValueError("Git checkout differs from pinned revision "+role)
    target.mkdir(mode=0o700)
    evidence = []
    try:
        for role, files in SOURCE_FILES.items():
            for relative in files:
                repo=roots[role]
                tree=git(repo,"ls-tree","-z",revisions[role],"--",relative)
                if tree.count(b"\0")!=1 or not tree.startswith(b"100644 blob ") or (
                        tree.split(b"\t",1)[1]!=relative.encode("ascii")+b"\0"):
                    raise ValueError("Not an immutable regular pinned Git file: "+relative)
                raw=git(repo,"show",revisions[role]+":"+relative)
                if len(raw)==0 or len(raw)>MAX_FILE:
                    raise ValueError("Invalid component size")
                destination=target/role/Path(relative).name
                destination.parent.mkdir(mode=0o700,exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    raise ValueError("Duplicate staged component")
                destination.write_bytes(raw)
                evidence.append({
                    "role":role,"relative_path":role+"/"+destination.name,
                    "origin_path":relative,"origin_commit":revisions[role],
                    "bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
                })
        manifest={
            "schema":"neurofactory.onepc.components.unreleased.v1",
            "integration_source_commit":source_sha,
            "release_approved":False,
            "host_is_ci_only":True,
            "host_service_installed":False,
            "core_queue_dispatch_enabled":False,
            "model_inference_enabled":False,
            "owner_approval_present":False,
            "independent_review_passed":False,
            "files":evidence,
        }
        (target/"manifest.json").write_text(json.dumps(manifest,sort_keys=True,
                                 ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        return manifest
    except Exception:
        import shutil
        shutil.rmtree(target, ignore_errors=True)
        raise


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo",required=True,type=Path)
    parser.add_argument("--providers",required=True,type=Path)
    parser.add_argument("--coordinator",required=True,type=Path)
    parser.add_argument("--target",required=True,type=Path)
    parser.add_argument("--source-sha",required=True)
    args=parser.parse_args()
    manifest=stage(args.repo,args.providers,args.coordinator,
                   args.target,args.source_sha)
    print("NF_ONEPC_IMMUTABLE_COMPONENTS_STAGED="+str(len(manifest["files"])))
    print("NF_ONEPC_STAGED_HOST_ACTIVE=FALSE")
    print("NF_ONEPC_STAGED_REAL_QWEN_VERIFIED=FALSE")

if __name__=="__main__":
    main()
