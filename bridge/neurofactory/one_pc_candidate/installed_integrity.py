"""Fail-closed integrity check of installed pinned source components.

Checking packaged source does NOT authorize CORE dispatch, model effects,
Windows service enrollment, owner approval or release.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PINNED={
    "core":("beb08eff32923d8ca364aabfde0458f380acf8e7",
            ("one_task_core.py","offline_os_receiver_client.py")),
    "host":("2c92e102efed49e62eac1bc0e434b3d412d62e40",
            ("windows_scm_sandbox_receiver.py","windows_named_pipe_pilot_receiver.py",
             "windows_scm_ci_worker.py","signed_effect_permit.py")),
    "providers":("827b654d9f7c6a10a9b90a9c97802e63116711b9",
            ("ollama_worker.py","local_qwen.py","provider_interface.py",
             "evidence_receipt.py","durable_budget.py","coordinator_adapter.py")),
    "coordinator":("ad82e853d9db2a0567c61e8d9a3f1e5f62905271",
            ("mvp_task_exchange.py","mvp_status_projection.py","release_readiness.py")),
}
MANIFEST_FIELDS={"schema","source","core_queue_wired","host_service_enrolled",
                 "model_weights_verified","release_approved","handoff_enabled",
                 "independent_review_complete","entries"}
ENTRY_FIELDS={"role","file","source_commit","git_blob","sha256","bytes"}

class IntegrityDenied(ValueError):
    pass

def regular_file(path: Path):
    if path.is_symlink() or not path.is_file():
        raise IntegrityDenied("Missing or linked component file")
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or (
        os.name=="nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise IntegrityDenied("Unsafe component file type")
    if not 0<info.st_size<=250_000:
        raise IntegrityDenied("Oversized or empty component")
    return info.st_size

def verify(root):
    root=Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise IntegrityDenied("Unsafe components directory")
    if os.name=="nt" and root.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise IntegrityDenied("Reparse components directory")
    manifest_file=root/"manifest.json"
    if regular_file(manifest_file)>32_768:
        raise IntegrityDenied("Oversized manifest")
    try:
        doc=json.loads(manifest_file.read_text(encoding="utf-8"))
    except (UnicodeError,ValueError) as exc:
        raise IntegrityDenied("Invalid components manifest") from exc
    if (type(doc) is not dict or set(doc)!=MANIFEST_FIELDS or
        doc["schema"]!="neurofactory.installed_components.v1" or
        doc["source"]!="pinned_git_blobs_only" or
        any(doc[k] is not False for k in (
            "core_queue_wired","host_service_enrolled","model_weights_verified",
            "release_approved","handoff_enabled","independent_review_complete")) or
        type(doc["entries"]) is not list or
        len(doc["entries"])!=sum(len(files) for _,files in PINNED.values())):
        raise IntegrityDenied("Unsafe or incompatible manifest")
    expected={(role,name) for role,(_,files) in PINNED.items() for name in files}
    seen=set()
    for item in doc["entries"]:
        if type(item) is not dict or set(item)!=ENTRY_FIELDS:
            raise IntegrityDenied("Malformed component entry")
        role=item.get("role")
        name=item.get("file")
        if type(role) is not str or type(name) is not str or (role,name) not in expected:
            raise IntegrityDenied("Unexpected component role or path")
        if (role,name) in seen:
            raise IntegrityDenied("Duplicate component")
        seen.add((role,name))
        commit,names=PINNED[role]
        if (item["source_commit"]!=commit or
            type(item["git_blob"]) is not str or
            not re.fullmatch(r"[a-f0-9]{40}",item["git_blob"]) or
            type(item["sha256"]) is not str or
            not re.fullmatch(r"[a-f0-9]{64}",item["sha256"]) or
            type(item["bytes"]) is not int or
            not 0<item["bytes"]<=250_000):
            raise IntegrityDenied("Unverified pinned component")
        folder=root/role
        if folder.is_symlink() or not folder.is_dir():
            raise IntegrityDenied("Linked component folder")
        if os.name=="nt" and folder.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise IntegrityDenied("Reparse component folder")
        path=folder/name
        if regular_file(path)!=item["bytes"]:
            raise IntegrityDenied("Component size mismatch")
        data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=item["sha256"]:
            raise IntegrityDenied("Installed component modified")
        git_fingerprint=hashlib.sha1(
            b"blob "+str(len(data)).encode("ascii")+b"\x00"+data
        ).hexdigest()
        if git_fingerprint!=item["git_blob"]:
            raise IntegrityDenied("Git blob identity mismatch")
    if seen!=expected:
        raise IntegrityDenied("Components missing")
    # Explicitly immutable return: no method here can start services or queues.
    return {"integrity":"PINNED_FILES_VERIFIED_NOT_AUTHORIZED",
            "files_verified":len(expected),"live_execution_allowed":False,
            "service_installed_by_this_check":False}
