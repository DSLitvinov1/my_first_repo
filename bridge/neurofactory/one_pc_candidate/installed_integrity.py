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
             "evidence_receipt.py","durable_budget.py","coordinator_adapter.py",
             "windows_private_acl.py")),
    "coordinator":("ad82e853d9db2a0567c61e8d9a3f1e5f62905271",
            ("mvp_task_exchange.py","mvp_status_projection.py","release_readiness.py")),
}
ANCHORED_BLOBS={
    "core/one_task_core.py": "ab1471813c6da29407c913b974a2209467a4b961",
    "core/offline_os_receiver_client.py": "417f7c1713c8333ff10a79962aafecf87a863cff",
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
        if (item["git_blob"]!=ANCHORED_BLOBS[role+"/"+name] or
            item["source_commit"]!=commit or
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
