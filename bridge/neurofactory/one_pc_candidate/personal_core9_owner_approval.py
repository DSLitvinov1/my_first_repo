"""Owner-facing Windows-only approval: one existing Qwen draft -> REAL CORE #9
one-task signed admission -> protected LocalService V2 owner-signed file request.

Both signatures are created ONLY in a real, interactive local owner console.
Never accepts model-generated paths, defaults to project filename chosen by owner.
No automatic retries after an ambiguous enqueue or submitted inbox packet.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from personal_approve_safe_note import _key_file, _decode_pub
from personal_approve_workspace_draft import owner_approvable_saved_draft
from personal_core_qwen_file_approval import _read_config
from personal_project_file_effect import (
    PROJECT_FILE_ACTION,PROJECT_FILE_SCHEMA,CORE_PERMISSION_SCHEMA,
    MAX_CONTENT,project_target,check_core_permission,
)
from personal_ssh_highwater import _canon
from signed_owner_admission import (
    prepare_draft_request,admit_signed_draft,AdmissionDenied,_canon as core_canon,
)
from local_workspace import WorkspaceStore
from one_task_core import OneTaskCore,EMPTY_SHA
from personal_core9_host_bridge import V2_SCHEMA,V2_DOMAIN,CORE_TARGET

ROOT=Path(os.environ.get("ProgramData",r"C:\ProgramData"))/"NeurofactoryPersonalHost"
CORE=ROOT/"core9"
WORKSPACE=Path(os.environ.get("LOCALAPPDATA",""))/"NeurofactoryData"


def approve_once(task_uuid,core_task_id,relative_path,epoch):
    if (os.name!="nt" or not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise ValueError("OWNER_ON_REAL_WINDOWS_CONSOLE_REQUIRED")
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Protected CORE admission requires owner administrator")
    operator=_read_config(ROOT)
    owner=Ed25519PrivateKey.from_private_bytes(
        _key_file(WORKSPACE/"owner-signing").read_bytes())
    if owner.public_key().public_bytes_raw()!=(
            _decode_pub(operator["owner_public_base64"]).public_bytes_raw()):
        raise ValueError("Trusted owner signing identity differs from installed host")
    if not (WORKSPACE/"workspace.sqlite3").is_file():
        raise ValueError("Existing SQLite Qwen workspace required")
    qwen=owner_approvable_saved_draft(WORKSPACE,task_uuid)
    store=WorkspaceStore(WORKSPACE)
    preview=prepare_draft_request(store,task_uuid)
    text=qwen["text"]
    digest=qwen["text_sha256"]
    if (preview["project_uuid"]!=qwen["project_id"]
            or preview["objective"]!=qwen["objective"]
            or not 1<=len(text.encode("utf-8"))<=MAX_CONTENT):
        raise ValueError("Saved Qwen proposal and CORE draft diverged")
    with sqlite3.connect(
            (WORKSPACE/"workspace.sqlite3").as_uri()+"?mode=ro",
            uri=True,timeout=3) as db:
        selected=db.execute(
            "SELECT model,status,content_sha256 FROM task_proposals WHERE task_id=?",
            (task_uuid,)).fetchone()
    if (selected is None or selected[1]!="PROPOSED_UNVERIFIED"
            or selected[2]!=digest
            or selected[0] not in ("qwen3.5:9b","qwen2.5-coder:1.5b")):
        raise ValueError("Exact Qwen result model/proposal not verified")
    model=selected[0]
    if (preview["model_preference"] not in ("auto",model)):
        raise ValueError("CORE task model differs from saved Qwen draft")
    target=project_target(ROOT/"projects",qwen["project_id"],relative_path)
    if target.exists() or target.is_symlink():
        raise ValueError("Destination file exists, no overwrites")
    core=OneTaskCore(CORE,CORE/"git")
    if core.snapshot()["state"]!="EMPTY":
        raise ValueError("CORE single-task queue already in use; no reset/replay")
    git=subprocess.run(
        ["git","-C",str(CORE/"git"),"rev-parse","HEAD"],
        stdin=subprocess.DEVNULL,capture_output=True,text=True,
        timeout=8,check=True).stdout.strip()
    if git!=operator["source_sha40"]:
        raise ValueError("Approved CORE Git checkout != protected installed source")
    with sqlite3.connect(
            (ROOT/"state"/"intent-fence.sqlite3").as_uri()+"?mode=ro",
            uri=True,timeout=3) as db:
        last=db.execute("SELECT max(external_epoch) FROM intents").fetchone()[0] or 0
        unknown=db.execute("SELECT count(*) FROM intents WHERE status='UNKNOWN_NO_AUTO_RETRY'").fetchone()[0]
    if unknown or type(epoch) is not int or epoch!=last+1:
        raise ValueError("Ambiguous or stale signed Linux epoch: never retry")
    spec={
        "schema":"neurofactory.core.task.v1",
        "task_id":core_task_id,
        "project_id":preview["core_project_id"],
        "target":CORE_TARGET,
        "objective":qwen["objective"],
        "source_sha":operator["source_sha40"],
        "source_sha256":EMPTY_SHA,
        "model":model,"reserved_units":100,
        "approval_commit":operator["source_sha40"],
    }
    print("NEUROFACTORY / ONE OWNER-APPROVED CORE9 / PROTECTED HOST",flush=True)
    print("CORE task:",core_task_id,flush=True)
    print("Saved Qwen task:",task_uuid,flush=True)
    print("Project:",qwen["project_name"],flush=True)
    print("Qwen model:",model,flush=True)
    print("Exact content SHA256:",digest,flush=True)
    print("New filename:",relative_path,flush=True)
    print("Next Linux epoch:",epoch,flush=True)
    print("Will create ONE UTF-8 file only, without executing ANY code.",flush=True)
    print("----- FULL QWEN TEXT -----",flush=True)
    print(text,flush=True)
    print("----- END QWEN TEXT -----",flush=True)
    phrase="СОЗДАТЬ "+task_uuid[:8]+" CORE "+core_task_id
    if input("Type exact phrase to sign BOTH CORE admission and HOST file: "+
             phrase+"\n> ").strip()!=phrase:
        raise ValueError("Owner did not approve this exact CORE and file pair")
    if owner_approvable_saved_draft(WORKSPACE,task_uuid)!=qwen:
        raise ValueError("Saved proposal changed during review")
    if target.exists() or target.is_symlink() or core.snapshot()["state"]!="EMPTY":
        raise ValueError("Task or protected output appeared during approval")
    now=int(time.time())
    core_body={
        "schema":"nf.onepc.owner_core_admission.v1",
        "scope":"OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION",
        "draft":preview,"spec":spec,"nonce":secrets.token_hex(16),
        "issued_at":now-1,"expires_at":now+180,
    }
    core_permit={
        **core_body,
        "owner_signature":base64.b64encode(
            owner.sign(b"NF_OWNER_CORE_ADMISSION_V1\x00"+core_canon(core_body))
        ).decode("ascii"),
    }
    permission={
        "schema":CORE_PERMISSION_SCHEMA,
        "task_id":task_uuid,"project_id":qwen["project_id"],
        "model":model,"draft_sha256":digest,
        "operation":PROJECT_FILE_ACTION,
        "relative_path":relative_path,"content_sha256":digest,
        "max_bytes":MAX_CONTENT,"owner_reviewed":True,
    }
    original={
        "schema":PROJECT_FILE_SCHEMA,
        "task_id":task_uuid,"project_id":qwen["project_id"],
        "nonce":secrets.token_hex(16),"external_epoch":epoch,
        "issued_unix":now,"expires_unix":now+85,
        "source_sha40":operator["source_sha40"],
        "machine_sha256":operator["machine_sha256"],
        "package_sha256":operator["package_sha256"],
        "operation":PROJECT_FILE_ACTION,
        "relative_path":relative_path,
        "text":text,"content_sha256":digest,
        "core_permission":permission,
    }
    check_core_permission(original)
    v2={
        **original,"schema":V2_SCHEMA,
        "core_task_id":core_task_id,
        "core_spec_sha256":sha256(core_canon(spec)).hexdigest(),
        "core_owner_permit":core_permit,
    }
    packet={
        **v2,"owner_signature_base64":base64.b64encode(
            owner.sign(V2_DOMAIN+_canon(v2))).decode("ascii")
    }
    if len(_canon(packet))>12000:
        raise ValueError("Combined owner authorization exceeds host limit")
    inbox=ROOT/"inbox"/(task_uuid+".json")
    if inbox.exists() or inbox.is_symlink():
        raise ValueError("Request already submitted; no replay")
    # CORE admission occurs only after human signature and all checks;
    # if writing the inbox fails, the existing CORE QUEUED state remains
    # blocking until explicitly inspected. No automatic reset.
    admitted=admit_signed_draft(store,core,core_permit,
                               owner_public_raw=owner.public_key().public_bytes_raw(),
                               now=now)
    if admitted.get("core_reported_state")!="QUEUED":
        raise ValueError("CORE signed admission not committed")
    with inbox.open("x",encoding="utf-8") as file:
        json.dump(packet,file,ensure_ascii=True,
                  separators=(",",":"),sort_keys=True)
        file.flush()
        os.fsync(file.fileno())
    print("OWNER_CORE9_AND_HOST_REQUEST_SUBMITTED_ONCE")
    print("CORE state QUEUED; protected SCM may CLAIM and perform one file.")
    print("No automatic retry if any later outcome is UNKNOWN.")


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--qwen-task-uuid",required=True)
    ap.add_argument("--core-task-id",required=True)
    ap.add_argument("--relative-file",required=True)
    ap.add_argument("--epoch",type=int,required=True)
    a=ap.parse_args()
    approve_once(a.qwen_task_uuid,a.core_task_id,a.relative_file,a.epoch)


if __name__=="__main__":
    main()
