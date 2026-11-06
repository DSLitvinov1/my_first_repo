"""Interactive CORE/Qwen -> personal HOST CREATE_NEW source approval.

The locally saved Qwen proposal is untrusted. This controller independently
reads the existing CORE workspace SQLite (mode=ro), confirms project/task
membership and the exact saved model response SHA256, shows the entire file
to the owner and re-reads it before the owner signs one bounded action.

No API/browser/model has access to this Ed25519 private key. The resulting
signed envelope can be consumed by the already restricted LocalService HOST.
The HOST verifies the exact CORE permission and a distinct owner signature,
then requires durable local UNKNOWN + Linux signed epoch before creating
one source file. Source files are NEVER executed automatically.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from personal_approve_safe_note import _key_file, _decode_pub, _unique
from personal_approve_workspace_draft import owner_approvable_saved_draft
from personal_ssh_highwater import _canon
from personal_project_file_effect import (
    PROJECT_FILE_ACTION,PROJECT_FILE_SCHEMA,CORE_PERMISSION_SCHEMA,
    OWNER_FILE_DOMAIN,MAX_CONTENT,check_core_permission,project_target,
)

def _read_config(root):
    config=root/"operator-config.json"
    if (not root.is_absolute() or root.is_symlink() or
            config.is_symlink() or not config.is_file()):
        raise ValueError("Operator-pinned LocalService root not installed")
    operator=json.loads(config.read_text("ascii"),object_pairs_hook=_unique)
    if (type(operator) is not dict or
            set(operator)!={
                "schema","owner_public_base64","witness_public_base64",
                "source_sha40","machine_sha256","package_sha256"
            } or operator["schema"]!="nf.personal.host.operator_pinned.v1"):
        raise ValueError("Actual protected Windows operator policy not present")
    return operator


def _submit_exact_qwen_project_file(*,workspace,owner_folder,root,
                                    task_id,epoch,relative_path):
    """Takes effect only with a real human at an interactive owner console."""
    if (os.name!="nt" or not sys.stdin.isatty() or not sys.stdout.isatty()
            or type(epoch) is not int or not 1<=epoch<2**62):
        raise ValueError("Interactive Windows owner + exact next epoch required")
    proposal=owner_approvable_saved_draft(workspace,task_id)
    source=proposal["text"]
    raw=source.encode("utf-8")
    if not 1<=len(raw)<=MAX_CONTENT:
        raise ValueError("Qwen draft too large for one owner-reviewed file")
    projects=root/"projects"
    # An operator-created service-SID project folder is a prerequisite.
    project_target(projects,proposal["project_id"],relative_path)
    if (projects/proposal["project_id"]/relative_path).exists():
        raise ValueError("Project output exists, no overwrite")
    operator=_read_config(root)
    owner=Ed25519PrivateKey.from_private_bytes(_key_file(owner_folder).read_bytes())
    if (owner.public_key().public_bytes_raw()!=
            _decode_pub(operator["owner_public_base64"]).public_bytes_raw()):
        raise ValueError("Wrong owner identity: cannot mint CORE permission")
    print("НЕЙРОЗАВОД / CORE: одно действие с файлом проекта",flush=True)
    print("Проект:",proposal["project_name"],flush=True)
    print("Задача:",proposal["objective"],flush=True)
    print("Qwen SHA256:",proposal["text_sha256"],flush=True)
    print("Файл:",relative_path,flush=True)
    print("Номер подтверждения Linux:",epoch,flush=True)
    print("----- ТОЧНЫЙ КОД ИЛИ ТЕКСТ QWEN -----",flush=True)
    print(source,flush=True)
    print("----- КОНЕЦ ТЕКСТА -----",flush=True)
    confirmation="СОЗДАТЬ "+task_id[:8]
    if input("Только создать файл, без выполнения кода? Введите "+
             confirmation+": ").strip()!=confirmation:
        raise ValueError("Owner did not approve exact source file")
    current=owner_approvable_saved_draft(workspace,task_id)
    if current!=proposal:
        raise ValueError("CORE/Qwen draft changed while owner reviewed")
    project_target(projects,proposal["project_id"],relative_path)
    if (projects/proposal["project_id"]/relative_path).exists():
        raise ValueError("File appeared while awaiting approval")
    now=int(time.time())
    permission={
        "schema":CORE_PERMISSION_SCHEMA,
        "task_id":task_id,
        "project_id":proposal["project_id"],
        "model":"qwen3.5:9b",
        "draft_sha256":proposal["text_sha256"],
        "operation":PROJECT_FILE_ACTION,
        "relative_path":relative_path,
        "content_sha256":proposal["text_sha256"],
        "max_bytes":MAX_CONTENT,
        "owner_reviewed":True,
    }
    # Do not assume the saved draft always came from the 9B: bind to actual
    # immutable SQLite model as verified by the same task join.
    db=workspace/"workspace.sqlite3"
    with closing(sqlite3.connect(db.as_uri()+"?mode=ro",uri=True,timeout=3)) as con:
        row=con.execute(
            "SELECT model,status,content_sha256 FROM task_proposals WHERE task_id=?",
            (task_id,)).fetchone()
    if (row is None or row[1]!="PROPOSED_UNVERIFIED" or
            row[2]!=proposal["text_sha256"] or
            row[0] not in ("qwen3.5:9b","qwen2.5-coder:1.5b")):
        raise ValueError("Cannot pin actual Qwen model to CORE task")
    permission["model"]=row[0]
    body={
        "schema":PROJECT_FILE_SCHEMA,
        "task_id":task_id,
        "project_id":proposal["project_id"],
        "nonce":secrets.token_hex(16),
        "external_epoch":epoch,
        "issued_unix":now,
        "expires_unix":now+85,
        "source_sha40":operator["source_sha40"],
        "machine_sha256":operator["machine_sha256"],
        "package_sha256":operator["package_sha256"],
        "operation":PROJECT_FILE_ACTION,
        "relative_path":relative_path,
        "text":source,
        "content_sha256":proposal["text_sha256"],
        "core_permission":permission,
    }
    check_core_permission(body)
    envelope={
        **body,
        "owner_signature_base64":base64.b64encode(
            owner.sign(OWNER_FILE_DOMAIN+_canon(body))).decode("ascii")
    }
    inbox=root/"inbox"
    if not inbox.is_dir() or inbox.is_symlink():
        raise ValueError("Protected service inbox missing")
    target=inbox/(task_id+".json")
    if target.exists() or target.is_symlink():
        raise ValueError("Task already submitted: never replay")
    with target.open("x",encoding="utf-8") as dest:
        json.dump(envelope,dest,ensure_ascii=True,
                  sort_keys=True,separators=(",",":"))
        dest.flush()
        os.fsync(dest.fileno())
    return {
        "status":"OWNER_AND_CORE_REVIEWED_QWEN_PROJECT_FILE_SUBMITTED_ONCE",
        "task_id":task_id,
        "project_id":proposal["project_id"],
        "relative_path":relative_path,
        "content_sha256":proposal["text_sha256"],
        "model":permission["model"],
        "external_epoch":epoch,
        "host_execution_status":"PENDING_SIGNED_LINUX_ACK_NO_RETRY",
        "generated_source_executed":False,
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--task-id",required=True)
    ap.add_argument("--relative-file",required=True)
    ap.add_argument("--epoch",type=int,required=True)
    args=ap.parse_args()
    if os.name!="nt":
        raise SystemExit("Windows owner terminal required")
    workspace=Path(os.environ["LOCALAPPDATA"])/"NeurofactoryData"
    root=Path(os.environ.get("ProgramData",r"C:\ProgramData"))/"NeurofactoryPersonalHost"
    result=_submit_exact_qwen_project_file(
        workspace=workspace,owner_folder=workspace/"owner-signing",
        root=root,task_id=args.task_id,epoch=args.epoch,
        relative_path=args.relative_file)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))


if __name__=="__main__":
    main()
