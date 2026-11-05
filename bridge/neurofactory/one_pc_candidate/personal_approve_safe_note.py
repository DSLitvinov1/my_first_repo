"""Explicit Windows owner approval for ONE safe note, not Qwen execution.

Run only in the owner's interactive user session. The user must choose exact
text/task/project and issue a one-time approval. Never mint a signature
inside the SCM service, model agent, remote SSH server or GitHub Actions.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from personal_ssh_highwater import _canon
from personal_windows_host_service import (
    OWNER_DOMAIN,PERMIT_SCHEMA,ALLOWED_ACTION,CONFIG,
    CONFIG_SCHEMA,INBOX,_unique,_decode_pub,
)

SHA32=re.compile(r"[a-f0-9]{32}\Z")


def _secure_key_dir(directory:Path):
    if (os.name!="nt" or not isinstance(directory,Path)
            or not directory.is_absolute() or directory.is_symlink()
            or not directory.is_dir()):
        raise ValueError("Existing secure owner-key directory required")
    return directory


def _key_file(folder):
    f=_secure_key_dir(folder)/"personal-owner-private.key"
    if f.is_symlink() or not f.is_file():
        raise ValueError("Owner private key unavailable or redirected")
    if len(f.read_bytes())!=32:
        raise ValueError("Invalid owner key size")
    return f


def provision_owner(folder:Path):
    folder=_secure_key_dir(folder)
    key=folder/"personal-owner-private.key"
    if key.exists() or key.is_symlink():
        raise ValueError("Owner key exists: NEVER overwrite")
    signer=Ed25519PrivateKey.generate()
    private=signer.private_bytes(
        serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    with key.open("xb") as out:
        out.write(private)
        out.flush()
        os.fsync(out.fileno())
    pub=signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    result={
        "status":"OWNER_IDENTITY_CREATED_LOCALLY_NOT_SHARED",
        "owner_public_base64":base64.b64encode(pub).decode("ascii"),
        "owner_private_key_exported":False,
        "automatic_model_authorization":False,
    }
    return result


def approve_one_note(*,owner_folder:Path,task_id:str,project_id:str,
                     text_file:Path,epoch:int):
    if (type(task_id) is not str or not SHA32.fullmatch(task_id)
            or type(project_id) is not str or not SHA32.fullmatch(project_id)
            or type(epoch) is not int or not 1<=epoch<2**62):
        raise ValueError("Explicit one-time task/project/epoch required")
    private=Ed25519PrivateKey.from_private_bytes(
        _key_file(owner_folder).read_bytes())
    if (not isinstance(text_file,Path) or not text_file.is_absolute()
            or text_file.is_symlink() or not text_file.is_file()
            or not 1<=text_file.stat().st_size<=2048):
        raise ValueError("Owner-selected safe note text required")
    text=text_file.read_text(encoding="utf-8")
    if not 1<=len(text.encode("utf-8"))<=2048:
        raise ValueError("Selected note outside 2KiB bounds")
    operator=json.loads(CONFIG.read_text(encoding="ascii"),
                        object_pairs_hook=_unique)
    if operator.get("schema")!=CONFIG_SCHEMA:
        raise ValueError("Owner-pinned SCM config not valid")
    pinned=_decode_pub(operator["owner_public_base64"])
    actual=private.public_key()
    if actual.public_bytes_raw()!=pinned.public_bytes_raw():
        raise ValueError("Owner signing identity not the actual pinned operator")
    now=int(time.time())
    body={
        "schema":PERMIT_SCHEMA,"task_id":task_id,
        "project_id":project_id,
        "nonce":secrets.token_hex(16),
        "external_epoch":epoch,
        "issued_unix":now,
        "expires_unix":now+85,
        "source_sha40":operator["source_sha40"],
        "machine_sha256":operator["machine_sha256"],
        "package_sha256":operator["package_sha256"],
        "operation":ALLOWED_ACTION,
        "text":text,
    }
    signature=private.sign(OWNER_DOMAIN+_canon(body))
    packet={**body,
            "owner_signature_base64":base64.b64encode(signature).decode("ascii")}
    if not INBOX.is_dir() or INBOX.is_symlink():
        raise ValueError("Protected Windows service inbox not installed")
    target=INBOX/(task_id+".json")
    if target.exists() or target.is_symlink():
        raise ValueError("Task already submitted: never retry")
    with target.open("x",encoding="utf-8") as output:
        json.dump(packet,output,ensure_ascii=False,
                  sort_keys=True,separators=(",",":"))
        output.flush()
        os.fsync(output.fileno())
    return {
        "status":"EXPLICIT_OWNER_SIGNED_SAFE_NOTE_SUBMITTED_ONCE",
        "task_id":task_id,"external_epoch":epoch,
        "owner_key_custody":"USER_ONLY",
        "remote_witness_result":"PENDING_ASYNC_NEVER_AUTO_RETRY",
        "system_command_execution_enabled":False,
    }


def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("action",choices=("provision-owner","approve-note"))
    p.add_argument("--owner-folder",required=True)
    p.add_argument("--task-id")
    p.add_argument("--project-id")
    p.add_argument("--text-file")
    p.add_argument("--epoch",type=int)
    args=p.parse_args(argv)
    folder=Path(args.owner_folder)
    if args.action=="provision-owner":
        result=provision_owner(folder)
    else:
        if not args.text_file or args.epoch is None:
            raise SystemExit("Explicit text and epoch required; do not guess/retry")
        result=approve_one_note(
            owner_folder=folder,
            task_id=args.task_id,project_id=args.project_id,
            text_file=Path(args.text_file),epoch=args.epoch)
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
