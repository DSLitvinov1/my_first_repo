"""Two DIFFERENT Windows token SID test actor. GitHub disposable runner ONLY.

- 'prepare' executes actual pinned CORE Git/SQLite task, claim and ephemeral
  owner signature under CI supervisor; private signer is NEVER sent to worker.
- 'server' runs as dedicated non-admin receiver user, strict NTFS ACL+token
  checking, SID-pinned Named Pipe and one inert file only.
- 'client' runs as separate non-admin worker and sends PRESIGNED bytes.
- 'probe' proves worker cannot write protected folder by NTFS permission.
No SCM installation, queue activation, key provisioning or real user PC.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

if os.name != "nt":
    raise RuntimeError("Windows ephemeral CI actor only")
if os.environ.get("GITHUB_ACTIONS")!="true" or \
        os.environ.get("NF_WINDOWS_TWO_SID_CI_ONLY")!="1":
    raise RuntimeError("disabled outside disposable GitHub Windows CI")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from windows_named_pipe_pilot_receiver import (
    canon,serve_one_pilot,WindowsReceiverDenied,
)
from windows_receiver_sid_acl_guard import own_sid
from test_windows_named_pipe_core_e2e import TARGET, CORE, git

def _read(path, limit=8192):
    p=Path(path)
    if not p.is_file() or p.stat().st_size>limit:
        raise RuntimeError("invalid bounded CI-only test input")
    return json.loads(p.read_text(encoding="ascii"))


def _write_result(out,data):
    Path(out).write_text(json.dumps(data,sort_keys=True,ensure_ascii=True),
                         encoding="ascii")


def prepare(args):
    from one_task_core import OneTaskCore,EMPTY_SHA
    stage=Path(args.stage)
    root=stage/"core"
    root.mkdir()
    repo=root/"repo"
    repo.mkdir()
    git(repo,"init","-q")
    git(repo,"config","user.name","isolated CI")
    git(repo,"config","user.email","test@example.invalid")
    (repo/"README.md").write_text("one inert Windows CI result\n",encoding="ascii")
    git(repo,"add","README.md")
    git(repo,"commit","-qm","fixture pinned source")
    sha=git(repo,"rev-parse","HEAD")
    (root/"core_state").mkdir()
    core=OneTaskCore(root/"core_state",repo)
    spec=dict(schema="neurofactory.core.task.v1",
              task_id="NF-DEV-05-Q908",project_id="core-test",
              target=TARGET,objective="One disposable Windows physical SID test",
              source_sha=sha,source_sha256=EMPTY_SHA,
              model="qwen2.5-coder:1.5b",reserved_units=10,
              approval_commit=sha)
    core.enqueue(spec,trusted_approval_check=lambda value:value==spec)
    core.claim("worker-one",now=int(time.time()),lease_seconds=120)
    if core.snapshot()["state"]!="CLAIMED":
        raise RuntimeError("real CORE lease not claimed")
    raw=b"NEUROFACTORY_INDEPENDENT_WINDOWS_USER_PILOT\n"
    signed=dict(schema="neurofactory.windows.single_file_pilot.v1",
                task_id=spec["task_id"],project_id=spec["project_id"],
                source_sha40=sha,operation_id="pilot-"+spec["task_id"],
                target=TARGET,
                content_base64=base64.b64encode(raw).decode("ascii"),
                content_sha256=hashlib.sha256(raw).hexdigest())
    # Exists only in this short-lived operator CI supervisor process, not
    # worker, receiver config, GitHub secrets or user computer.
    private=Ed25519PrivateKey.generate()
    signature=private.sign(b"NF_WINDOWS_PILOT_V1\x00"+canon(signed))
    packet={**signed,
            "approved_owner_signature":base64.b64encode(signature).decode("ascii")}
    public=private.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
    (stage/"packet.json").write_text(json.dumps(packet),encoding="ascii")
    (stage/"public.json").write_text(json.dumps({
        "public_key_base64":base64.b64encode(public).decode("ascii")
    }),encoding="ascii")
    (stage/"core_evidence.json").write_text(json.dumps({
        "task_id":spec["task_id"],
        "state":core.snapshot()["state"],
        "source_sha40":sha,
        "content_sha256":hashlib.sha256(raw).hexdigest(),
        "live_queue_enabled":False}),encoding="ascii")
    print("NF_TWO_SID_ACTUAL_CORE_CLAIM_AND_OWNER_PRESIGNED=PASS",flush=True)


def server(args):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    config=_read(Path(args.stage)/"server_config.json")
    pin=_read(Path(args.stage)/"public.json")
    public=Ed25519PublicKey.from_public_bytes(
        base64.b64decode(pin["public_key_base64"],validate=True))
    if own_sid()!=config["receiver_sid"]:
        raise RuntimeError("receiver process not under expected Windows user")
    res=serve_one_pilot(
        config["pipe"],config["protected_root"],public,
        config["worker_sid"],receiver_user_sid=config["receiver_sid"])
    print("NF_TWO_SID_SERVER_STATUS="+res["status"],flush=True)


def client(args):
    import win32file
    import win32pipe
    import win32con
    import pywintypes
    config=_read(Path(args.stage)/"server_config.json")
    if own_sid()!=config["worker_sid"]:
        raise RuntimeError("worker token SID mismatch")
    packet=_read(Path(args.stage)/"packet.json")
    if args.tamper=="signature":
        packet["approved_owner_signature"]="A"*88
    pipe_path=config["pipe"]
    deadline=time.monotonic()+8
    while True:
        try:
            win32pipe.WaitNamedPipe(pipe_path,1200)
            break
        except pywintypes.error as exc:
            if exc.winerror not in (2,231) or time.monotonic()>deadline:
                raise
            time.sleep(0.04)
    handle=win32file.CreateFile(pipe_path,
                                win32con.GENERIC_READ|win32con.GENERIC_WRITE,
                                0,None,win32con.OPEN_EXISTING,0,None)
    try:
        win32pipe.SetNamedPipeHandleState(handle,
                                          win32pipe.PIPE_READMODE_MESSAGE,None,None)
        win32file.WriteFile(handle,canon(packet))
        _,answer=win32file.ReadFile(handle,4096)
        res=json.loads(answer.decode("ascii"))
    finally:
        win32file.CloseHandle(handle)
    if res.get("live_execution_allowed") is not False:
        raise RuntimeError("production queue incorrectly allowed")
    print("NF_TWO_SID_WORKER_STATUS="+res["status"],flush=True)
    if args.expected=="positive" and res["status"]!="ONE_INERT_WINDOWS_FILE_TEST_ONLY":
        raise RuntimeError("expected exactly one safe effect")
    if args.expected=="denied" and res["status"]!="DENIED_OR_UNKNOWN_MANUAL_STOP":
        raise RuntimeError("expected explicit denial")


def probe(args):
    config=_read(Path(args.stage)/"server_config.json")
    if own_sid()!=config["worker_sid"]:
        raise RuntimeError("direct-access probe must use worker SID")
    root=Path(config["protected_root"])
    if not root.is_dir():
        raise RuntimeError("protected sandbox absent")
    probe_file=root/"worker_forbidden.txt"
    try:
        with probe_file.open("xb") as f:
            f.write(b"UNAUTHORIZED")
    except PermissionError:
        print("NF_TWO_SID_WORKER_DIRECT_FILE_ACCESS=DENIED",flush=True)
        return
    else:
        try: probe_file.unlink()
        finally: raise RuntimeError("WORKER CAN WRITE RECEIVER DIRECTORY")


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("mode",choices=["prepare","server","client","probe"])
    parser.add_argument("--stage",required=True)
    parser.add_argument("--tamper",choices=["none","signature"],default="none")
    parser.add_argument("--expected",choices=["positive","denied"],default="positive")
    a=parser.parse_args()
    {"prepare":prepare,"server":server,"client":client,"probe":probe}[a.mode](a)


if __name__=="__main__":
    main()
