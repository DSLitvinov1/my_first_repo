"""Safe one-shot actual cloud Qwen inference, *only* as untrusted UI draft.

This connects to an already-owned Linux machine via an SSH key scoped server-
side to a forced command. No shell, port forwarding, arbitrary remote commands,
privileged Windows HOST action, CORE queue submission, or automatic retries.
Only the signed/pinned SSH host identity authenticates transport; responses
remain untrusted model suggestions (not independent reviewer evidence).
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

MODEL = "qwen2.5-coder:1.5b"
MODEL_SHA = "cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046"
SCHEMA = "nf.cloud.qwen.one_draft_request.v1"
RESULT_SCHEMA = "nf.cloud.qwen.one_draft_result.v1"
HOST = "157.228.118.199"
USER = "cloudagent"
HOST_ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIGkpprqPMxHxDcqY0048vPwxYfXPfbrLWPbKtVmnoo7A"
HEX32 = re.compile(r"[0-9a-f]{32}\Z")


class CloudDraftDenied(ValueError):
    pass


def _unique(items):
    data = {}
    for key, value in items:
        if key in data:
            raise CloudDraftDenied("Duplicate SSH result field")
        data[key] = value
    return data


def _plain_file(file: Path, *, maximum: int = 12000):
    if file.is_symlink() or not file.is_file():
        raise CloudDraftDenied("Cloud SSH configuration missing")
    info = file.lstat()
    if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= maximum:
        raise CloudDraftDenied("Unsafe cloud SSH configuration")
    if os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise CloudDraftDenied("Cloud SSH reparse file refused")
    return file


def _config(workspace_dir: Path):
    if (not isinstance(workspace_dir, Path) or not workspace_dir.is_absolute() or
            workspace_dir.is_symlink() or not workspace_dir.is_dir()):
        raise CloudDraftDenied("Trusted local workspace missing")
    folder = workspace_dir / "cloud_qwen"
    if folder.is_symlink() or not folder.is_dir():
        raise CloudDraftDenied("Cloud Qwen provisioned folder unavailable")
    if os.name == "nt" and folder.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise CloudDraftDenied("Cloud SSH folder cannot be an NTFS junction")
    key = _plain_file(folder / "id_ed25519", maximum=5000)
    known = _plain_file(folder / "known_hosts", maximum=500)
    pin = f"{HOST} ssh-ed25519 {HOST_ED25519}"
    if known.read_text(encoding="ascii").strip() != pin:
        raise CloudDraftDenied("Unexpected pinned cloud server host key")
    ssh = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh.exe"
    if not ssh.is_file():
        raise CloudDraftDenied("Windows OpenSSH not installed")
    return ssh, key, known


def available(workspace_dir: Path) -> bool:
    try:
        _config(workspace_dir)
        return True
    except (CloudDraftDenied, OSError, UnicodeError):
        return False


def generate(workspace_dir: Path, task: dict, *, model: str):
    ssh, identity, known = _config(workspace_dir)
    if (model != MODEL or type(task) is not dict or
            any(type(task.get(name)) is not str or
                not HEX32.fullmatch(task[name])
                for name in ("id", "project_id")) or
            type(task.get("objective")) is not str or
            not 15 <= len(task["objective"]) <= 1200):
        raise CloudDraftDenied("Incompatible cloud Qwen request")
    nonce = secrets.token_hex(16)
    request = {
        "schema": SCHEMA, "task_id": task["id"],
        "project_id": task["project_id"], "objective": task["objective"],
        "model": MODEL, "nonce": nonce,
    }
    data = json.dumps(request, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    if len(data) > 4096:
        raise CloudDraftDenied("Cloud Qwen request oversized")
    cmd = [
        str(ssh), "-T",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known}",
        "-o", "GlobalKnownHostsFile=NUL",
        "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "ConnectTimeout=8",
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=2",
        "-o", "ClearAllForwardings=yes",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "LogLevel=ERROR",
        "-i", str(identity), f"{USER}@{HOST}",
    ]
    try:
        process = subprocess.run(cmd, input=data, capture_output=True,
                                 timeout=120, check=False)
        if (process.returncode != 0 or not 2 <= len(process.stdout) <= 14000):
            return {"status": "UNKNOWN", "model": MODEL,
                    "error_code": "CLOUD_SSH_UNKNOWN_NO_RETRY"}
        reply = json.loads(process.stdout.decode("utf-8"), object_pairs_hook=_unique)
        if (type(reply) is not dict or
                set(reply) != {
                    "schema", "status", "model", "model_sha256",
                    "task_id", "nonce", "text", "response_sha256",
                    "execution_allowed", "automatic_retry_allowed", "owner_signed"} or
                reply["schema"] != RESULT_SCHEMA or
                reply["status"] != "PROPOSED_UNVERIFIED" or
                reply["model"] != MODEL or reply["model_sha256"] != MODEL_SHA or
                reply["task_id"] != task["id"] or reply["nonce"] != nonce or
                reply["execution_allowed"] is not False or
                reply["automatic_retry_allowed"] is not False or
                reply["owner_signed"] is not False):
            raise CloudDraftDenied("Unsigned model output claimed authorization")
        result = reply["text"]
        if (type(result) is not str or
                not 2 <= len(result.encode("utf-8")) <= 10000 or
                type(reply["response_sha256"]) is not str or
                sha256(result.encode("utf-8")).hexdigest() != reply["response_sha256"]):
            raise CloudDraftDenied("Wrong model output digest")
        return {
            "status": "PROPOSED_UNVERIFIED",
            "model": MODEL,
            "text": result,
            "response_sha256": reply["response_sha256"],
            "content_sha256": reply["response_sha256"],
        }
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError,
            TypeError, CloudDraftDenied):
        return {"status": "UNKNOWN", "model": MODEL,
                "error_code": "CLOUD_SSH_UNKNOWN_NO_RETRY"}
