"""Scoped SSH transport for the restricted Windows LocalService.

Uses a service-SID-only ACL on the Ed25519 key: Paramiko loads it in the
running service process. Windows OpenSSH ssh.exe refuses such an otherwise
restricted key because it sees the service SID as an additional ACL principal.
NEVER weaken ACLs, disable host-key verification, use an agent/shared key, or
invoke a shell. Exactly ONE SSH session / request; no automatic retry.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import time

import paramiko

HOST = "157.228.118.199"
PORT = 22
USER = "cloudagent"
HOST_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIGkpprqPMxHxDcqY0048vPwxYfXPfbrLWPbKtVmnoo7A"
HOST_LINE = HOST + " ssh-ed25519 " + HOST_KEY


class ScopedSSHTransportDenied(RuntimeError):
    pass


def _safe_file(value: Path, *, max_size: int):
    if not isinstance(value, Path) or not value.is_absolute() or value.is_symlink():
        raise ScopedSSHTransportDenied("Pinned service identity file not canonical")
    if not value.is_file():
        raise ScopedSSHTransportDenied("Pinned service identity file missing")
    mode = value.lstat()
    if (not stat.S_ISREG(mode.st_mode) or
            not 1 <= mode.st_size <= max_size or
            os.name == "nt" and
            mode.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ScopedSSHTransportDenied("Pinned identity file redirected or invalid")
    return value


def exchange_once(*, root: Path, request: bytes, cap: int, timeout: float):
    """One bounded forced-command SSH exchange; caller verifies Ed25519 ACK.

    Pinned known_hosts authentication protects connection; user authorization
    remains a separate owner signature inside the caller, never inferred from
    SSH's successful transport or the Qwen model's text.
    """
    if (os.name != "nt" or not isinstance(root, Path) or not root.is_absolute() or
            root.is_symlink() or not root.is_dir() or
            type(request) is not bytes or not 24 <= len(request) <= 4096 or
            type(cap) is not int or not 150 <= cap <= 3500 or
            type(timeout) not in (int, float) or not 8 <= timeout <= 35):
        raise ScopedSSHTransportDenied("Invalid bounded Windows-only SSH exchange")
    private = _safe_file(root / "remote-client-id_ed25519", max_size=5000)
    known = _safe_file(root / "known_hosts", max_size=500)
    if known.read_text("ascii").strip() != HOST_LINE:
        raise ScopedSSHTransportDenied("Pinned remote SSH host changed")
    started = time.monotonic()
    client = paramiko.SSHClient()
    try:
        # RejectPolicy only; the exact single known_hosts Ed25519 key was
        # verified independently above. No agent or other private identities.
        client.load_host_keys(str(known))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        signer = paramiko.Ed25519Key.from_private_key_file(str(private))
        client.connect(
            HOST, port=PORT, username=USER, pkey=signer,
            allow_agent=False, look_for_keys=False,
            timeout=8, auth_timeout=8, banner_timeout=8, compress=False,
        )
        connection = client.get_transport()
        if connection is None or not connection.is_authenticated():
            raise ScopedSSHTransportDenied("Pinned SSH host did not authenticate")
        channel = connection.open_session(timeout=8)
        # An EMPTY SSH exec request: Linux restrict,command="..." invokes
        # only its forced Python validator, no interactive shell or PTY.
        # With a missing forced command, empty exec cannot execute user text.
        channel.settimeout(timeout)
        channel.exec_command("")
        channel.sendall(request)
        channel.shutdown_write()
        output = bytearray()
        while True:
            if time.monotonic() - started > timeout:
                raise ScopedSSHTransportDenied(
                    "Unknown forced SSH request outcome, do not retry"
                )
            item = channel.recv(min(1024, cap + 1 - len(output)))
            if not item:
                break
            output.extend(item)
            if len(output) > cap:
                raise ScopedSSHTransportDenied("Bounded SSH answer exceeds limit")
        if channel.recv_exit_status() != 0 or not 1 <= len(output) <= cap:
            raise ScopedSSHTransportDenied(
                "Forced Linux witness refused or uncertain, do not retry"
            )
        return bytes(output)
    except (OSError, ValueError, EOFError, TimeoutError, paramiko.SSHException,
            ScopedSSHTransportDenied) as exc:
        raise ScopedSSHTransportDenied(
            "Pinned protected service SSH unknown; NO AUTOMATIC RETRY"
        ) from exc
    finally:
        client.close()
