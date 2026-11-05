"""Windows-only authenticated SSH client for the personal remote highwater.

A successful signed reservation is NOT permission for arbitrary execution.
The caller must separately verify owner Ed25519 signature, local one-use
intent, exact action allowlist and user project scope before one safe effect.
No shell commands, no auto retry after timeout, no model-controlled URLs.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from personal_ssh_highwater import _canon, REQ_SCHEMA, ACK_SCHEMA, DOMAIN

HOST="157.228.118.199"
USER="cloudagent"
HOST_KEY="AAAAC3NzaC1lZDI1NTE5AAAAIGkpprqPMxHxDcqY0048vPwxYfXPfbrLWPbKtVmnoo7A"
HEX64=re.compile(r"[a-f0-9]{64}\Z")


class PersonalWitnessUnknown(RuntimeError):
    pass


def _unknown(detail):
    raise PersonalWitnessUnknown("Remote signed highwater UNKNOWN; do not retry: "+detail)


def _unique(pairs):
    result={}
    for k,v in pairs:
        if k in result:
            _unknown("duplicate JSON field")
        result[k]=v
    return result


def _file(path,*,maximum):
    if (not isinstance(path,Path) or not path.is_absolute()
            or path.is_symlink() or not path.is_file()):
        _unknown("required immutable SSH key or trust file missing")
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or not 1<=st.st_size<=maximum:
        _unknown("invalid SSH file")
    if os.name=="nt" and st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        _unknown("SSH NTFS reparse attack")
    return path


def reserve_personal_epoch(*,trusted_service_root:Path,claim:dict,
                           pinned_public_raw:bytes,timeout:float=22):
    if (os.name!="nt" or not isinstance(trusted_service_root,Path)
            or not trusted_service_root.is_absolute()
            or trusted_service_root.is_symlink()
            or not trusted_service_root.is_dir()
            or type(claim) is not dict or
            claim.get("schema")!=REQ_SCHEMA or
            not isinstance(pinned_public_raw,bytes)
            or len(pinned_public_raw)!=32
            or type(timeout) not in (float,int)
            or not 5<=timeout<=30):
        _unknown("service environment or independently pinned key invalid")
    key=_file(trusted_service_root/"remote-client-id_ed25519",maximum=5000)
    known=_file(trusted_service_root/"known_hosts",maximum=500)
    if (known.read_text("ascii").strip() !=
            HOST+" ssh-ed25519 "+HOST_KEY):
        _unknown("SSH host identity not exactly operator pinned")
    executable=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32"/"OpenSSH"/"ssh.exe"
    if not executable.is_file():
        _unknown("OS OpenSSH executable absent")
    request=_canon(claim)
    if not 200<=len(request)<=4096:
        _unknown("bounded task reservation invalid")
    ssh=[
        str(executable),"-T",
        "-o","BatchMode=yes",
        "-o","StrictHostKeyChecking=yes",
        "-o",f"UserKnownHostsFile={known}",
        "-o","GlobalKnownHostsFile=NUL",
        "-o","IdentitiesOnly=yes",
        "-o","PasswordAuthentication=no",
        "-o","KbdInteractiveAuthentication=no",
        "-o","ConnectTimeout=8",
        "-o","ConnectionAttempts=1",
        "-o","ClearAllForwardings=yes",
        "-o","HostKeyAlgorithms=ssh-ed25519",
        "-o","LogLevel=ERROR",
        "-i",str(key),f"{USER}@{HOST}",
    ]
    started=int(time.time())
    try:
        result=subprocess.run(ssh,input=request,capture_output=True,
                              check=False,timeout=timeout)
        if (result.returncode!=0 or
                not 50<=len(result.stdout)<=3000 or result.stderr and
                len(result.stderr)>2048):
            _unknown("SSH auth, refused epoch or remote commit ambiguous")
        response=json.loads(result.stdout.decode("ascii"),
                            object_pairs_hook=_unique)
        if (type(response) is not dict or
                set(response)!={"receipt","signature_base64"} or
                type(response["receipt"]) is not dict or
                type(response["signature_base64"]) is not str):
            _unknown("signed remote response shape invalid")
        ack=response["receipt"]
        if (set(ack)!={"schema","status","task_id","external_epoch",
                       "claim_sha256","ledger_head","committed_unix",
                       "expires_unix","automatic_retry_allowed",
                       "production_effect_authorized"} or
                ack.get("schema")!=ACK_SCHEMA or
                ack.get("status")!="DURABLE_REMOTE_RESERVATION_NO_OS_EFFECT_AUTHORITY"
                or ack.get("task_id")!=claim.get("task_id")
                or ack.get("external_epoch")!=claim.get("external_epoch")
                or ack.get("claim_sha256")!=sha256(request).hexdigest()
                or type(ack.get("ledger_head")) is not str
                or not HEX64.fullmatch(ack["ledger_head"])
                or type(ack.get("committed_unix")) is not int
                or type(ack.get("expires_unix")) is not int
                or ack.get("automatic_retry_allowed") is not False
                or ack.get("production_effect_authorized") is not False):
            _unknown("remote scope mismatch")
        try:
            signature=base64.b64decode(
                response["signature_base64"],validate=True)
            if len(signature)!=64:
                _unknown("unexpected Ed25519 signature size")
            Ed25519PublicKey.from_public_bytes(
                pinned_public_raw).verify(signature,DOMAIN+_canon(ack))
        except (InvalidSignature,ValueError,TypeError) as exc:
            raise PersonalWitnessUnknown("remote Ed25519 signature invalid") from exc
        # Real Linux/Windows clocks differ ~1.24s. Permit at most 2 seconds
        # of independently signed remote lead. Never extend expiry.
        now=int(time.time())
        if (now<started or now-started>int(timeout)+2 or
                ack["committed_unix"]>now+2 or
                ack["committed_unix"]<started-3 or
                not now<ack["expires_unix"]<=now+90):
            _unknown("remote signed receipt freshness or local time invalid")
        return {
            "status":"SIGNED_EXTERNAL_EPOCH_OBSERVED_NO_EFFECT_AUTHORITY",
            "epoch":ack["external_epoch"],
            "ledger_head":ack["ledger_head"],
            "claim_sha256":ack["claim_sha256"],
            "signed_witness_verified":True,
            "automatic_retry_allowed":False,
            "os_effect_authorized_by_receipt_alone":False,
        }
    except (subprocess.TimeoutExpired,OSError,UnicodeError,ValueError,
            json.JSONDecodeError) as exc:
        raise PersonalWitnessUnknown(
            "SSH or remote state ambiguous; NO AUTOMATIC RETRY") from exc
