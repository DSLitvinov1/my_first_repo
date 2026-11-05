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
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from personal_scoped_ssh_transport import exchange_once,ScopedSSHTransportDenied

from personal_ssh_highwater import (
    _canon,REQ_SCHEMA,ACK_SCHEMA,DOMAIN,
    STATUS_REQ_SCHEMA,STATUS_ACK_SCHEMA,STATUS_DOMAIN,
)

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
    request=_canon(claim)
    if not 200<=len(request)<=4096:
        _unknown("bounded task reservation invalid")
    started=int(time.time())
    try:
        wire=exchange_once(root=trusted_service_root,request=request,
                           cap=3000,timeout=timeout)
        if not 50<=len(wire)<=3000:
            _unknown("SSH auth, refused epoch or remote commit ambiguous")
        response=json.loads(wire.decode("ascii"),
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
    except (ScopedSSHTransportDenied,OSError,UnicodeError,ValueError,
            json.JSONDecodeError) as exc:
        raise PersonalWitnessUnknown(
            "SSH or remote state ambiguous; NO AUTOMATIC RETRY") from exc


def read_signed_remote_head(*,trusted_service_root:Path,
                            pinned_public_raw:bytes,
                            expected_source:str,expected_machine:str,
                            expected_package:str):
    """Read signed remote epoch without changing it; used at SCM startup.

    An outage or forged head makes the SCM fail closed. No change to the
    Linux SQLite counters occurs for this request.
    """
    import secrets
    if os.name!="nt" or not trusted_service_root.is_absolute() or (
            type(pinned_public_raw) is not bytes or len(pinned_public_raw)!=32):
        _unknown("Windows pinned status environment unavailable")
    nonce=secrets.token_hex(16)
    request=_canon({"schema":STATUS_REQ_SCHEMA,"nonce":nonce})
    started=int(time.time())
    try:
        wire=exchange_once(root=trusted_service_root,request=request,
                           cap=3000,timeout=20)
        if not 150<=len(wire)<=3000:
            _unknown("remote signed head inaccessible")
        doc=json.loads(wire.decode("ascii"),
                       object_pairs_hook=_unique)
        if type(doc) is not dict or set(doc)!={"receipt","signature_base64"}:
            _unknown("remote status malformed")
        ack=doc["receipt"]
        if (type(ack) is not dict or
                set(ack)!={"schema","status","nonce","epoch","ledger_head",
                           "reservations","source_sha40","machine_sha256",
                           "package_sha256","recorded_unix","expires_unix",
                           "production_release_attested"} or
                ack.get("schema")!=STATUS_ACK_SCHEMA or
                ack.get("status")!="SIGNED_REMOTE_READ_ONLY_HIGHWATER" or
                ack.get("nonce")!=nonce or
                ack.get("source_sha40")!=expected_source or
                ack.get("machine_sha256")!=expected_machine or
                ack.get("package_sha256")!=expected_package or
                type(ack.get("epoch")) is not int or
                type(ack.get("reservations")) is not int or
                ack["epoch"]!=ack["reservations"] or
                type(ack.get("ledger_head")) is not str or
                not HEX64.fullmatch(ack["ledger_head"]) or
                ack.get("production_release_attested") is not False):
            _unknown("remote head not exact operator scope")
        signature=base64.b64decode(doc["signature_base64"],validate=True)
        if len(signature)!=64:
            _unknown("wrong signed status size")
        Ed25519PublicKey.from_public_bytes(pinned_public_raw).verify(
            signature,STATUS_DOMAIN+_canon(ack))
        now=int(time.time())
        if (type(ack.get("recorded_unix")) is not int or
                type(ack.get("expires_unix")) is not int or
                ack["recorded_unix"]>now+2 or
                ack["recorded_unix"]<started-3 or
                not now<ack["expires_unix"]<=now+32 or
                not started<=now<=started+22):
            _unknown("signed remote status expired or clocks drifted")
        return {"epoch":ack["epoch"],
                "ledger_head":ack["ledger_head"],
                "remote_status_signature_verified":True,
                "production_effect_authorized_by_status":False}
    except (OSError,ValueError,UnicodeError,ScopedSSHTransportDenied,
            InvalidSignature,TypeError) as exc:
        raise PersonalWitnessUnknown(
            "remote signed head unavailable or false, no effects") from exc
