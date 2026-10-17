"""Disposable cross-UID operator anchor: NEVER a production issuer or file permit.

Only signer OS principal can own/read Ed25519 private key and monotonic local
anchor. A separate less-privileged DB/CORE actor can store copies of signed
checkpoint receipts but cannot roll back the signer-owned current tip. Root
and signer-UID compromise are out of scope. No real owner approval, network
service or permission to write project files is provided.

CLI strictly isolated behind NF_OPERATOR_ANCHOR_FIXTURE_ONLY=1 on Linux.
"""
from __future__ import annotations
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey


class OperatorAnchorDenied(ValueError):
    pass

_SHA64=re.compile(r"[0-9a-f]{64}\Z")
_KEY="issuer-private.raw"
_ANCHOR="protected-anchor.json"
_LOCK="operator.lock"
_DOMAIN="neurofactory.operator.anchor.FIXTURE.v1"

def _reject(message):
    raise OperatorAnchorDenied(message)

def _canonical(x):
    return json.dumps(x,sort_keys=True,ensure_ascii=True,
                      allow_nan=False,separators=(",",":")).encode("ascii")

def _guard(home):
    if (os.name!="posix" or os.environ.get("NF_OPERATOR_ANCHOR_FIXTURE_ONLY")!="1"
            or not hasattr(os,"geteuid") or os.geteuid()==0):
        _reject("requires explicitly selected non-root signer test principal")
    root=Path(home)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        _reject("signer-owned isolated absolute directory required")
    s=root.lstat()
    if s.st_uid!=os.geteuid() or not stat.S_ISDIR(s.st_mode) or s.st_mode & 0o077:
        _reject("signer directory wrong owner or not private 0700")
    if root.name!="nf-signer-fixture":
        _reject("only explicitly named disposable signer fixture")
    return root

def _file(root,name):
    path=root/name
    try:
        st=path.lstat()
    except FileNotFoundError:
        _reject("missing protected operator material")
    if st.st_uid!=os.geteuid() or st.st_mode & 0o077 or not stat.S_ISREG(st.st_mode):
        _reject("unsafe key or external anchor file")
    return path

def _read_private(root):
    raw=_file(root,_KEY).read_bytes()
    if len(raw)!=32:
        _reject("invalid private key file")
    return Ed25519PrivateKey.from_private_bytes(raw)

def _read_tip(root):
    try:
        data=json.loads(_file(root,_ANCHOR).read_text("ascii"))
    except (ValueError,UnicodeError) as e:
        raise OperatorAnchorDenied("damaged protected anchor") from e
    if (type(data) is not dict or
        set(data)!={"schema","sequence","head","public_sha256","used_claims"}
        or data["schema"]!=_DOMAIN or
        type(data["sequence"]) is not int or data["sequence"]<0 or
        type(data["head"]) is not str or not _SHA64.fullmatch(data["head"]) or
        type(data["public_sha256"]) is not str or not _SHA64.fullmatch(data["public_sha256"]) or
        type(data["used_claims"]) is not list or
        not all(type(q) is str and _SHA64.fullmatch(q) for q in data["used_claims"]) or
        len(data["used_claims"])!=len(set(data["used_claims"])) or
        len(data["used_claims"])>256):
        _reject("damaged monotonic anchor structure")
    return data

def _atomic_write(root, name, payload):
    # Only own UID may create temp files; no inherited DB/worker write perms.
    fd=os.open(root/(name+".next"),os.O_CREAT|os.O_EXCL|os.O_WRONLY|
               getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        try:
            with os.fdopen(fd,"wb",closefd=False) as w:
                w.write(payload);w.flush();os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(root/(name+".next"),root/name)
        dfd=os.open(root,os.O_DIRECTORY|os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    except BaseException:
        try:(root/(name+".next")).unlink()
        except FileNotFoundError:pass
        raise

def _locked(root, fn):
    fd=os.open(root/_LOCK,os.O_CREAT|os.O_RDWR|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        st=os.fstat(fd)
        if st.st_uid!=os.geteuid() or st.st_mode & 0o077 or not stat.S_ISREG(st.st_mode):
            _reject("operator lock not privately owned")
        fcntl.flock(fd,fcntl.LOCK_EX)
        return fn()
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)

def bootstrap(home):
    root=_guard(home)
    def action():
        if (root/_KEY).exists() or (root/_ANCHOR).exists():
            _reject("cannot reset persistent signer/anchor")
        key=Ed25519PrivateKey.generate()
        raw=key.private_bytes(serialization.Encoding.Raw,
                              serialization.PrivateFormat.Raw,
                              serialization.NoEncryption())
        pub=key.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        # Never emit the private key.
        fd=os.open(root/_KEY,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),0o600)
        try:
            os.write(fd,raw);os.fsync(fd)
        finally:os.close(fd)
        tip={"schema":_DOMAIN,"sequence":0,"head":"0"*64,
             "public_sha256":hashlib.sha256(pub).hexdigest(),"used_claims":[]}
        _atomic_write(root,_ANCHOR,_canonical(tip))
        return {"status":"OFFLINE_OPERATOR_BOOTSTRAPPED_NO_APPROVAL",
                "public_key_base64":base64.b64encode(pub).decode(),
                "public_key_sha256":tip["public_sha256"],
                "can_authorize_live_operations":False}
    return _locked(root,action)

def advance_fixture(home, claim_sha):
    root=_guard(home)
    if type(claim_sha) is not str or not _SHA64.fullmatch(claim_sha):
        _reject("exact offline claim digest required")
    def action():
        tip=_read_tip(root)
        key=_read_private(root)
        pub=key.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)
        if tip["public_sha256"]!=hashlib.sha256(pub).hexdigest():
            _reject("protected key mismatch")
        if claim_sha in tip["used_claims"] or len(tip["used_claims"])>=256:
            _reject("replayed claim or fixture limit reached")
        seq=tip["sequence"]+1
        data={"schema":_DOMAIN,"sequence":seq,
              "previous_head":tip["head"],"claim_sha256":claim_sha,
              "public_key_sha256":tip["public_sha256"]}
        new_head=hashlib.sha256(_canonical(data)).hexdigest()
        certificate={"schema":_DOMAIN,"sequence":seq,"head":new_head,
                     "claim_sha256":claim_sha,"public_key_sha256":tip["public_sha256"]}
        signature=key.sign(_canonical(certificate))
        updated={"schema":_DOMAIN,"sequence":seq,"head":new_head,
                 "public_sha256":tip["public_sha256"],
                 "used_claims":tip["used_claims"]+[claim_sha]}
        # Once the protected tip has advanced, an unprivileged DB rollback
        # cannot replay an older certificate as current.
        _atomic_write(root,_ANCHOR,_canonical(updated))
        return {"certificate":certificate,
                "signature_base64":base64.b64encode(signature).decode(),
                "kind":"MONOTONIC_FIXTURE_WITNESS_NOT_OPERATION_APPROVAL",
                "execution_allowed":False}
    return _locked(root,action)

def verify_current(home, packet, externally_pinned_public_sha, public_key_base64):
    root=_guard(home)
    if (type(packet) is not dict or set(packet)!={"certificate","signature_base64","kind","execution_allowed"}
            or packet["kind"]!="MONOTONIC_FIXTURE_WITNESS_NOT_OPERATION_APPROVAL"
            or packet["execution_allowed"] is not False or
            type(externally_pinned_public_sha) is not str or
            not _SHA64.fullmatch(externally_pinned_public_sha) or
            type(public_key_base64) is not str or
            type(packet["certificate"]) is not dict or
            set(packet["certificate"])!={"schema","sequence","head","claim_sha256","public_key_sha256"}
            or type(packet["signature_base64"]) is not str):
        _reject("invalid witness request")
    def action():
        tip=_read_tip(root)
        cert=packet["certificate"]
        if (cert["schema"]!=_DOMAIN or
            type(cert["sequence"]) is not int or cert["sequence"]!=tip["sequence"] or
            type(cert["head"]) is not str or cert["head"]!=tip["head"] or
            type(cert["claim_sha256"]) is not str or
            not _SHA64.fullmatch(cert["claim_sha256"]) or
            cert["public_key_sha256"]!=externally_pinned_public_sha or
            tip["public_sha256"]!=externally_pinned_public_sha):
            _reject("ROLLBACK_OR_UNPINNED_CHECKPOINT")
        try:
            pub=base64.b64decode(public_key_base64,validate=True)
            sig=base64.b64decode(packet["signature_base64"],validate=True)
            if (len(pub)!=32 or len(sig)!=64 or
                hashlib.sha256(pub).hexdigest()!=externally_pinned_public_sha):
                _reject("wrong independently pinned verifier")
            Ed25519PublicKey.from_public_bytes(pub).verify(sig,_canonical(cert))
        except (ValueError,InvalidSignature) as exc:
            raise OperatorAnchorDenied("bad cryptographic witness") from exc
        return {"status":"CURRENT_SEPARATE_OS_UID_TIP_MATCHES",
                "sequence":cert["sequence"],"head":cert["head"],
                "production_owner_authenticated":False,
                "operation_execution_allowed":False,"auto_retry_allowed":False}
    return _locked(root,action)

def cli(args):
    if len(args)<3:
        _reject("usage: bootstrap | advance <sha> | verify <packet-file> <pub_sha> <pub_b64>")
    action,home=args[1:3]
    if action=="bootstrap" and len(args)==3:ret=bootstrap(home)
    elif action=="advance" and len(args)==4:ret=advance_fixture(home,args[3])
    elif action=="verify" and len(args)==6:
        p=Path(args[3])
        if not p.is_file() or p.stat().st_size>8192:
            _reject("invalid untrusted DB receipt")
        ret=verify_current(home,json.loads(p.read_text("ascii")),args[4],args[5])
    else:_reject("invalid operator command")
    print(json.dumps(ret,sort_keys=True,separators=(",",":")))

if __name__=="__main__":
    try:cli(sys.argv)
    except (OperatorAnchorDenied,ValueError,OSError) as e:
        print("BLOCKED_OFFLINE_OPERATOR_BOUNDARY:"+str(e),file=sys.stderr)
        sys.exit(3)
