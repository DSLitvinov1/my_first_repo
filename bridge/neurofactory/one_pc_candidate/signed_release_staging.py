"""Offline two-person SIGNED RELEASE CANDIDATE STAGING, never installation.

The owner and an independent reviewer sign exactly one artifact/commit/evidence.
This code verifies their *externally pinned* distinct Ed25519 public keys.
Successful verification authorizes ONLY a protected, inactive staging copy
on a manually operated Windows machine. No SCM registration, program startup,
Qwen inference, CORE queue activation, executable run, merge, or publication.

The caller/LLM must never provide or install trusted keys. The actual
independent signatures and real target hardware cannot be forged by a CI test.
"""
from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN_REVIEW=b"NF_ONEPC_RELEASE_REVIEW_STAGING_V1\x00"
DOMAIN_OWNER=b"NF_ONEPC_RELEASE_OWNER_STAGING_V1\x00"
HEX40=re.compile(r"[a-f0-9]{40}\Z")
HEX64=re.compile(r"[a-f0-9]{64}\Z")
NONCE=re.compile(r"[a-f0-9]{32}\Z")
SCHEMA="nf.onepc.release_staging_approval.v1"
SCOPE="TWO_PERSON_REVIEWED_INSTALLER_QUARANTINE_COPY_ONLY_NO_EXECUTION"
BASE_FIELDS={
    "schema", "scope", "source_commit", "installer_sha256",
    "installer_run_id", "scm_run_id", "qwen_run_id",
    "nonce", "issued_unix", "expires_unix",
}
SIGNED_FIELDS=BASE_FIELDS | {"owner_signature_base64","reviewer_signature_base64"}
INSTALLER_SOURCE_COMMIT="48529c50f9a40d20cd5b0d7e586eb4f092ed0b7e"
TRUST_REL=Path("Neurofactory")/"TrustPins"
STAGING_REL=Path("Neurofactory")/"Quarantine"

class StagingDenied(ValueError):
    pass

def _deny(reason):
    raise StagingDenied("Protected staging refused: "+reason)

def _canon(obj):
    try:
        return json.dumps(obj,sort_keys=True,ensure_ascii=True,
                          separators=(",",":"),allow_nan=False).encode("ascii")
    except (ValueError,UnicodeError,TypeError,RecursionError) as exc:
        raise StagingDenied("Uncanonical approval document") from exc

def verify_two_person_signatures(approval,owner_public,reviewer_public, *,
                                 expected_source_commit, now=None):
    """Pure verification. No filesystem writes or release enablement."""
    if (type(approval) is not dict or set(approval)!=SIGNED_FIELDS
            or len(_canon(approval))>2600 or
            type(owner_public) is not bytes or len(owner_public)!=32
            or type(reviewer_public) is not bytes or len(reviewer_public)!=32
            or owner_public==reviewer_public or
            type(expected_source_commit) is not str
            or not HEX40.fullmatch(expected_source_commit)):
        _deny("missing exact independently pinned signer or envelope")
    unsigned={k:approval[k] for k in BASE_FIELDS}
    if (approval["schema"]!=SCHEMA or approval["scope"]!=SCOPE
            or any(type(approval[x]) is not str for x in (
                "source_commit","installer_sha256","nonce"))
            or approval["source_commit"]!=expected_source_commit
            or approval["source_commit"]!=INSTALLER_SOURCE_COMMIT
            or not HEX64.fullmatch(approval["installer_sha256"])
            or not NONCE.fullmatch(approval["nonce"])
            or any(type(approval[x]) is not int or approval[x]<1
                   for x in ("installer_run_id","scm_run_id","qwen_run_id",
                             "issued_unix","expires_unix"))):
        _deny("invalid approved artifact, source, audit evidence or scope")
    if (approval["installer_run_id"]!=39701930342
            or approval["scm_run_id"]!=39702159425
            or approval["qwen_run_id"]!=39702865907
            or approval["installer_sha256"]!=
                "648dc60f51390578c1835ca46b5151b61f1cb64858c34d6e164a8092381e35cf"):
        _deny("not the reviewed exact candidate and targeted Windows evidence")
    issued,expiry=approval["issued_unix"],approval["expires_unix"]
    if now is None:
        now=int(time.time())
    if (type(now) is not int or not 0<issued<=now<expiry
            or expiry-issued>24*3600):
        _deny("expired, not-yet-effective or overbroad approval")
    data=_canon(unsigned)
    for role,pin,prefix in (
            ("owner",owner_public,DOMAIN_OWNER),
            ("reviewer",reviewer_public,DOMAIN_REVIEW)):
        enc=approval[role+"_signature_base64"]
        if type(enc) is not str or len(enc)!=88:
            _deny(role+" signature missing or not canonical")
        try:
            decoded=base64.b64decode(enc,validate=True)
            if len(decoded)!=64:
                _deny(role+" signature wrong length")
            Ed25519PublicKey.from_public_bytes(pin).verify(decoded,prefix+data)
        except (InvalidSignature,ValueError,TypeError,binascii.Error) as exc:
            raise StagingDenied("Invalid independently pinned "+role+" signature") from exc
    return {
        "schema":"nf.onepc.staging_gate_report.v1",
        "status":"TWO_PERSON_SIGNATURES_VERIFIED_QUARANTINE_ONLY",
        "source_commit":approval["source_commit"],
        "installer_sha256":approval["installer_sha256"],
        "reviewer_approved_exact_staging":True,
        "owner_approved_exact_staging":True,
        "production_execution_authorized":False,
        "service_enrollment_authorized":False,
        "automated_install_authorized":False,
        "unsigned_replacement_authorized":False,
        "independent_physical_acceptance_complete":False,
        "live_qwen_core_host_authority":False,
        "external_antirollback_witness_verified":False,
    }

def _private_file(path:Path, limit):
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        _deny("missing fixed trust file or installer")
    st=path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_size<1 or st.st_size>limit
            or (os.name=="nt" and st.st_file_attributes & 0x400)):
        _deny("unsafe file, link, size or reparse")
    return path.read_bytes()

def _privileged_acl(path):
    """The real on-disk DACL must grant only SYSTEM/Administrators.

    A public key's cryptography proves nothing if an untrusted UI user could
    replace the trust-root file or the directory holding it.
    """
    if os.name!="nt":
        _deny("ACL verification requires native Windows")
    try:
        import win32security
        import win32con
        st=path.lstat()
        if (path.is_symlink() or st.st_file_attributes & 0x400):
            _deny("linked root or file")
        descriptor=win32security.GetNamedSecurityInfo(
            str(path),win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION |
            win32security.OWNER_SECURITY_INFORMATION)
        acl=descriptor.GetSecurityDescriptorDacl()
        if acl is None or acl.GetAceCount()<2:
            _deny("missing or null privileged DACL")
        allowed={"S-1-5-18","S-1-5-32-544"}
        seen=set()
        for index in range(acl.GetAceCount()):
            ace=acl.GetAce(index)
            if ace[0][0] != win32security.ACCESS_ALLOWED_ACE_TYPE:
                _deny("unreviewed access-control entry")
            sid=win32security.ConvertSidToStringSid(ace[-1])
            if sid not in allowed:
                _deny("non-operator account has access to trust/staging root")
            seen.add(sid)
        if seen!=allowed:
            _deny("SYSTEM and Administrators missing from private DACL")
    except (OSError,ImportError,AttributeError,TypeError,ValueError) as exc:
        raise StagingDenied("Unable to authenticate Windows root DACL") from exc


def _admin():
    if os.name!="nt":
        _deny("Windows only")
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        _deny("explicit elevated operator process required")

def _locked_acl(path):
    """REPLACE the entire DACL, do not merely add ACEs with icacls.

    Newly created ProgramData folders may include explicit ACEs for a
    runner/creator. /inheritance:r does not remove explicit ACEs.
    """
    if os.name!="nt":
        _deny("Windows-only ACL installation")
    try:
        import win32security
        import win32con
        acl=win32security.ACL()
        inherit=win32con.CONTAINER_INHERIT_ACE|win32con.OBJECT_INHERIT_ACE
        for sid_text in ("S-1-5-18","S-1-5-32-544"):
            sid=win32security.ConvertStringSidToSid(sid_text)
            acl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION,inherit,
                win32con.GENERIC_ALL,sid)
        win32security.SetNamedSecurityInfo(
            str(path),win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION |
            win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,None,acl,None)
    except (OSError,ImportError,AttributeError,TypeError,ValueError) as exc:
        raise StagingDenied("Windows private DACL replacement failed") from exc
    _privileged_acl(path)

def operator_stage_signed_candidate(installer,approval_file,*,expected_source_commit):
    """One-time admin-only quarantine; NEVER executes the copied installer."""
    _admin()
    programdata=os.environ.get("PROGRAMDATA")
    if not programdata or not Path(programdata).is_absolute():
        _deny("Windows ProgramData not available")
    root=Path(programdata)
    if root.is_symlink() or not root.is_dir() or (
            root.lstat().st_file_attributes & 0x400):
        _deny("ProgramData changed to unsafe directory")
    trust=root/TRUST_REL
    quarantine=root/STAGING_REL
    # Paths are operator-provisioned only. Never accept keys from environment
    # overrides, the signed request, the browser, or a model proposal.
    if trust.is_symlink() or not trust.is_dir():
        _deny("independent reviewer and owner pins are not enrolled")
    _privileged_acl(root/"Neurofactory")
    _privileged_acl(trust)
    _privileged_acl(trust/"owner-ed25519.pub")
    _privileged_acl(trust/"reviewer-ed25519.pub")
    owner=_private_file(trust/"owner-ed25519.pub",32)
    reviewer=_private_file(trust/"reviewer-ed25519.pub",32)
    if len(owner)!=32 or len(reviewer)!=32:
        _deny("exact public pins not provisioned")
    data=_private_file(Path(approval_file),2600)
    try:
        approval=json.loads(data.decode("ascii"),
                            object_pairs_hook=_unique)
    except (UnicodeError,ValueError,TypeError):
        _deny("invalid or duplicate-key staging consent")
    accepted=verify_two_person_signatures(
        approval,owner,reviewer,
        expected_source_commit=expected_source_commit)
    path=Path(installer)
    data=_private_file(path,100_000_000)
    if sha256(data).hexdigest()!=accepted["installer_sha256"]:
        _deny("candidate installer differs from separately approved SHA256")
    if path.name!="Neurofactory-Local-Draft-Setup.exe":
        _deny("unexpected installer name")
    if quarantine.exists() or quarantine.is_symlink():
        _deny("staging root already exists; never overwrite or downgrade")
    if (root/TRUST_REL.parent).exists() and (root/TRUST_REL.parent).is_symlink():
        _deny("linked parent of trust root")
    # This is NOT an installer or service registration. Only a quarantine
    # copy. The operator must examine ACL with an independent reviewer.
    try:
        quarantine.parent.mkdir(mode=0o700,exist_ok=True)
        quarantine.mkdir(mode=0o700)
        _locked_acl(quarantine)
        _privileged_acl(quarantine)
        dest=quarantine/path.name
        with dest.open("xb") as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        if sha256(_private_file(dest,100_000_000)).hexdigest()!=accepted["installer_sha256"]:
            _deny("quarantine readback differs from signed candidate")
        # Do not log user credentials/signatures or mark production ready.
        return {**accepted,"quarantine_copy_verified":True,
                "quarantine_filename":dest.name}
    except Exception:
        # Never remove an existing quarantine or execute a fallback.
        raise

def _unique(items):
    out={}
    for key,value in items:
        if key in out: _deny("duplicate approval field")
        out[key]=value
    return out
