"""Windows two-principal isolation: fail-closed SID/token/NTFS DACL inspection.

This module performs NO ACL changes, service installation, key creation or
filesystem effects. The guarded receiver must run as a dedicated low-rights
local Windows account whose identity and protected folder are provisioned
by a separately authorized operator. Running it as an Administrator, SYSTEM
or the CORE worker is denied. Explicit Windows ACLs must grant only the
receiver (and administrators/SYSTEM as host root of trust) write access.
"""
from __future__ import annotations

import os
from pathlib import Path

class PrincipalIsolationDenied(PermissionError):
    pass

# Worldwide, Authenticated Users, builtin Users, Anonymous
UNTRUSTED_BROAD_SIDS=frozenset((
    "S-1-1-0","S-1-5-11","S-1-5-32-545","S-1-5-7",
))
SYSTEM_SID="S-1-5-18"
ADMIN_SID="S-1-5-32-544"
FILE_WRITE_MASK=(
    0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x00040000 |
    0x00080000 | 0x00010000 | 0x10000000 | 0x40000000
)
REPARSE_ATTR=0x400


def own_sid():
    import win32api
    import win32con
    import win32security
    token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                        win32con.TOKEN_QUERY)
    sid=win32security.GetTokenInformation(token,win32security.TokenUser)[0]
    return win32security.ConvertSidToStringSid(sid)


def _get_acl_sids(root):
    import win32security
    sec=win32security.GetFileSecurity(
        str(root),win32security.OWNER_SECURITY_INFORMATION |
                  win32security.DACL_SECURITY_INFORMATION)
    dacl=sec.GetSecurityDescriptorDacl()
    if dacl is None: raise PrincipalIsolationDenied("null DACL forbidden")
    entries=[]
    for i in range(dacl.GetAceCount()):
        ace=dacl.GetAce(i)
        header,mask,sid=ace[0],ace[1],ace[2]
        name=win32security.ConvertSidToStringSid(sid)
        # Windows deny ACE type 1, allow ACE type 0. Audited explicit ACL
        # should never trust inherited or object-specific unhandled ACEs.
        if header[0] not in (0,1):
            raise PrincipalIsolationDenied("unsupported ACL entry")
        entries.append((header[0],int(mask),name))
    return entries


def verify_receiver_isolation(root, *, receiver_sid, worker_sid):
    import win32security
    import win32api
    import win32con
    if os.name!="nt" or not all(type(x) is str for x in
                                (receiver_sid,worker_sid)):
        raise PrincipalIsolationDenied("Windows and SID pins required")
    if receiver_sid==worker_sid:
        raise PrincipalIsolationDenied("same Windows principal not isolation")
    for sidstr in (receiver_sid,worker_sid):
        try:
            win32security.ConvertStringSidToSid(sidstr)
        except Exception as exc:
            raise PrincipalIsolationDenied("malformed pinned SID") from exc
    if own_sid()!=receiver_sid or receiver_sid in UNTRUSTED_BROAD_SIDS or \
            receiver_sid in (ADMIN_SID,SYSTEM_SID):
        raise PrincipalIsolationDenied("receiver not running as pinned isolated account")
    # A restricted account must not hold elevated Administrators membership.
    current_token=win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),win32con.TOKEN_QUERY)
    groups=win32security.GetTokenInformation(current_token,
                                             win32security.TokenGroups)
    for sid,attrs in groups:
        groupname=win32security.ConvertSidToStringSid(sid)
        if groupname==ADMIN_SID and attrs & 0x00000004:
            raise PrincipalIsolationDenied("receiver has administrator privileges")
    p=Path(root)
    if not p.is_dir() or p.is_symlink() or \
            (p.stat().st_file_attributes & REPARSE_ATTR):
        raise PrincipalIsolationDenied("protected root missing/reparse")
    acl=_get_acl_sids(p)
    # All inheritable/broad allows are rejected, including read-only broad
    # ACEs. Only receiver, SYSTEM and Administrators may be allowed.
    approved={receiver_sid,SYSTEM_SID,ADMIN_SID}
    has_receiver_write=False
    for ace_type,mask,name in acl:
        if ace_type==0:
            if name not in approved or name in UNTRUSTED_BROAD_SIDS or \
                    name==worker_sid:
                raise PrincipalIsolationDenied("unsafe allow ACE in protected root")
            if name==receiver_sid and mask & FILE_WRITE_MASK:
                has_receiver_write=True
    if not has_receiver_write:
        raise PrincipalIsolationDenied("receiver has no explicit write ACE")
    return dict(status="SEPARATE_SID_AND_PROTECTED_DACL_VERIFIED_SANDBOX_ONLY",
                receiver_sid_verified=True,
                worker_sid_distinct=True,
                protected_root_checked=True,
                signed_owner_and_external_highwater_checked=False,
                live_execution_allowed=False,
                production_queue_allowed=False)


def verify_operator_public_config(config_file, *, receiver_sid, worker_sid):
    """Fail closed unless the installed public-pin file AND its directory
    have explicitly protected Windows NTFS DACLs. Do not trust filename alone.
    This is not proof of real owner's GitHub ACL or independent signing.
    """
    if os.name!="nt" or type(receiver_sid) is not str or \
            type(worker_sid) is not str or receiver_sid==worker_sid:
        raise PrincipalIsolationDenied("invalid service identity pins")
    p=Path(config_file)
    if (not p.is_file() or p.is_symlink() or
            not p.parent.is_dir() or p.parent.is_symlink() or
            p.stat().st_file_attributes & REPARSE_ATTR or
            p.parent.stat().st_file_attributes & REPARSE_ATTR):
        raise PrincipalIsolationDenied("operator public config is reparse/missing")
    for protected_path in (p.parent,p):
        acl=_get_acl_sids(protected_path)
        has_receiver_read=False
        for ace_type,mask,name in acl:
            if ace_type==0:
                if name not in {receiver_sid,SYSTEM_SID,ADMIN_SID}:
                    raise PrincipalIsolationDenied("untrusted public pin ACL")
                if name==worker_sid or name in UNTRUSTED_BROAD_SIDS:
                    raise PrincipalIsolationDenied("worker/broad access to operator pins")
                if name==receiver_sid and mask & FILE_WRITE_MASK:
                    raise PrincipalIsolationDenied("receiver could replace own owner pin")
                if name==receiver_sid and mask & 0x0001:
                    has_receiver_read=True
        if not has_receiver_read:
            raise PrincipalIsolationDenied("service account cannot read pinned config")
    return {"status":"OPERATOR_PUBLIC_PIN_CONFIG_READ_ONLY_FOR_RECEIVER",
            "worker_can_modify_config":False,
            "owner_authority_independently_authenticated":False,
            "live_execution_allowed":False}
