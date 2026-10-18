"""Grant SeServiceLogonRight ONLY to a newly created disposable CI SID.

This intentionally does not run outside hosted GitHub Windows Actions and
does not create, inspect or export private keys. The entire ephemeral runner
is destroyed at job end. NEVER use this as an installer on user's Windows.
"""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import os
import re
import sys

class LSA_UNICODE_STRING(ctypes.Structure):
    _fields_=[("Length",wintypes.USHORT),
              ("MaximumLength",wintypes.USHORT),
              ("Buffer",wintypes.LPWSTR)]

class LSA_OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_=[("Length",wintypes.ULONG),
              ("RootDirectory",wintypes.HANDLE),
              ("ObjectName",ctypes.c_void_p),
              ("Attributes",wintypes.ULONG),
              ("SecurityDescriptor",ctypes.c_void_p),
              ("SecurityQualityOfService",ctypes.c_void_p)]


def grant_ephemeral_service_right(sid_str):
    if (os.name!="nt" or os.environ.get("GITHUB_ACTIONS")!="true"
            or os.environ.get("NF_WINDOWS_TWO_SID_CI_ONLY")!="1"):
        raise RuntimeError("DISABLED OUTSIDE EPHEMERAL WINDOWS CI")
    if not re.fullmatch(r"S-1-5-21-(?:[0-9]{1,11}-){3}[0-9]{1,11}",sid_str):
        raise RuntimeError("only newly-provisioned local user SID allowed")
    adv=ctypes.WinDLL("advapi32",use_last_error=True)
    convert=adv.ConvertStringSidToSidW
    convert.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(ctypes.c_void_p)]
    convert.restype=wintypes.BOOL
    sid=ctypes.c_void_p()
    if not convert(sid_str,ctypes.byref(sid)):
        raise ctypes.WinError(ctypes.get_last_error())
    localfree=ctypes.WinDLL("kernel32",use_last_error=True).LocalFree
    localfree.argtypes=[ctypes.c_void_p]
    localfree.restype=ctypes.c_void_p
    handle=wintypes.HANDLE()
    attrs=LSA_OBJECT_ATTRIBUTES()
    attrs.Length=ctypes.sizeof(attrs)
    open_policy=adv.LsaOpenPolicy
    open_policy.argtypes=[ctypes.c_void_p,ctypes.POINTER(LSA_OBJECT_ATTRIBUTES),
                          wintypes.ULONG,ctypes.POINTER(wintypes.HANDLE)]
    open_policy.restype=ctypes.c_long
    add=adv.LsaAddAccountRights
    add.argtypes=[wintypes.HANDLE,ctypes.c_void_p,
                  ctypes.POINTER(LSA_UNICODE_STRING),wintypes.ULONG]
    add.restype=ctypes.c_long
    close=adv.LsaClose
    close.argtypes=[wintypes.HANDLE]
    close.restype=ctypes.c_long
    nt2win=adv.LsaNtStatusToWinError
    nt2win.argtypes=[ctypes.c_long]
    nt2win.restype=wintypes.ULONG
    try:
        status=open_policy(None,ctypes.byref(attrs),0x00000810,ctypes.byref(handle))
        if status!=0:
            raise ctypes.WinError(nt2win(status))
        try:
            raw="SeServiceLogonRight"
            buf=ctypes.create_unicode_buffer(raw)
            value=LSA_UNICODE_STRING(len(raw)*2,(len(raw)+1)*2,
                                     ctypes.cast(buf,wintypes.LPWSTR))
            result=add(handle,sid,ctypes.byref(value),1)
            if result!=0:
                raise ctypes.WinError(nt2win(result))
        finally:
            close(handle)
    finally:
        localfree(sid)
    print("NF_DISPOSABLE_RECEIVER_ACCOUNT_LOGON_AS_SERVICE_GRANTED=PASS")


if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("SID required")
    grant_ephemeral_service_right(sys.argv[1])
