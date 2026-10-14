"""Windows-only restrictive DACL gate for private model-response evidence.

Fail closed.  Only the directory owner, NT AUTHORITY\SYSTEM and BUILTIN\
Administrators may have allow ACEs.  Unknown/compound ACEs, missing DACL,
inaccessible ACL, unsupported filesystems, and foreign ownership are rejected.

This is a local defensive ACL check, NOT a race-free directory capability and
NOT a substitute for an independently authorized Windows service account.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os


class WindowsAclError(RuntimeError):
    pass


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_ubyte),
        ("AceFlags", ctypes.c_ubyte),
        ("AceSize", wintypes.WORD),
    ]


def require_private_windows_acl(directory) -> None:
    """Reject Windows directory unless a narrowly scoped DACL is confirmed.

    The check must be repeated immediately around file operations. Windows
    directory replacement/hostile concurrent ACL modification is not proven
    impossible: all such operations still require a trusted exclusive owner.
    """
    if os.name != "nt":
        return
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_named = advapi.GetNamedSecurityInfoW
        get_named.argtypes = [
            wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        get_named.restype = wintypes.DWORD
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        # SE_FILE_OBJECT=1, OWNER_SECURITY_INFORMATION=1, DACL=4
        status = get_named(
            str(directory), 1, 5, ctypes.byref(owner), None,
            ctypes.byref(dacl), None, ctypes.byref(descriptor),
        )
        if status != 0 or not descriptor.value:
            raise WindowsAclError("cannot inspect Windows evidence ACL")
        try:
            if not owner.value or not dacl.value:
                raise WindowsAclError("missing owner or null DACL")
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            advapi.OpenProcessToken.argtypes = [
                wintypes.HANDLE, wintypes.DWORD,
                ctypes.POINTER(wintypes.HANDLE),
            ]
            advapi.OpenProcessToken.restype = wintypes.BOOL
            token = wintypes.HANDLE()
            # TOKEN_QUERY=8
            if not advapi.OpenProcessToken(
                kernel.GetCurrentProcess(), 8, ctypes.byref(token)
            ):
                raise WindowsAclError("cannot query Windows access token")
            try:
                advapi.GetTokenInformation.argtypes = [
                    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                ]
                advapi.GetTokenInformation.restype = wintypes.BOOL
                count = wintypes.DWORD()
                # TokenUser=1; first call discovers required buffer size.
                advapi.GetTokenInformation(token, 1, None, 0,
                                           ctypes.byref(count))
                if not 8 <= count.value <= 4096:
                    raise WindowsAclError("untrusted token buffer size")
                buffer = ctypes.create_string_buffer(count.value)
                if not advapi.GetTokenInformation(
                    token, 1, buffer, count.value, ctypes.byref(count)
                ):
                    raise WindowsAclError("cannot read current user SID")
                user_sid = ctypes.c_void_p.from_buffer(buffer).value
                if not user_sid:
                    raise WindowsAclError("missing user SID")

                advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                advapi.EqualSid.restype = wintypes.BOOL
                if not advapi.EqualSid(owner, ctypes.c_void_p(user_sid)):
                    raise WindowsAclError("owner differs from runner identity")

                advapi.GetAclInformation.argtypes = [
                    ctypes.c_void_p, ctypes.c_void_p,
                    wintypes.DWORD, ctypes.c_int,
                ]
                advapi.GetAclInformation.restype = wintypes.BOOL
                info = _AclSizeInformation()
                # AclSizeInformation=2
                if not advapi.GetAclInformation(
                    dacl, ctypes.byref(info), ctypes.sizeof(info), 2
                ):
                    raise WindowsAclError("cannot inspect DACL entries")
                if not 1 <= info.AceCount <= 64:
                    raise WindowsAclError("empty or unusually large evidence ACL")

                advapi.GetAce.argtypes = [
                    ctypes.c_void_p, wintypes.DWORD,
                    ctypes.POINTER(ctypes.c_void_p),
                ]
                advapi.GetAce.restype = wintypes.BOOL
                advapi.IsWellKnownSid.argtypes = [
                    ctypes.c_void_p, ctypes.c_int,
                ]
                advapi.IsWellKnownSid.restype = wintypes.BOOL
                for index in range(info.AceCount):
                    ace = ctypes.c_void_p()
                    if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                        raise WindowsAclError("cannot inspect ACE")
                    if not ace.value:
                        raise WindowsAclError("null ACE")
                    header = _AceHeader.from_address(ace.value)
                    # 0 = ACCESS_ALLOWED_ACE, 1 = ACCESS_DENIED_ACE.
                    # Object/conditional/callback ACEs need their own parser:
                    # reject rather than mistakenly grant access.
                    if header.AceType == 1:
                        continue
                    if header.AceType != 0 or header.AceSize < 12:
                        raise WindowsAclError("unsupported Windows ACE")
                    ace_sid = ctypes.c_void_p(ace.value + 8)
                    # Well-known 22=WinLocalSystemSid, 26=WinBuiltinAdministratorsSid
                    if (advapi.EqualSid(ace_sid, ctypes.c_void_p(user_sid))
                        or advapi.IsWellKnownSid(ace_sid, 22)
                        or advapi.IsWellKnownSid(ace_sid, 26)):
                        continue
                    raise WindowsAclError("evidence ACL includes foreign principal")
            finally:
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                kernel.CloseHandle.restype = wintypes.BOOL
                kernel.CloseHandle(token)
        finally:
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            kernel.LocalFree.restype = ctypes.c_void_p
            kernel.LocalFree(descriptor)
    except WindowsAclError:
        raise
    except (AttributeError, OSError, ValueError, TypeError) as exc:
        raise WindowsAclError("unable to verify private Windows evidence ACL") from exc
