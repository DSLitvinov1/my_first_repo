"""Work ONE per-Windows-user encrypted secret vault (DPAPI only).

No secrets ever appear in SQLite, logs, screenshots, commands, Git, or URLs.
Access tokens and refresh tokens are inaccessible unless running as the same
Windows user. Cross-platform development/test mode has no persistent vault.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import secrets
import time

from work_core import WorkDenied

APP_NAMES = frozenset(("google", "bitrix24"))
SCOPE_NAMES = frozenset(("tasks","task","crm","drive.metadata.readonly",
                         "gmail.readonly","calendar.readonly"))
KEY_RE = re.compile(r"^[a-z0-9.-]{2,90}$")


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytes):
    buf=ctypes.create_string_buffer(data)
    return DataBlob(len(data),ctypes.cast(buf,ctypes.POINTER(ctypes.c_ubyte))),buf


def dpapi_protect(data: bytes):
    if os.name != "nt":
        raise WorkDenied("VAULT_WINDOWS_DPAPI_REQUIRED")
    inp,owner=_blob(data)
    output=DataBlob()
    crypt=ctypes.windll.crypt32.CryptProtectData
    crypt.argtypes=[ctypes.POINTER(DataBlob),wintypes.LPCWSTR,
                    ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,
                    wintypes.DWORD,ctypes.POINTER(DataBlob)]
    crypt.restype=wintypes.BOOL
    if not crypt(ctypes.byref(inp),"Neirozavod ONE user secret",None,
                 None,None,0,ctypes.byref(output)):
        raise WorkDenied("VAULT_PROTECT_FAILED")
    try:
        return ctypes.string_at(output.pbData,output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


def dpapi_unprotect(data: bytes):
    if os.name != "nt":
        raise WorkDenied("VAULT_WINDOWS_DPAPI_REQUIRED")
    inp,owner=_blob(data)
    output=DataBlob()
    crypt=ctypes.windll.crypt32.CryptUnprotectData
    crypt.argtypes=[ctypes.POINTER(DataBlob),ctypes.c_void_p,
                    ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,
                    wintypes.DWORD,ctypes.POINTER(DataBlob)]
    crypt.restype=wintypes.BOOL
    if not crypt(ctypes.byref(inp),None,None,None,None,0,ctypes.byref(output)):
        raise WorkDenied("VAULT_UNLOCK_REFUSED")
    try:
        return ctypes.string_at(output.pbData,output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


class UserVault:
    def __init__(self, root=None):
        if root is None:
            local=os.environ.get("LOCALAPPDATA")
            if not local or os.name!="nt":
                self.root=None
                return
            root=Path(local)/"NeirozavodWorkOne"/"secrets"
        self.root=Path(root)

    def ready(self):
        return os.name=="nt" and self.root is not None

    def _path(self, provider, scope):
        if (provider not in APP_NAMES or scope not in SCOPE_NAMES or
                not KEY_RE.fullmatch(provider+"."+scope) or not self.root):
            raise WorkDenied("VAULT_KEY_NOT_ALLOWED")
        return self.root/(provider+"."+scope+".dpapi")

    def put(self, provider, scope, data):
        if not self.ready():
            raise WorkDenied("VAULT_WINDOWS_DPAPI_REQUIRED")
        if type(data) is not dict or len(json.dumps(data))>16000:
            raise WorkDenied("VAULT_DATA_REFUSED")
        path=self._path(provider,scope)
        if self.root.is_symlink() or (path.exists() and path.is_symlink()):
            raise WorkDenied("VAULT_SYMLINK_REFUSED")
        self.root.mkdir(parents=True,exist_ok=True)
        payload=json.dumps(data,ensure_ascii=False,
                           separators=(",",":")).encode("utf8")
        encrypted=dpapi_protect(payload)
        tmp=path.with_name(path.name+"."+secrets.token_hex(8)+".tmp")
        try:
            with tmp.open("xb") as f:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp,path)
        finally:
            try: tmp.unlink(missing_ok=True)
            except OSError: pass

    def get(self, provider, scope):
        if not self.ready():
            return None
        path=self._path(provider,scope)
        if not path.is_file() or path.is_symlink():
            return None
        if path.stat().st_size>20000:
            raise WorkDenied("VAULT_BLOB_TOO_LARGE")
        data=json.loads(dpapi_unprotect(path.read_bytes()).decode("utf8"))
        if type(data) is not dict:
            raise WorkDenied("VAULT_DATA_INVALID")
        return data

    def delete(self, provider, scope):
        if not self.ready():
            raise WorkDenied("VAULT_WINDOWS_DPAPI_REQUIRED")
        path=self._path(provider,scope)
        if path.is_symlink():
            raise WorkDenied("VAULT_SYMLINK_REFUSED")
        path.unlink(missing_ok=True)
