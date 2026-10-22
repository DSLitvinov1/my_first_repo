"""Windows SCM operator-acceptance service: safe, dormant, zero project effects.

Real Windows service implementation with ServiceMain/SCM handshake, built
using only the officially pinned embedded Python runtime and ctypes.
It is NOT a production CORE/HOST worker. It has no pipe listener,
owner private key, queue admission, file execution or automatic activation.
Service + config installed ONLY by separate privileged operator procedure.

The operator must provision a restricted service SID and immutable binary,
read-only config and dedicated writable diagnostic folder under protected
ProgramData ACLs. This module never grants permissions.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

NAME = "NeurofactoryCoreHost"
EXPECTED_SCHEMA = "nf.windows.dormant_host_provision.v1"
CFG_FIELDS = frozenset((
    "schema", "service_name", "source_sha40", "mode",
    "real_host_execution_allowed", "core_queue_allowed",
    "network_listener_allowed", "production_release_approved",
    "independent_review_approved", "owner_key_installed",
    "external_witness_verified",
))
FALSE_FIELDS = frozenset(CFG_FIELDS - {
    "schema", "service_name", "source_sha40", "mode"})
REVIEW_BLOCKED = "REVIEW_BLOCKED_NOT_PRODUCTION"
_SHA40 = re.compile(r"[a-f0-9]{40}\Z")

class DormantServiceDenied(ValueError):
    pass

def validate_config(raw: bytes):
    if type(raw) is not bytes or not 100 <= len(raw) <= 1400:
        raise DormantServiceDenied("Missing or oversized sealed readiness config")
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:
                raise DormantServiceDenied("Duplicate protected config field")
            result[k]=v
        return result
    try:
        doc=json.loads(raw.decode("ascii"),object_pairs_hook=unique)
    except (UnicodeError, ValueError, RecursionError, TypeError) as exc:
        raise DormantServiceDenied("Invalid config") from exc
    if (type(doc) is not dict or set(doc)!=CFG_FIELDS or
            doc["schema"]!=EXPECTED_SCHEMA or
            doc["service_name"]!=NAME or
            type(doc["source_sha40"]) is not str or
            not _SHA40.fullmatch(doc["source_sha40"]) or
            doc["mode"]!=REVIEW_BLOCKED or
            any(doc[k] is not False for k in FALSE_FIELDS)):
        raise DormantServiceDenied("Production execution is not authorized")
    return doc

def _regular(path: Path, *, directory: bool):
    try:
        if path.is_symlink():
            raise DormantServiceDenied("Linked path")
        info=path.lstat()
        good=stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not good or info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise DormantServiceDenied("Nonregular or reparse path")
        return info
    except OSError as exc:
        raise DormantServiceDenied("Missing service resource") from exc

def prepare_dormant(root: Path):
    """Validate only immutable read input; never elevate privileges."""
    if os.name!="nt" or not root.is_absolute():
        raise DormantServiceDenied("Windows installed service only")
    _regular(root,directory=True)
    config=root/"dormant-config.json"
    if not 100<=_regular(config,directory=False).st_size<=1400:
        raise DormantServiceDenied("Invalid protected config size")
    doc=validate_config(config.read_bytes())
    output=root/"status"
    _regular(output,directory=True)
    # The operator-provisioned ACL is also required; this pure check alone
    # cannot establish the service SID/DACL, verified separately at runtime.
    return doc,output

def _assert_readonly_install_root(root: Path):
    # POSIX permissions / os.access do not represent Windows restricted
    # tokens. Prove directly that this REAL service token cannot create a
    # non-status file in the operator-owned immutable installation root.
    name=root/("nf-protected-write-denial-"+secrets.token_hex(12)+".tmp")
    try:
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    except PermissionError:
        return True
    except OSError as exc:
        raise DormantServiceDenied("Read-only root probe inconclusive") from exc
    else:
        os.close(fd)
        try: name.unlink()
        finally: raise DormantServiceDenied("Restricted service can modify immutable files")

def _publish_status(folder: Path,doc):
    marker={
        "schema":"nf.windows.dormant_service_status.v1",
        "status":REVIEW_BLOCKED,
        "service_name":NAME,
        "source_sha40":doc["source_sha40"],
        "core_queue_allowed":False,
        "host_execution_allowed":False,
        "untrusted_model_effects_allowed":False,
        "independent_review_complete":False,
        "protected_runtime_production_attested":False,
        "immutable_install_root_write_denied":True,
    }
    raw=(json.dumps(marker,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
    tmp=folder/("nf-readiness-"+secrets.token_hex(12)+".tmp")
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,"wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp,folder/"dormant-status.json")
    finally:
        try:tmp.unlink(missing_ok=True)
        except OSError:pass

def run_windows_service():
    if os.name!="nt":
        raise DormantServiceDenied("Not Windows")
    # SCM callback. No network, subprocess, project-file writer or model.
    advapi32=ctypes.WinDLL("advapi32",use_last_error=True)
    kernel32=ctypes.WinDLL("kernel32",use_last_error=True)
    DWORD=wintypes.DWORD
    HANDLE=wintypes.HANDLE
    LPVOID=wintypes.LPVOID
    CALLBACK=ctypes.WINFUNCTYPE(DWORD,DWORD,DWORD,LPVOID,LPVOID)
    MAIN=ctypes.WINFUNCTYPE(None,DWORD,ctypes.POINTER(wintypes.LPWSTR))
    SERVICE_WIN32_OWN_PROCESS=0x10
    SERVICE_START_PENDING=2
    SERVICE_RUNNING=4
    SERVICE_STOP_PENDING=3
    SERVICE_STOPPED=1
    SERVICE_ACCEPT_STOP=1
    SERVICE_CONTROL_STOP=1
    NO_ERROR=0
    ERROR_SERVICE_SPECIFIC_ERROR=1066
    WAIT_INFINITE=0xFFFFFFFF
    class STATUS(ctypes.Structure):
        _fields_=[
            ("dwServiceType",DWORD),("dwCurrentState",DWORD),
            ("dwControlsAccepted",DWORD),("dwWin32ExitCode",DWORD),
            ("dwServiceSpecificExitCode",DWORD),("dwCheckPoint",DWORD),
            ("dwWaitHint",DWORD)]
    class TABLE(ctypes.Structure):
        _fields_=[("lpServiceName",wintypes.LPWSTR),("lpServiceProc",MAIN)]
    advapi32.RegisterServiceCtrlHandlerExW.argtypes=[wintypes.LPCWSTR,CALLBACK,LPVOID]
    advapi32.RegisterServiceCtrlHandlerExW.restype=HANDLE
    advapi32.SetServiceStatus.argtypes=[HANDLE,ctypes.POINTER(STATUS)]
    advapi32.SetServiceStatus.restype=wintypes.BOOL
    advapi32.StartServiceCtrlDispatcherW.argtypes=[ctypes.POINTER(TABLE)]
    advapi32.StartServiceCtrlDispatcherW.restype=wintypes.BOOL
    kernel32.CreateEventW.argtypes=[LPVOID,wintypes.BOOL,wintypes.BOOL,wintypes.LPCWSTR]
    kernel32.CreateEventW.restype=HANDLE
    kernel32.SetEvent.argtypes=[HANDLE]
    kernel32.SetEvent.restype=wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes=[HANDLE,DWORD]
    kernel32.WaitForSingleObject.restype=DWORD
    kernel32.CloseHandle.argtypes=[HANDLE]
    kernel32.CloseHandle.restype=wintypes.BOOL
    stop=kernel32.CreateEventW(None,True,False,None)
    if not stop:
        raise DormantServiceDenied("Cannot create service stop event")
    current={"handle":None}
    def status(state,error=NO_ERROR,checkpoint=0):
        handle=current["handle"]
        if not handle:return
        item=STATUS(SERVICE_WIN32_OWN_PROCESS,state,
                    SERVICE_ACCEPT_STOP if state==SERVICE_RUNNING else 0,
                    error,1 if error else 0,checkpoint,
                    15000 if state in (SERVICE_START_PENDING,SERVICE_STOP_PENDING) else 0)
        if not advapi32.SetServiceStatus(handle,ctypes.byref(item)):
            raise DormantServiceDenied("SCM rejected service status")
    @CALLBACK
    def control(ctrl,event_type,data,context):
        if ctrl==SERVICE_CONTROL_STOP:
            try: status(SERVICE_STOP_PENDING)
            finally:kernel32.SetEvent(stop)
        return NO_ERROR
    @MAIN
    def service_main(argc,argv):
        try:
            current["handle"]=advapi32.RegisterServiceCtrlHandlerExW(NAME,control,None)
            if not current["handle"]:
                return
            status(SERVICE_START_PENDING,checkpoint=1)
            root=Path(__file__).resolve().parent
            doc,folder=prepare_dormant(root)
            _assert_readonly_install_root(root)
            _publish_status(folder,doc)
            status(SERVICE_RUNNING)
            kernel32.WaitForSingleObject(stop,WAIT_INFINITE)
            status(SERVICE_STOPPED)
        except Exception:
            try:status(SERVICE_STOPPED,ERROR_SERVICE_SPECIFIC_ERROR)
            except Exception:pass
    cb=TABLE(NAME,service_main)
    null=TABLE(None,MAIN())
    array=(TABLE*2)(cb,null)
    try:
        if not advapi32.StartServiceCtrlDispatcherW(array):
            raise DormantServiceDenied("Must be started by Windows SCM")
    finally:
        kernel32.CloseHandle(stop)

if __name__=="__main__":
    if len(sys.argv)!=1 or os.name!="nt":
        raise SystemExit("Service accepts SCM start only, no user CLI")
    run_windows_service()
