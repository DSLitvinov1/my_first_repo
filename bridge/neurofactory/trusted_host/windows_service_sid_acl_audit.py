"""Read-only Windows SCM/NTFS isolation verifier. NEVER installs or changes ACL.

A running service named NeurofactorySandboxReceiver must have an explicitly
non-admin, non-worker logon SID, receiver-only write access to its output root,
and a separate client SID. Owner's real authorization, external antirollback
and independent REVIEW are additional gates not established by this utility.
"""
import os
from pathlib import Path

class IsolationDenied(ValueError):
    pass

def _deny():
    raise IsolationDenied("Windows receiver principal and protected ACL not independently established")

def inspect_windows_two_sid_boundary(service_name, root, worker_sid):
    if os.name!="nt" or service_name!="NeurofactorySandboxReceiver" or type(worker_sid) is not str:
        _deny()
    import win32security, win32con, win32service, win32serviceutil
    import ntsecuritycon
    if not worker_sid.startswith("S-1-5-21-"):
        _deny()
    p=Path(root)
    if p.is_symlink() or not p.is_dir() or p.stat().st_file_attributes & 0x400:
        _deny()
    try:
        manager=win32service.OpenSCManager(None,None,win32con.SC_MANAGER_CONNECT)
        try:
            service=win32service.OpenService(manager,service_name,win32service.SERVICE_QUERY_CONFIG)
            try:
                config=win32service.QueryServiceConfig(service)
            finally:
                win32service.CloseServiceHandle(service)
        finally:
            win32service.CloseServiceHandle(manager)
        account=str(config[7])
        if account.lower() in ("localsystem","nt authority\\system","nt authority\\networkservice",
                               "nt authority\\localservice","localsystem"):
            _deny()
        # Resolve the actual configured account, not a string copied from a request.
        receiver_sid=win32security.ConvertSidToStringSid(
            win32security.LookupAccountName(None,account)[0])
        if receiver_sid==worker_sid:
            _deny()
        sd=win32security.GetNamedSecurityInfo(
            str(p),win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION |
            win32security.DACL_SECURITY_INFORMATION)
        dacl=sd.GetSecurityDescriptorDacl()
        if dacl is None or not dacl.GetAceCount():
            _deny()
        forbidden={"S-1-1-0","S-1-5-11","S-1-5-32-545",worker_sid}
        protected_writer=False
        for i in range(dacl.GetAceCount()):
            ace=dacl.GetAce(i)
            # Reject dangerous inherited or explicit ALLOW ACE to worker,
            # Everyone, Authenticated Users, Users.
            sid=win32security.ConvertSidToStringSid(ace[2])
            ace_type=ace[0][0]
            access=ace[1]
            writable=bool(access & (
                ntsecuritycon.FILE_GENERIC_WRITE |
                ntsecuritycon.FILE_WRITE_DATA |
                ntsecuritycon.FILE_APPEND_DATA |
                win32con.GENERIC_ALL |
                win32con.GENERIC_WRITE |
                win32con.WRITE_DAC |
                win32con.WRITE_OWNER))
            if ace_type==win32security.ACCESS_ALLOWED_ACE_TYPE and writable:
                if sid in forbidden: _deny()
                if sid==receiver_sid: protected_writer=True
        if not protected_writer: _deny()
        return {
            "status":"TWO_DIFFERENT_WINDOWS_SIDS_AND_DIRECTORY_DACL_OBSERVED",
            "receiver_sid":receiver_sid,
            "worker_sid":worker_sid,
            "acl_writer_receiver_only_observed":True,
            "pipe_peer_impersonation_tested_here":False,
            "independent_owner_key_verified_here":False,
            "external_witness_highwater_verified_here":False,
            "live_execution_allowed":False,
            "release_approved":False
        }
    except IsolationDenied: raise
    except Exception as exc:
        raise IsolationDenied("Windows SCM or NTFS access denied/unavailable") from exc
