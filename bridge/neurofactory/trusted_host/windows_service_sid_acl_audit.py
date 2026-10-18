"""Read-only Windows SCM/NTFS diagnostic. Never installs services or changes ACLs.

The result is a bounded snapshot, NOT proof of a live Windows service security
boundary, trusted caller identity, hardware signer, reboot safety or permission
for effect/publishing. Administrators and SYSTEM remain privileged OS trust roots.
"""
import os
from pathlib import Path

# NTFS write, append, attribute modification, delete, ACL/owner mutation, generic
# write/all and MAXIMUM_ALLOWED bits.  Avoid equating "no FILE_WRITE_DATA" with
# no way to change a directory or its entries.
_MODIFY_MASK = (
    0x00000002 | 0x00000004 | 0x00000010 | 0x00000020 |
    0x00000040 | 0x00000100 | 0x00010000 | 0x00040000 |
    0x00080000 | 0x00120116 | 0x02000000 | 0x10000000 |
    0x40000000
)
_SYSTEM = "S-1-5-18"
_ADMINISTRATORS = "S-1-5-32-544"
_PRIVILEGED_WRITERS = frozenset((_SYSTEM, _ADMINISTRATORS))


class IsolationDenied(ValueError):
    pass


def _deny():
    raise IsolationDenied("Windows receiver principal and protected ACL not independently established")


def _verify_acl_entries(entries, receiver_sid, worker_sid, owner_sid, protected):
    """Pure fail-closed ACL snapshot verifier; no Windows privileges or side effects.

    entries: sequence of (SID string, ACE type 0=allow/1=deny, access mask).
    This verifies the *directory* DACL only. It does not prove the worker's
    actual token/group membership or prevent a privileged OS administrator from
    changing ACLs after inspection. Never use this verdict as a release grant.
    """
    if type(protected) is not bool or not protected:
        _deny()
    if any(type(sid) is not str or not sid for sid in
           (receiver_sid, worker_sid, owner_sid)):
        _deny()
    if receiver_sid == worker_sid or worker_sid in _PRIVILEGED_WRITERS:
        _deny()
    # A worker owning the directory can change its DACL even without a write ACE.
    # Unknown owners may have the same privilege; accept only scoped receiver or
    # the Windows system/administrator trusted operating-system principals.
    if owner_sid not in (_SYSTEM, _ADMINISTRATORS, receiver_sid):
        _deny()
    if type(entries) not in (tuple, list) or not 0 < len(entries) <= 1024:
        _deny()

    receiver_writable = False
    privileged_writers = set()
    for entry in entries:
        if type(entry) not in (list, tuple) or len(entry) != 3:
            _deny()
        sid, ace_type, mask = entry
        if type(sid) is not str or not sid or type(ace_type) is not int or type(mask) is not int:
            _deny()
        # Object/callback/conditional ACEs require additional evaluation; do not
        # silently ignore a possible grant that this inspector cannot interpret.
        if ace_type not in (0, 1) or mask < 0:
            _deny()
        if mask & _MODIFY_MASK:
            if ace_type == 1:
                # Deny ACEs may cancel the receiver's permission via group SIDs.
                # Group membership is not evaluated here: refuse ambiguous ACLs.
                _deny()
            if sid == receiver_sid:
                receiver_writable = True
            elif sid in _PRIVILEGED_WRITERS:
                privileged_writers.add(sid)
            else:
                # Includes worker, Everyone, Authenticated Users, Users AND
                # arbitrary unrelated user/group SIDs.
                _deny()
    if not receiver_writable:
        _deny()
    return tuple(sorted(privileged_writers))


def _check_local_root(path):
    # Reject relative/UNC locations and reparse points anywhere in the path,
    # not just at the final directory. This is a read-only momentary snapshot.
    if not isinstance(path, (str, Path)):
        _deny()
    p = Path(path)
    if not p.is_absolute() or str(p).startswith("\\\\") or not p.is_dir():
        _deny()
    current = p
    while True:
        stat = os.lstat(current)
        if getattr(stat, "st_file_attributes", 0) & 0x400:
            _deny()
        if current == current.parent:
            break
        current = current.parent
    return p


def inspect_windows_two_sid_boundary(service_name, root, worker_sid):
    if os.name != "nt" or service_name != "NeurofactorySandboxReceiver" or type(worker_sid) is not str:
        _deny()
    try:
        import win32security
        import win32con
        import win32service

        # This checks SID syntax, NOT whether the supplied SID belongs to the
        # active CORE worker process. That needs a separate kernel token check.
        if not worker_sid.startswith("S-1-5-21-"):
            _deny()
        canonical = win32security.ConvertSidToStringSid(
            win32security.ConvertStringSidToSid(worker_sid))
        if worker_sid != canonical:
            _deny()
        p = _check_local_root(root)
        manager = win32service.OpenSCManager(None, None, win32con.SC_MANAGER_CONNECT)
        try:
            service = win32service.OpenService(
                manager, service_name, win32service.SERVICE_QUERY_CONFIG)
            try:
                config = win32service.QueryServiceConfig(service)
            finally:
                win32service.CloseServiceHandle(service)
        finally:
            win32service.CloseServiceHandle(manager)

        account = str(config[7])
        if account.lower() in (
            "localsystem", "nt authority\\system", "nt authority\\networkservice",
            "nt authority\\localservice"):
            # Shared built-in logon identity is insufficient to establish a
            # receiver-specific SID; this diagnostic does not inspect the
            # actual service token / restricted service SID configuration.
            _deny()
        receiver_sid = win32security.ConvertSidToStringSid(
            win32security.LookupAccountName(None, account)[0])
        sd = win32security.GetNamedSecurityInfo(
            str(p), win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION |
            win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            _deny()
        owner_sid = win32security.ConvertSidToStringSid(
            sd.GetSecurityDescriptorOwner())
        control = sd.GetSecurityDescriptorControl()[0]
        entries = []
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            entries.append((
                win32security.ConvertSidToStringSid(ace[2]),
                ace[0][0],
                ace[1],
            ))
        privileged_writers = _verify_acl_entries(
            entries, receiver_sid, worker_sid, owner_sid,
            bool(control & win32security.SE_DACL_PROTECTED))
        return {
            "status": "SCM_ACCOUNT_AND_PROTECTED_DIRECTORY_ACL_SNAPSHOT_ONLY",
            "receiver_sid": receiver_sid,
            "worker_sid_supplied_not_token_attested": worker_sid,
            "receiver_directory_write_ace_observed": True,
            "privileged_os_writers_observed": list(privileged_writers),
            "service_process_token_attested_here": False,
            "worker_process_token_attested_here": False,
            "pipe_peer_impersonation_tested_here": False,
            "independent_owner_key_verified_here": False,
            "external_witness_highwater_verified_here": False,
            "live_execution_allowed": False,
            "release_approved": False,
        }
    except IsolationDenied:
        raise
    except Exception as exc:
        raise IsolationDenied("Windows SCM or NTFS access denied/unavailable") from exc
