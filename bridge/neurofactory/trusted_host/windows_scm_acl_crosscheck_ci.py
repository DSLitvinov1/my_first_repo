"""Read-only, disposable GitHub CI cross-check for pinned Windows SCM + ACL.

This measures ONE current service/token/DACL snapshot and never grants LIVE
execution. CI checks an enabled and restricting per-service SID, but this is
NOT production attestation, owner permission, or evidence from physical PCs.
The policy engine comes from an immutable, independently pinned HOST PR #29.
"""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path

CI_SERVICE_NAME = "NeurofactorySandboxReceiverCI"
CI_SERVICE_SID = "S-1-5-19"  # Logon identity; not a per-service principal.
CI_RESTRICTED_SERVICE_NAME = r"NT SERVICE\NeurofactorySandboxReceiverCI"
EXPECTED_ACL_POLICY_BLOB = "d135a4f9f763cb4b454bdce4c0121dd91422e76c"


class CIBoundaryDenied(ValueError):
    pass


def _deny(message="Windows CI service SID/ACL snapshot rejected"):
    raise CIBoundaryDenied(message)


def _load_pinned_acl_policy(policy_path):
    """Only fixed, independently checked-out source; hash verification in CI."""
    path = Path(policy_path).resolve()
    expected = (
        Path(__file__).resolve().parents[3] /
        ".nf_pinned_acl" / "bridge" / "neurofactory" /
        "trusted_host" / "windows_service_sid_acl_audit.py"
    ).resolve()
    if path != expected or not path.is_file():
        _deny("pinned source missing or path substituted")
    spec = importlib.util.spec_from_file_location("nf_pinned_host_acl_policy", path)
    if spec is None or spec.loader is None:
        _deny("ACL policy unreadable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect_disposable_ci_service(root, worker_sid, policy_path):
    """Return observation-only evidence, never permission to execute.

    Worker SID is provisioned by test operator and compared with the worker's
    separately launched OS identity in the fixture, not learned from a packet.
    Actual live SCM service PID and corresponding kernel process token are read
    independently of service configuration; DACL is examined on the filesystem.
    """
    if (
        os.name != "nt" or
        os.getenv("GITHUB_ACTIONS") != "true" or
        os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or
        os.getenv("NF_WINDOWS_SCM_DISPOSABLE_ONLY") != "1" or
        type(worker_sid) is not str or
        not worker_sid.startswith("S-1-5-21-")
    ):
        _deny("not an explicitly authorized ephemeral GitHub Windows fixture")
    import win32api
    import win32con
    import win32security
    import win32service

    try:
        policy = _load_pinned_acl_policy(policy_path)
        folder = policy._check_local_root(root)
        worker_sid_canonical = win32security.ConvertSidToStringSid(
            win32security.ConvertStringSidToSid(worker_sid))
        if worker_sid != worker_sid_canonical or worker_sid == CI_SERVICE_SID:
            _deny("invalid/potentially shared worker SID")

        mgr = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            svc = win32service.OpenService(
                mgr, CI_SERVICE_NAME,
                win32service.SERVICE_QUERY_CONFIG |
                win32service.SERVICE_QUERY_STATUS)
            try:
                config = win32service.QueryServiceConfig(svc)
                status = win32service.QueryServiceStatusEx(svc)
                sid_type = win32service.QueryServiceConfig2(
                    svc, win32service.SERVICE_CONFIG_SERVICE_SID_INFO)
            finally:
                win32service.CloseServiceHandle(svc)
        finally:
            win32service.CloseServiceHandle(mgr)

        if str(config[7]).lower() not in (
            "nt authority\\localservice", "localservice"
        ):
            _deny("unexpected configured Windows service logon identity")
        if sid_type != 3:  # SERVICE_SID_TYPE_RESTRICTED
            _deny("SCM service SID is not configured restricted")
        expected_service_sid = win32security.ConvertSidToStringSid(
            win32security.LookupAccountName(None, CI_RESTRICTED_SERVICE_NAME)[0])
        if not expected_service_sid.startswith("S-1-5-80-"):
            _deny("untrusted per-service SID")
        if status.get("CurrentState") != win32service.SERVICE_RUNNING:
            _deny("SCM receiver is not running")
        pid = status.get("ProcessId")
        if type(pid) is not int or pid < 4:
            _deny("SCM service PID not available")
        # Obtain the REAL process access token; neither config nor input
        # JSON can forge this OS kernel-linked identity query.
        process = win32api.OpenProcess(
            win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        try:
            token = win32security.OpenProcessToken(
                process, win32con.TOKEN_QUERY)
            try:
                sid = win32security.GetTokenInformation(
                    token, win32security.TokenUser)[0]
                running_service_sid = win32security.ConvertSidToStringSid(sid)
                groups = win32security.GetTokenInformation(
                    token, win32security.TokenGroups)
                restricted = win32security.GetTokenInformation(
                    token, win32security.TokenRestrictedSids)
                group_sids = {
                    win32security.ConvertSidToStringSid(s): attrs
                    for s, attrs in groups
                }
                restricted_sids = {
                    win32security.ConvertSidToStringSid(s)
                    for s, _ in restricted
                }
                if not (group_sids.get(expected_service_sid, 0) & 0x4):
                    _deny("service SID not enabled in running process token")
                if expected_service_sid not in restricted_sids:
                    _deny("per-service SID absent from token restricted list")
            finally:
                token.Close()
        finally:
            process.Close()
        if running_service_sid != CI_SERVICE_SID:
            _deny("real SCM process SID differs from configured LocalService")

        descriptor = win32security.GetNamedSecurityInfo(
            str(folder), win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION |
            win32security.DACL_SECURITY_INFORMATION)
        dacl = descriptor.GetSecurityDescriptorDacl()
        if dacl is None:
            _deny("unprotected/null DACL")
        owner = win32security.ConvertSidToStringSid(
            descriptor.GetSecurityDescriptorOwner())
        control = descriptor.GetSecurityDescriptorControl()[0]
        entries = []
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            entries.append((
                win32security.ConvertSidToStringSid(ace[2]),
                ace[0][0],
                ace[1],
            ))
        privileged = policy._verify_acl_entries(
            entries, expected_service_sid, worker_sid, owner,
            bool(control & win32security.SE_DACL_PROTECTED))
        return {
            "status": "EPHEMERAL_CI_RESTRICTED_SERVICE_SID_TOKEN_AND_NTFS_SNAPSHOT_ONLY",
            "restricted_service_sid": expected_service_sid,
            "service_sid_enabled_in_token": True,
            "service_sid_restricted_in_token": True,
            "actual_scm_service_sid_type": sid_type,
            "actual_running_service_sid": running_service_sid,
            "worker_sid_expected_not_attested_by_this_function": worker_sid,
            "filesystem_owner_sid": owner,
            "privileged_os_writer_sids": list(privileged),
            "pinned_acl_policy_blob": EXPECTED_ACL_POLICY_BLOB,
            "service_account_exclusive": False,
            "restricted_service_sid_acl_scoped": True,
            "worker_token_attested_here": False,
            "physical_device_acceptance": False,
            "independent_reviewer_approval": False,
            "production_release_allowed": False,
            "live_execution_allowed": False,
        }
    except CIBoundaryDenied:
        raise
    except Exception as exc:
        raise CIBoundaryDenied("unverifiable CI service identity or directory ACL") from exc
