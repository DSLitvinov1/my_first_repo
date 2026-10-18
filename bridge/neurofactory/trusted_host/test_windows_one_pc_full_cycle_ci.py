"""Single-Windows-computer disposable integration trial (ONE OS, TWO identities).

Runs existing real SCM+CORE+restricted-Service-SID tests sequentially on the
SAME temporary GitHub-hosted Windows VM. Never runs on a user's PC.
This is not an owner installation, production witness or RELEASE approval.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import subprocess
import sys
import time

CI_SERVICE = "NeurofactorySandboxReceiverCI"
CI_ROOT_NAME = "NeurofactoryCIReceiver"
CI_WORKER_NAME = "NeurofactoryCIWorker"
MANDATORY_FLAGS = (
    "NF_WINDOWS_SCM_DISPOSABLE_ONLY",
    "NF_WINDOWS_CROSS_BRANCH_ACL_VERIFY",
    "NF_WINDOWS_REQUIRE_RESTRICTED_SERVICE_SID",
)


def _stop(message):
    raise RuntimeError("ONE_PC_LOCAL_PILOT_CI_DENIED: " + message)


def _verify_ci_scope():
    if os.name != "nt":
        _stop("Windows-only")
    if os.environ.get("GITHUB_ACTIONS") != "true" or \
       os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        _stop("not an ephemeral GitHub-hosted runner")
    if any(os.environ.get(flag) != "1" for flag in MANDATORY_FLAGS):
        _stop("mandatory disposable-only flags missing")
    if not os.environ.get("PROGRAMDATA"):
        _stop("Windows ProgramData unavailable")


def _service_absent():
    import win32service
    import pywintypes

    mgr = win32service.OpenSCManager(
        None, None, win32service.SC_MANAGER_CONNECT)
    try:
        try:
            svc = win32service.OpenService(
                mgr, CI_SERVICE, win32service.SERVICE_QUERY_STATUS)
        except pywintypes.error as exc:
            return exc.winerror == 1060  # ERROR_SERVICE_DOES_NOT_EXIST
        else:
            win32service.CloseServiceHandle(svc)
            return False
    finally:
        win32service.CloseServiceHandle(mgr)


def _assert_clean_before_next():
    """Wait for SCM DeleteService to finish, fail closed on residual state."""
    data = Path(os.environ["PROGRAMDATA"])
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        service_gone = _service_absent()
        folders_gone = not (data / CI_ROOT_NAME).exists() and \
                       not (data / CI_WORKER_NAME).exists()
        if service_gone and folders_gone:
            return
        time.sleep(0.3)
    _stop("previous CI service/user directories not fully removed")


def _machine_marker():
    # Local-only continuity observation; not signed remote attestation.
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\\Microsoft\\Cryptography") as key:
        guid = winreg.QueryValueEx(key, "MachineGuid")[0]
    if not isinstance(guid, str) or len(guid) < 16:
        _stop("no machine continuity marker")
    return (platform.node(), guid)


def _run_scenario(mode):
    test = Path(__file__).with_name("test_windows_scm_two_user_recovery.py")
    result = subprocess.run(
        [sys.executable, "-B", str(test), mode],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=220, check=False,
    )
    permitted = (
        "NF_WINDOWS_PER_SERVICE_RESTRICTED_TOKEN_AND_ACL=PASS_TEST_ONLY",
        "NF_WINDOWS_SHARED_LOCAL_SERVICE_WRITER=DENIED",
        "NF_WINDOWS_FOREIGN_WORKER_WRITE_ACE=DENIED",
        "NF_WINDOWS_REAL_DIFFERENT_SIDS_FORGED_SIGNATURE=DENIED",
        "NF_WINDOWS_REAL_SCM_DIFFERENT_ACCOUNT_ONE_FILE=PASS_TEST_ONLY",
        "NF_WINDOWS_DUPLICATE_REJECTED=PASS_TEST_ONLY",
        "NF_WINDOWS_SCM_CRASH_RESTART_NO_REPLAY=PASS_TEST_ONLY",
        "NF_WINDOWS_SCM_KILLED_AFTER_FSYNC_UNKNOWN_NO_FILE=PASS_TEST_ONLY",
        "NF_WINDOWS_SCM_RESTART_NO_RETRY_UNKNOWN=PASS_TEST_ONLY",
        "NF_WINDOWS_LIVE_QUEUE=OFF",
    )
    found = set(line.strip() for line in result.stdout.splitlines() if
                line.strip() in permitted)
    for item in sorted(found):
        print(item, flush=True)
    required = set(permitted[:4]) | {"NF_WINDOWS_LIVE_QUEUE=OFF"}
    required |= set(permitted[4:7] if mode == "normal" else permitted[7:9])
    if result.returncode or not required.issubset(found):
        # Never include the command/environment/key or any generated password
        # in diagnostics. Show only result category.
        _stop("scenario " + mode + " failed: exit=" +
              str(result.returncode) + ", expected-markers-missing=" +
              str(len(required - found)))


def main():
    _verify_ci_scope()
    machine = _machine_marker()
    _assert_clean_before_next()
    _run_scenario("normal")
    _assert_clean_before_next()
    if _machine_marker() != machine:
        _stop("OS identity changed within single runner")
    _run_scenario("crash-window")
    _assert_clean_before_next()
    if _machine_marker() != machine:
        _stop("OS identity changed within single runner")
    print("NF_ONE_WINDOWS_PC_NORMAL_AND_CRASH_SEQUENTIAL=PASS_TEST_ONLY")
    print("NF_ONE_WINDOWS_PC_SAME_HOST_OBSERVED=PASS_TEST_ONLY")
    print("NF_ONE_WINDOWS_PC_SECOND_PHYSICAL_DEVICE_REQUIRED=FALSE_FOR_PILOT")
    print("NF_ONE_WINDOWS_PC_PRODUCTION_RELEASE_ALLOWED=FALSE")
    print("NF_ONE_WINDOWS_PC_INDEPENDENT_EXTERNAL_WITNESS_ESTABLISHED=FALSE")
    print("NF_ONE_WINDOWS_PC_INDEPENDENT_REVIEW_COMPLETE=FALSE")


if __name__ == "__main__":
    main()
