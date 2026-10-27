"""Ephemeral Windows-2025 GH admin CI: separate actual LocalService + local worker.

Installs/removes an SCM service ONLY on disposable hosted GitHub machine.
Does not install on owner's machine. No production GitHub token or keys.
Private owner key lives only in test orchestrator memory, not in worker or
receiver. CORE imported from immutable separate pinned checkout.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import win32api
import win32con
import win32security

from windows_named_pipe_pilot_receiver import canon
from windows_scm_sandbox_receiver import CI_ROOT,CI_CONFIG,CI_PIPE,SERVICE_NAME
from windows_named_pipe_pilot_receiver import _ALLOWED_TARGET

REPO = Path(__file__).resolve().parents[3]
CORE = REPO/".nf_pinned_core"/"bridge"/"neurofactory"/"development"/"core_owned"
sys.path.insert(0,str(CORE))
from one_task_core import OneTaskCore,EMPTY_SHA

def call(args, *, required=True, env=None,timeout=35):
    p=subprocess.run(args,text=True,capture_output=True,env=env,timeout=timeout)
    if required and p.returncode:
        # Redacted stderr is safe; argument list might contain ephemeral passwd.
        raise RuntimeError("CI command failed exit "+str(p.returncode)+
                           " stdout="+p.stdout[-550:]+" stderr="+p.stderr[-550:])
    return p

def icacls(path,sid,level="M"):
    p=str(path)
    call(["icacls",p,"/inheritance:r"])
    call(["icacls",p,"/grant:r",
          "*S-1-5-18:(OI)(CI)F",
          "*S-1-5-32-544:(OI)(CI)F",
          "*"+sid+":(OI)(CI)"+level])

def ensure_no_unauthorised_client(root):
    from pathlib import Path
    receipt=root/"one_effect_unknown.json"
    dest=root/"windows_pilot.txt"
    if receipt.is_symlink() or dest.is_symlink():
        raise AssertionError("symlink")
    if receipt.exists():
        assert json.loads(receipt.read_text())["state"]=="UNKNOWN_NO_AUTO_RETRY"
    return receipt.exists(),dest.exists()

def prepare_core_fixture(tmp, owner_key):
    repo=tmp/"git"
    repo.mkdir()
    call(["git","-C",str(repo),"init","-q"])
    call(["git","-C",str(repo),"config","user.name","CI only"])
    call(["git","-C",str(repo),"config","user.email","ci@example.invalid"])
    (repo/"README.md").write_text("temporary fixture\n",encoding="utf8")
    call(["git","-C",str(repo),"add","README.md"])
    call(["git","-C",str(repo),"commit","-qm","synthetic source"])
    sha=call(["git","-C",str(repo),"rev-parse","HEAD"]).stdout.strip()
    work=tmp/"core"
    work.mkdir()
    core=OneTaskCore(work,repo)
    spec={
      "schema":"neurofactory.core.task.v1","task_id":"NF-DEV-05-Q901",
      "project_id":"core-test","target":_ALLOWED_TARGET,
      "objective":"Write one inert test file from separate receiver service only.",
      "source_sha":sha,"source_sha256":EMPTY_SHA,
      "approval_commit":sha,"model":"qwen2.5-coder:1.5b",
      "reserved_units":10
    }
    core.enqueue(spec,trusted_approval_check=lambda s:s==spec)
    claim=core.claim("worker-one",now=int(time.time()),lease_seconds=180)
    # NOTE: in production the owner key must NOT be in CORE or CI code.
    # Here the test operator signs externally to the future low-priv worker.
    snapshot=core.snapshot()
    assert snapshot["state"]=="CLAIMED"
    text="NEUROFACTORY_WINDOWS_SCM_TWO_REAL_SIDS_ONE_SAFE_FILE\n"
    content=text.encode("utf8")
    body={
      "schema":"neurofactory.windows.single_file_pilot.v1",
      "task_id":spec["task_id"],"project_id":spec["project_id"],
      "source_sha40":spec["source_sha"],
      "operation_id":"pilot-"+spec["task_id"],
      "target":spec["target"],
      "content_base64":base64.b64encode(content).decode("ascii"),
      "content_sha256":hashlib.sha256(content).hexdigest(),
    }
    sig=owner_key.sign(b"NF_WINDOWS_PILOT_V1\x00"+canon(body))
    packet={**body,"approved_owner_signature":base64.b64encode(sig).decode("ascii")}
    return core,spec,claim,packet,text

def worker_as_local_account(username,password,script,payload,response):
    """Launch with a real different local Windows token, not runas/net-only.

    CreateProcessWithLogonW creates the new locally authenticated token;
    its NULL environment chooses the user's own clean environment, never
    inherits runner credentials or test signing key.
    """
    import ctypes
    import ctypes.wintypes as w
    from ctypes import byref

    class STARTUPINFOW(ctypes.Structure):
        _fields_=[("cb",w.DWORD),("lpReserved",w.LPWSTR),
                  ("lpDesktop",w.LPWSTR),("lpTitle",w.LPWSTR),
                  ("dwX",w.DWORD),("dwY",w.DWORD),
                  ("dwXSize",w.DWORD),("dwYSize",w.DWORD),
                  ("dwXCountChars",w.DWORD),("dwYCountChars",w.DWORD),
                  ("dwFillAttribute",w.DWORD),("dwFlags",w.DWORD),
                  ("wShowWindow",w.WORD),("cbReserved2",w.WORD),
                  ("lpReserved2",ctypes.c_void_p),
                  ("hStdInput",w.HANDLE),("hStdOutput",w.HANDLE),
                  ("hStdError",w.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_=[("hProcess",w.HANDLE),("hThread",w.HANDLE),
                  ("dwProcessId",w.DWORD),("dwThreadId",w.DWORD)]

    api=ctypes.WinDLL("advapi32",use_last_error=True)
    fn=api.CreateProcessWithLogonW
    fn.argtypes=(w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,w.DWORD,
                 w.LPCWSTR,w.LPWSTR,w.DWORD,ctypes.c_void_p,
                 w.LPCWSTR,ctypes.POINTER(STARTUPINFOW),
                 ctypes.POINTER(PROCESS_INFORMATION))
    fn.restype=w.BOOL
    si=STARTUPINFOW()
    si.cb=ctypes.sizeof(si)
    pi=PROCESS_INFORMATION()
    cmd=' "'+str(script)+'" "'+str(payload)+'" "'+str(response)+'" "'+CI_PIPE+'"'
    command=ctypes.create_unicode_buffer('"'+sys.executable+'"'+cmd)
    ok=fn(username,".",password,0,sys.executable,command,
          0x08000000,None,str(script.parent),byref(si),byref(pi))
    if not ok:
        raise RuntimeError("CreateProcessWithLogonW refused distinct worker error "+
                           str(ctypes.get_last_error()))
    kernel=ctypes.WinDLL("kernel32",use_last_error=True)
    kernel.WaitForSingleObject.argtypes=(w.HANDLE,w.DWORD)
    kernel.WaitForSingleObject.restype=w.DWORD
    kernel.CloseHandle.argtypes=(w.HANDLE,)
    kernel.CloseHandle.restype=w.BOOL
    try:
        waited=kernel.WaitForSingleObject(pi.hProcess,10000)
        if waited != 0:
            raise RuntimeError("different-SID worker did not finish: "+str(waited))
    finally:
        kernel.CloseHandle(pi.hThread)
        kernel.CloseHandle(pi.hProcess)
    if not response.is_file():
        raise RuntimeError("worker created no report")
    return json.loads(response.read_text(encoding="ascii"))

def wait_service(expected,timeout=20):
    import win32service
    import win32serviceutil
    limit=time.monotonic()+timeout
    while time.monotonic()<limit:
        try:
            state=win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
            if state==expected:
                return
        except Exception:
            pass
        time.sleep(.2)
    raise RuntimeError("SCM did not reach status "+str(expected))

def main():
    if os.name!="nt" or os.getenv("GITHUB_ACTIONS")!="true" or \
           os.getenv("RUNNER_ENVIRONMENT")!="github-hosted" or \
           os.getenv("NF_WINDOWS_SCM_DISPOSABLE_ONLY")!="1":
        raise RuntimeError("RUN only on disposable GitHub-hosted Windows fixture")
    import win32service
    import win32serviceutil
    from win32service import SERVICE_RUNNING,SERVICE_STOPPED
    if CI_ROOT.exists():
        raise RuntimeError("existing test service root; refuse reuse")
    mode=sys.argv[1] if len(sys.argv)==2 else "normal"
    resident = (os.getenv("NF_ONEPC_RESIDENT_QWEN_JOURNAL_CI") == "1")
    if resident and (mode != "normal" or os.getenv("NF_ONEPC_FINAL_SIGNED_CI") != "1"):
        raise RuntimeError("Resident SCM receipt audit only in genuine signed one-run hosted CI")
    if mode not in ("normal","crash-window"):
        raise RuntimeError("only two isolated CI modes accepted")
    username="nfci"+secrets.token_hex(3)
    password="T7-"+secrets.token_urlsafe(18)+"-Q!"
    user_created=False
    service_created=False
    root=CI_ROOT
    worker_root=Path(os.environ["PROGRAMDATA"])/"NeurofactoryCIWorker"
    temp=None
    try:
        call(["net","user",username,password,"/add","/Y"])
        user_created=True
        sid=win32security.LookupAccountName(None,username)[0]
        worker_sid=win32security.ConvertSidToStringSid(sid)
        service_sid="S-1-5-19"
        assert worker_sid!=service_sid
        root.mkdir(parents=True)
        output=root/"protected_output";output.mkdir()
        binfolder=root/"receiver_bin";binfolder.mkdir()
        worker_root.mkdir()
        icacls(root,service_sid,"RX")
        icacls(output,service_sid,"M")
        # Windows CI fixture only: make the directory owner a known OS
        # administrator, not an untrusted worker or ambiguous personal SID.
        # This does NOT authorize real service deployment or change user's PC.
        if os.getenv("NF_WINDOWS_CROSS_BRANCH_ACL_VERIFY") == "1":
            call(["icacls",str(output),"/setowner","*S-1-5-32-544"])
        icacls(binfolder,service_sid,"RX")
        icacls(worker_root,worker_sid,"M")
        # Admin provisions pin and never exposes owner PRIVATE to receiver.
        owner=Ed25519PrivateKey.generate()
        pub=owner.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        host_receipt_signer=Ed25519PrivateKey.generate()
        host_public_raw=host_receipt_signer.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        host_private_raw=host_receipt_signer.private_bytes(
            serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        CI_CONFIG.write_text(json.dumps({
            "schema":"neurofactory.windows.ci_service.v1",
            "worker_sid":worker_sid,
            "owner_public_raw_base64":base64.b64encode(pub).decode("ascii"),
            "host_receipt_private_raw_base64":
                base64.b64encode(host_private_raw).decode("ascii"),
        }),encoding="ascii")
        # Discard the operator-side test signer handle: actual signing only
        # occurs within restricted SCM process, never within worker/CORE.
        host_receipt_signer=None
        host_private_raw=None
        # root ACL should cascade, but explicitly protect config.
        call(["icacls",str(CI_CONFIG),"/inheritance:r",
              "/grant:r","*S-1-5-18:F","*S-1-5-32-544:F"])
        source_dir=Path(__file__).parent
        for name in ("windows_scm_sandbox_receiver.py",
                     "windows_named_pipe_pilot_receiver.py"):
            shutil.copy2(source_dir/name,binfolder/name)
        shutil.copy2(source_dir/"windows_scm_ci_worker.py",
                     worker_root/"windows_scm_ci_worker.py")
        shutil.copy2(source_dir/"windows_named_pipe_pilot_receiver.py",
                     worker_root/"windows_named_pipe_pilot_receiver.py")
        temp=tempfile.TemporaryDirectory()
        core,spec,claim,packet,expected=prepare_core_fixture(Path(temp.name),owner)
        owner=None # Never hand private signer handle to worker/service.
        handoff=worker_root/"handoff.json"
        handoff.write_text(json.dumps(packet,sort_keys=True),encoding="ascii")
        call(["icacls",str(handoff),"/inheritance:r",
              "/grant:r","*"+worker_sid+":R","*S-1-5-18:F",
              "*S-1-5-32-544:F"])
        servicepy=binfolder/"windows_scm_sandbox_receiver.py"
        cmdline='"'+sys.executable+'" -u "'+str(servicepy)+'" --scm'
        call(["sc.exe","create",SERVICE_NAME,"binPath=",cmdline,
              "obj=","NT AUTHORITY\\LocalService","start=","demand"])
        service_created=True
        # CI-ONLY; SCM injects a per-service SID into the actual LocalService
        # process token. A restricted SID additionally limits write authority.
        # Never configure or install any service on a user's machine.
        if os.getenv("NF_WINDOWS_REQUIRE_RESTRICTED_SERVICE_SID") != "1":
            raise RuntimeError("restricted per-service SID gate is mandatory in this branch")
        call(["sc.exe","sidtype",SERVICE_NAME,"restricted"])
        if resident:
            # Hosted-only: this actual SCM receiver now survives unattended
            # service process crashes using Windows recovery, not a manual
            # new sc start. This is still a test-only single-file pilot.
            call(["sc.exe","config",SERVICE_NAME,"start=","delayed-auto"])
            call(["sc.exe","failure",SERVICE_NAME,"reset=","3600",
                  "actions=","restart/6000/restart/15000/none/0"])
            call(["sc.exe","failureflag",SERVICE_NAME,"1"])
            scpolicy=call(["sc.exe","qfailure",SERVICE_NAME]).stdout
            if "RESTART" not in scpolicy or "6000" not in scpolicy:
                raise RuntimeError("Actual Windows SCM unattended recovery not configured")
            print("NF_RESIDENT_GENUINE_QWEN_SCM_DELAYED_AUTO_RECOVERY=CONFIGURED_CI_ONLY")
        explicit_service_sid=win32security.ConvertSidToStringSid(
            win32security.LookupAccountName(
                None,"NT SERVICE\\"+SERVICE_NAME)[0])
        if not explicit_service_sid.startswith("S-1-5-80-"):
            raise AssertionError("SCM did not allocate expected per-service SID")
        # Private HOST signer is readable only by this specific restricted
        # service SID, SYSTEM and Administrators. Shared LocalService DENIED.
        call(["icacls",str(CI_CONFIG),"/grant:r",
              "*"+explicit_service_sid+":R",
              "*S-1-5-18:F","*S-1-5-32-544:F"])
        # A shared LocalService logon SID MUST NOT be granted write access
        # to this receiver-owned directory; grant only its distinct service
        # SID (+ original SYSTEM/Administrators). Inspect this actual ACL.
        call(["icacls",str(output),"/grant:r",
              "*"+explicit_service_sid+":(OI)(CI)M"])
        call(["icacls",str(output),"/remove:g","*S-1-5-19"])
        call(["sc.exe","start",SERVICE_NAME],timeout=22)
        wait_service(SERVICE_RUNNING)
        # Actual least-privilege service account is NT AUTHORITY\LocalService.
        svc=call(["sc.exe","qc",SERVICE_NAME]).stdout
        if "LocalService" not in svc:
            raise AssertionError("SCM service not LocalService")
        # Verify the ACTUAL running SCM process token via Windows WMI,
        # not just the configured service StartName string.
        process_owner=call([
            "powershell.exe","-NoProfile","-NonInteractive","-Command",
            (
                "$svc=Get-CimInstance Win32_Service -Filter "
                "\"Name='"+SERVICE_NAME+"'\"; "
                "$proc=Get-CimInstance Win32_Process -Filter "
                "(\"ProcessId=\"+$svc.ProcessId); "
                "($proc | Invoke-CimMethod -MethodName GetOwner).User"
            )
        ]).stdout.strip()
        if "LOCAL SERVICE" not in process_owner.upper():
            raise AssertionError("actual SCM process token is not LocalService")
        if os.getenv("NF_WINDOWS_CROSS_BRANCH_ACL_VERIFY") == "1":
            from windows_scm_acl_crosscheck_ci import (
                inspect_disposable_ci_service, CIBoundaryDenied,
            )
            policy = (
                REPO/".nf_pinned_acl"/"bridge"/"neurofactory"/"trusted_host"/
                "windows_service_sid_acl_audit.py"
            )
            # Positive: this inspects a REAL SCM process token and actual
            # provisioned NTFS DACL, unlike synthetic pure-policy fixtures.
            observed=inspect_disposable_ci_service(output,worker_sid,policy)
            assert observed["actual_running_service_sid"]=="S-1-5-19"
            assert observed["restricted_service_sid"]==explicit_service_sid
            assert observed["service_sid_enabled_in_token"] is True
            assert observed["service_sid_restricted_in_token"] is True
            assert observed["restricted_service_sid_acl_scoped"] is True
            print("NF_WINDOWS_PER_SERVICE_RESTRICTED_TOKEN_AND_ACL=PASS_TEST_ONLY")
            assert observed["production_release_allowed"] is False
            assert observed["service_account_exclusive"] is False
            print("NF_WINDOWS_CI_LOCAL_SERVICE_ACTUAL_TOKEN_AND_ACL_OBSERVED")
            # Negative: if a different service shares LocalService, a
            # direct grant to that shared logon SID must be disallowed.
            try:
                call(["icacls",str(output),"/grant",
                      "*S-1-5-19:(OI)(CI)M"])
                try:
                    inspect_disposable_ci_service(output,worker_sid,policy)
                except CIBoundaryDenied:
                    print("NF_WINDOWS_SHARED_LOCAL_SERVICE_WRITER=DENIED")
                else:
                    raise AssertionError("LocalService shared writer accepted")
            finally:
                call(["icacls",str(output),"/remove:g","*S-1-5-19"])
            # Negative: grant the REAL worker directory write access and prove
            # the inspector immediately denies it; restore BEFORE workers run.
            try:
                call(["icacls",str(output),"/grant",
                      "*"+worker_sid+":(OI)(CI)M"])
                try:
                    inspect_disposable_ci_service(output,worker_sid,policy)
                except CIBoundaryDenied:
                    print("NF_WINDOWS_FOREIGN_WORKER_WRITE_ACE=DENIED")
                else:
                    raise AssertionError("untrusted worker ACL grant accepted")
            finally:
                call(["icacls",str(output),"/remove:g","*"+worker_sid])
            restored=inspect_disposable_ci_service(output,worker_sid,policy)
            assert restored["production_release_allowed"] is False
            print("NF_WINDOWS_LOCAL_SERVICE_BUT_NOT_EXCLUSIVE=RELEASE_BLOCKED")
        # A synthetic FORGED signature must be rejected even though the
        # worker SID and pipe ACL are valid; no file has been created.
        forged=dict(packet)
        forged["approved_owner_signature"]=base64.b64encode(
            b"not real owner signature".ljust(64,b"\0")).decode("ascii")
        handoff.write_text(json.dumps(forged),encoding="ascii")
        response=worker_root/"negative.json"
        denied=worker_as_local_account(username,password,
            worker_root/"windows_scm_ci_worker.py",handoff,response)
        assert denied["status"] in (
            "WORKER_STOPPED_OR_SERVER_DENIED","DENIED_OR_UNKNOWN_MANUAL_STOP")
        assert denied["worker_sid_observed"]==worker_sid
        assert denied["protected_directory_read_denied"] is True
        assert denied["protected_directory_write_denied"] is True
        assert ensure_no_unauthorised_client(output)==(False,False)
        print("NF_WINDOWS_REAL_DIFFERENT_SIDS_FORGED_SIGNATURE=DENIED")
        # For crash-window test, create a root-owned operator-controlled
        # failpoint. The receiver will os._exit right AFTER fsync UNKNOWN
        # and BEFORE CREATE_NEW. No worker can select this condition.
        if mode=="crash-window":
            flag=root/"operator_ci_crash_after_unknown"
            flag.write_text("CI_ONLY_CRASH_AFTER_DURABLE_UNKNOWN",encoding="ascii")
            call(["icacls",str(flag),"/inheritance:r",
                  "/grant:r","*S-1-5-19:R","*S-1-5-18:F",
                  "*S-1-5-32-544:F"])
            handoff.write_text(json.dumps(packet,sort_keys=True),encoding="ascii")
            crashed=worker_as_local_account(username,password,
                worker_root/"windows_scm_ci_worker.py",handoff,
                worker_root/"crash_before_file.json")
            assert crashed["worker_sid_observed"]==worker_sid
            assert crashed["protected_directory_read_denied"] is True
            assert crashed["protected_directory_write_denied"] is True
            assert crashed["status"]=="WORKER_STOPPED_OR_SERVER_DENIED",crashed
            wait_service(SERVICE_STOPPED)
            assert ensure_no_unauthorised_client(output)==(True,False)
            # The root-owned crash flag was not included in either owner
            # signed packet nor CORE lease, and can only be removed by
            # fixture administrator before a new SCM process starts.
            flag.unlink()
            call(["sc.exe","start",SERVICE_NAME],timeout=22)
            wait_service(SERVICE_RUNNING)
            again=worker_as_local_account(username,password,
                worker_root/"windows_scm_ci_worker.py",handoff,
                worker_root/"after_unknown_restart.json")
            assert again["worker_sid_observed"]==worker_sid
            assert again["status"] in ("DENIED_OR_UNKNOWN_MANUAL_STOP",
                                       "WORKER_STOPPED_OR_SERVER_DENIED"),again
            assert ensure_no_unauthorised_client(output)==(True,False)
            assert not (core.sandbox/_ALLOWED_TARGET).exists()
            print("NF_WINDOWS_SCM_KILLED_AFTER_FSYNC_UNKNOWN_NO_FILE=PASS_TEST_ONLY")
            print("NF_WINDOWS_SCM_RESTART_NO_RETRY_UNKNOWN=PASS_TEST_ONLY")
            print("NF_WINDOWS_WORKER_SID_AND_PROTECTED_FOLDER_DENIAL=PASS")
            print("NF_WINDOWS_LIVE_QUEUE=OFF")
            return
        # Send properly owner-signed exact immutable CORE task.
        resident_journal=None
        resident_expected_head=None
        handoff.write_text(json.dumps(packet,sort_keys=True),encoding="ascii")
        response=worker_root/"accepted.json"
        accepted=worker_as_local_account(username,password,
            worker_root/"windows_scm_ci_worker.py",handoff,response)
        assert accepted["status"]=="ONE_INERT_WINDOWS_FILE_TEST_ONLY",accepted
        assert accepted["worker_sid_observed"]==worker_sid
        assert accepted["protected_directory_read_denied"] is True
        assert accepted["protected_directory_write_denied"] is True
        assert accepted["content_sha256"]==packet["content_sha256"]
        assert accepted["live_execution_allowed"] is False
        assert ensure_no_unauthorised_client(output)==(True,True)
        target=output/"windows_pilot.txt"
        assert target.read_text(encoding="utf8")==expected
        assert core.snapshot()["state"]=="CLAIMED"
        if os.getenv("NF_ONEPC_FINAL_SIGNED_CI") == "1":
            # Staged integration uses real CORE SQLite from the trusted source,
            # but loads new completion logic ONLY from this integration branch.
            import importlib.util
            integrated=REPO/"bridge"/"neurofactory"/"development"/"core_owned"/"one_task_core.py"
            loader=importlib.util.spec_from_file_location(
                "nf_onepc_integrated_core",integrated)
            if loader is None or loader.loader is None:
                raise AssertionError("integration-owned finalizer unavailable")
            module=importlib.util.module_from_spec(loader)
            loader.loader.exec_module(module)
            operator_pinned_core=module.OneTaskCore(
                core.root,core.repo,host_output_dir=output,
                host_receipt_public_raw=host_public_raw)
            receipt=accepted.get("host_signed_receipt")
            if not isinstance(receipt,dict):
                raise AssertionError("SCM did not sign actual protected effect")
            status=operator_pinned_core.finalize_signed_host_test(
                spec["task_id"],claim["token"],receipt)
            assert status["state"]=="HOST_CHECKPOINTED_TEST"
            assert status["result_sha256"]==packet["content_sha256"]
            restarted=module.OneTaskCore(
                core.root,core.repo,host_output_dir=output,
                host_receipt_public_raw=host_public_raw)
            assert restarted.snapshot()["state"]=="HOST_CHECKPOINTED_TEST"
            try:
                restarted.finalize_signed_host_test(spec["task_id"],claim["token"],receipt)
            except module.CoreSafetyError:
                pass
            else:
                raise AssertionError("HOST receipt was replayed")
            print("NF_ONEPC_REAL_SCM_SIGNED_HOST_RECEIPT=VERIFIED_TEST_ONLY")
            print("NF_ONEPC_CORE_SQLITE_HOST_COMPLETION=HOST_CHECKPOINTED_TEST")
            print("NF_ONEPC_CORE_RESTART_AND_RECEIPT_REPLAY=PASS_TEST_ONLY")
            if resident:
                from resident_host_audit_journal import (
                    append_after_core_checkpoint,inspect,LocalAuditDenied,
                )
                proposal_sha=os.getenv("NF_REAL_QWEN_PROPOSAL_SHA256")
                if not isinstance(proposal_sha,str) or len(proposal_sha)!=64:
                    raise AssertionError("Real Qwen model digest not bound to local journal")
                receipt_digest=hashlib.sha256(json.dumps(
                    receipt,sort_keys=True,separators=(",",":"),
                    ensure_ascii=True,allow_nan=False).encode("ascii")).hexdigest()
                # Operator's local journal is separate from actual HOST and
                # from model workspace, and is updated only AFTER CORE has
                # validated the restricted-SCM-signed receipt in SQLite.
                resident_journal=Path(temp.name)/"resident-host-audit.sqlite3"
                audit_event={
                    "schema":"nf.onepc.local_host_checkpoint.v1",
                    "task_id":spec["task_id"],
                    "source_sha40":spec["source_sha"],
                    "proposal_sha256":proposal_sha,
                    "result_sha256":packet["content_sha256"],
                    "receipt_sha256":receipt_digest,
                    "operation_id":"pilot-"+spec["task_id"],
                    "checkpoint_state":status["state"],
                }
                first=append_after_core_checkpoint(
                    resident_journal,audit_event,actual_core_state=status["state"])
                resident_expected_head=first["head_sha256"]
                if first["entries"]!=1 or first["external_highwater_attested"] is not False:
                    raise AssertionError("Local journal falsely claims external antirollback")
                try:
                    append_after_core_checkpoint(resident_journal,audit_event,
                                                 actual_core_state=status["state"])
                except LocalAuditDenied:
                    pass
                else:
                    raise AssertionError("Same real SCM receipt was journaled twice")
                print("NF_REAL_QWEN_TO_SCM_SIGNED_CORE_CHECKPOINT_TO_SQLITE_JOURNAL=PASS_CI_ONLY")
        assert not (core.sandbox/_ALLOWED_TARGET).exists()
        print("NF_WINDOWS_REAL_SCM_DIFFERENT_ACCOUNT_ONE_FILE=PASS_TEST_ONLY")
        # Ordinary replay must not overwrite/duplicate protected result.
        response=worker_root/"replay.json"
        replay=worker_as_local_account(username,password,
            worker_root/"windows_scm_ci_worker.py",handoff,response)
        assert replay["status"] in (
            "DENIED_OR_UNKNOWN_MANUAL_STOP","WORKER_STOPPED_OR_SERVER_DENIED")
        assert target.read_text(encoding="utf8")==expected
        assert len(list(output.iterdir()))==2
        print("NF_WINDOWS_DUPLICATE_REJECTED=PASS_TEST_ONLY")
        # Actually kill the Windows SERVICE process, not only test Python.
        import win32service
        from win32service import SERVICE_STOPPED
        pid=win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        svc_pid=call(["powershell.exe","-NoProfile","-NonInteractive",
            "-Command","(Get-CimInstance Win32_Service -Filter \"Name='"+SERVICE_NAME+
            "'\").ProcessId"]).stdout.strip()
        if not svc_pid.isdigit() or int(svc_pid)<100:
            raise AssertionError("Windows SCM process PID not identified")
        call(["taskkill","/PID",svc_pid,"/F"])
        if resident:
            # No caller-initiated service start; Windows SCM must do this.
            # Fresh PROCESS PID is essential: mere stored recovery policy
            # does not prove successful unattended restart.
            cutoff=time.monotonic()+42
            recovered=False
            while time.monotonic()<cutoff:
                observation=call([
                    "powershell.exe","-NoProfile","-NonInteractive",
                    "-Command","$p=Get-CimInstance Win32_Service -Filter "
                    "\"Name='"+SERVICE_NAME+"'\"; "
                    "Write-Output ($p.State+':'+$p.ProcessId)",
                ],timeout=15).stdout.strip()
                if observation=="Running:"+svc_pid:
                    raise AssertionError("SCM reported old crashed process PID")
                if observation.startswith("Running:") and observation.split(":")[-1].isdigit():
                    newpid=int(observation.split(":")[-1])
                    if newpid>0 and newpid!=int(svc_pid):
                        recovered=True
                        break
                time.sleep(.4)
            if not recovered:
                raise AssertionError("Windows SCM failed unattended recovery with a new PID")
            print("NF_REAL_QWEN_PROTECTED_SCM_AUTOMATIC_NEW_PROCESS_AFTER_CRASH=PASS_CI_ONLY")
        else:
            wait_service(SERVICE_STOPPED)
            call(["sc.exe","start",SERVICE_NAME],timeout=22)
            wait_service(SERVICE_RUNNING)
        response=worker_root/"after_crash.json"
        post=worker_as_local_account(username,password,
            worker_root/"windows_scm_ci_worker.py",handoff,response)
        assert post["status"] in (
            "DENIED_OR_UNKNOWN_MANUAL_STOP","WORKER_STOPPED_OR_SERVER_DENIED")
        assert len(list(output.iterdir()))==2
        assert target.read_text(encoding="utf8")==expected
        print("NF_WINDOWS_SCM_CRASH_RESTART_NO_REPLAY=PASS_TEST_ONLY")
        if resident:
            if resident_journal is None or resident_expected_head is None:
                raise AssertionError("Required CORE-signed journal absent after restart")
            journal_report=inspect(resident_journal)
            if journal_report["entries"]!=1 or journal_report["head_sha256"]!=resident_expected_head:
                raise AssertionError("Protected Windows crash/recovery changed signed audit history")
            persisted=module.OneTaskCore(
                core.root,core.repo,host_output_dir=output,
                host_receipt_public_raw=host_public_raw)
            if persisted.snapshot()["state"]!="HOST_CHECKPOINTED_TEST" or (
                persisted.snapshot()["result_sha256"]!=packet["content_sha256"]):
                raise AssertionError("Real CORE durable checkpoint lost after auto SCM recovery")
            print("NF_QWEN_CORE_RESTRICTED_RESIDENT_SCM_RESULT_AND_PERSISTENT_JOURNAL=PASS_CI_ONLY")
            print("NF_REAL_PRODUCTION_OWNER_MACHINE_INSTALL=FALSE")
            print("NF_EXTERNAL_MONOTONIC_WITNESS=NOT_CONFIGURED")
        print("NF_WINDOWS_TWO_DIFFERENT_ACCOUNTS_AND_CLAIM=PASS_TEST_ONLY")
        print("NF_WINDOWS_WORKER_SID_AND_PROTECTED_FOLDER_DENIAL=PASS")
        print("NF_WINDOWS_LIVE_QUEUE=OFF")
    finally:
        if service_created:
            call(["sc.exe","stop",SERVICE_NAME],required=False,timeout=10)
            call(["sc.exe","delete",SERVICE_NAME],required=False,timeout=10)
        if user_created:
            call(["net","user",username,"/delete"],required=False,timeout=10)
        if temp is not None:
            temp.cleanup()
        # No cleanup outside ephemeral CI; directory is protected and
        # runner gets destroyed. Explicitly remove if possible.
        shutil.rmtree(worker_root,ignore_errors=True)
        shutil.rmtree(root,ignore_errors=True)

if __name__=="__main__":
    main()
