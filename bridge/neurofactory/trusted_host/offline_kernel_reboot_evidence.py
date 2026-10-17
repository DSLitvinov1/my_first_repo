"""TEST-ONLY evidence for a REAL Linux kernel reboot across a protected receipt.

Run as nf_effect UID only, after a harmless completed/UNKNOWN offline operation.
Never initiates a reboot or authorizes execution; before/after boot-id snapshots
live under receiver-only 0700 journal outside PostgreSQL.  No CLI-provided
boot-id, fake reboot flag, private key or external action is accepted.
A Docker restart, signer restart or PostgreSQL restart has the SAME Linux kernel
boot-id and MUST NOT pass the after check.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from offline_recipient_protected_journal import RecipientProtectedJournal, _fsync_dir

class KernelRebootEvidenceDenied(ValueError):
    pass

_SHA64=re.compile(r"[0-9a-f]{64}\Z")
_SHA40=re.compile(r"[0-9a-f]{40}\Z")
_UUID=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")

def _die(s):
    raise KernelRebootEvidenceDenied(s)

def _boot_id():
    # Fixed Linux kernel source. Never take this from a request, database or env.
    boot=Path("/proc/sys/kernel/random/boot_id").read_text("ascii").strip()
    if not _UUID.fullmatch(boot):
        _die("unavailable trusted Linux kernel boot identity")
    return boot

def _read_private(p,uid):
    if p.is_symlink() or not p.is_file():
        _die("protected witness or journal marker absent")
    stat0=p.lstat()
    if (not stat.S_ISREG(stat0.st_mode) or stat0.st_uid!=uid or
            stat0.st_mode & 0o077 or stat0.st_size>4096):
        _die("unprotected, oversize or substituted witness")
    return p.read_bytes()

def _marker(j,task_id):
    name="task-"+hashlib.sha256(task_id.encode("ascii")).hexdigest()+".json"
    raw=_read_private(j.dir/name,os.geteuid())
    try:
        status=json.loads(raw)["status"]
    except (KeyError,TypeError,UnicodeError,ValueError):
        _die("corrupt protected receipt")
    if status not in {"UNKNOWN_MANUAL_RECONCILIATION","COMPLETED_TEST_ONLY"}:
        _die("unexpected receipt state")
    return hashlib.sha256(raw).hexdigest(),status

def inspect_kernel_reboot(config_dir,task_id,trial_sha,core_sha,host_sha,*,stage):
    """PRE persists protected witness; POST requires a different actual boot_id.

    Success is only boot/storage evidence, NOT device identity, owner authority,
    remote server integrity, independent review or a release approval.
    """
    if (stage not in ("before","after") or
            os.name!="posix" or not hasattr(os,"geteuid") or os.geteuid()==0 or
            os.getenv("NF_RECEIVER_OS_FIXTURE_ONLY")!="1" or
            not isinstance(task_id,str) or not isinstance(trial_sha,str) or
            not _SHA64.fullmatch(trial_sha) or
            not isinstance(core_sha,str) or not _SHA40.fullmatch(core_sha) or
            not isinstance(host_sha,str) or not _SHA40.fullmatch(host_sha)):
        _die("Linux isolated pre-approved fixture scope only")
    j=RecipientProtectedJournal(config_dir)
    recorded=j.inspect(task_id)
    if recorded["state"] not in ("UNKNOWN_MANUAL_RECONCILIATION","COMPLETED_TEST_ONLY"):
        _die("cannot witness missing protected irreversible receipt")
    curr_digest,curr_status=_marker(j,task_id)
    witness=j.dir/("kernel-reboot-"+trial_sha+".json")
    with open(j.lock,"rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        try:
            boot=_boot_id()
            if stage=="before":
                record={"schema":"neurofactory.kernel_reboot_receipt.fixture.v1",
                        "task_id":task_id,"trial_sha256":trial_sha,
                        "core_sha40":core_sha,"host_sha40":host_sha,
                        "boot_id_before":boot,
                        "protected_receipt_sha256":curr_digest,
                        "protected_state":curr_status}
                payload=json.dumps(record,sort_keys=True,separators=(",",":")).encode("ascii")
                fd=os.open(witness,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                try:
                    with os.fdopen(fd,"wb") as stream:
                        stream.write(payload);stream.flush();os.fsync(stream.fileno())
                finally:
                    _fsync_dir(j.dir)
                return {"status":"BEFORE_REBOOT_SAVED_TEST_ONLY",
                        "boot_id_before":boot,
                        "boot_changed":False,"live_execution_allowed":False,
                        "release_approved":False}
            record=json.loads(_read_private(witness,os.geteuid()))
            if (type(record) is not dict or
                    set(record)!={"schema","task_id","trial_sha256","core_sha40",
                                 "host_sha40","boot_id_before","protected_receipt_sha256",
                                 "protected_state"} or
                    record["schema"]!="neurofactory.kernel_reboot_receipt.fixture.v1" or
                    record["task_id"]!=task_id or record["trial_sha256"]!=trial_sha or
                    record["core_sha40"]!=core_sha or record["host_sha40"]!=host_sha or
                    not isinstance(record["boot_id_before"],str) or
                    not _UUID.fullmatch(record["boot_id_before"]) or
                    record["boot_id_before"]==boot or
                    record["protected_receipt_sha256"]!=curr_digest or
                    record["protected_state"]!=curr_status):
                _die("no independently observable reboot or private ledger changed")
            return {"status":"KERNEL_BOOT_ID_CHANGED_LEDGER_UNCHANGED_TEST_ONLY",
                    "boot_id_before":record["boot_id_before"],"boot_id_after":boot,
                    "protected_state":curr_status,
                    "protected_receipt_sha256":curr_digest,
                    "physical_machine_distinctness_proven":False,
                    "independent_operator_identity_proven":False,
                    "live_execution_allowed":False,"release_approved":False}
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN)

def main(argv):
    if len(argv)!=7:
        _die("args: before|after recipient-config task-id trial-sha core-sha host-sha")
    result=inspect_kernel_reboot(argv[2],argv[3],argv[4],argv[5],argv[6],
                                 stage=argv[1])
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
    try:
        main(sys.argv)
    except Exception:
        print("KERNEL_REBOOT_WITNESS_DENIED_NO_RELEASE",file=sys.stderr)
        sys.exit(3)
