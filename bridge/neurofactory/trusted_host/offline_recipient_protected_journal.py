"""Non-live OS-recipient-owned irreversible-effect barrier.

A durable receipt lives OUTSIDE postgres and outside worker permissions, under
nf_effect UID 0700. The protected UNKNOWN intent is fsynced BEFORE any effect,
including across receiver restart and arbitrary PG journal rollback. Both the
task identity and target name are consumed atomically under recipient UID flock.
Never grants permission; actual HOST signed/lease checks remain mandatory.
"""
from __future__ import annotations
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

class ProtectedEffectDenied(ValueError):pass
_SHA64=re.compile(r"[0-9a-f]{64}\Z")
_TASK=re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_PREFIX="bridge/neurofactory/development/core_owned/"
_O_NOFOLLOW=getattr(os,"O_NOFOLLOW",0)
_ROOT_DIR="nf-protected-effect-journal"

def _denied(reason):raise ProtectedEffectDenied(reason)
def _fsync_dir(root):
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|_O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def _write_exclusive(directory, name, payload):
    fd=os.open(directory/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|_O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as f:
            f.write(payload);f.flush();os.fsync(fd)
    finally:os.close(fd)
    _fsync_dir(directory)
def _private_dir(directory, label):
    p=Path(directory)
    if p.is_symlink() or not p.is_dir():_denied(label+" missing")
    st=p.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077):
        _denied(label+" not protected from DB/worker UID")
    return p
def _exact_claim(task_id, operation_id, target, content_sha256):
    if (type(task_id) is not str or not _TASK.fullmatch(task_id) or
        type(operation_id) is not str or not 1<=len(operation_id)<=128 or
        any(ord(c)<33 or ord(c)>126 for c in operation_id) or
        type(target) is not str or not target.startswith(_PREFIX) or
        not target.endswith((".txt",".py",".md",".json")) or
        ".." in target.split("/") or
        type(content_sha256) is not str or not _SHA64.fullmatch(content_sha256)):
        _denied("untrusted operation identity")
    return {"task_id":task_id,"operation_id":operation_id,
            "target":target,"content_sha256":content_sha256}

class RecipientProtectedJournal:
    def __init__(self, receiver_config_dir):
        if (os.name!="posix" or os.getenv("NF_RECEIVER_OS_FIXTURE_ONLY")!="1" or
            not hasattr(os,"geteuid") or os.geteuid()==0):
            _denied("OS protected journal requires unprivileged explicit CI fixture UID")
        self.config=_private_dir(receiver_config_dir,"recipient owner config")
        if self.config.name!="nf-recipient-config":_denied("unexpected trusted config location")
        self.dir=self.config/_ROOT_DIR
        try:self.dir.mkdir(mode=0o700)
        except FileExistsError:pass
        _private_dir(self.dir,"recipient independent highwater")
        self.lock=self.dir/"receiver.lock"

    @contextmanager
    def intent_once(self, *, task_id, operation_id, target, content_sha256):
        claim=_exact_claim(task_id,operation_id,target,content_sha256)
        lockfd=os.open(self.lock,os.O_RDWR|os.O_CREAT|_O_NOFOLLOW,0o600)
        try:
            st=os.fstat(lockfd)
            if st.st_uid!=os.geteuid() or st.st_mode&0o077 or not stat.S_ISREG(st.st_mode):
                _denied("receipt lock substituted")
            fcntl.flock(lockfd,fcntl.LOCK_EX)
            # Separate task and target markers: changing operation UUID or
            # rolling back the DB cannot permit another effect at same place.
            task_marker=self.dir/("task-"+hashlib.sha256(task_id.encode()).hexdigest()+".json")
            target_marker=self.dir/("target-"+hashlib.sha256(target.encode()).hexdigest()+".json")
            if task_marker.exists() or target_marker.exists():
                _denied("recipient-owned irreversible effect already reserved; reconcile")
            intent=dict(claim,schema="neurofactory.protected_recipient_receipt.fixture.v1",
                        status="UNKNOWN_MANUAL_RECONCILIATION")
            raw=json.dumps(intent,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
            _write_exclusive(self.dir,task_marker.name,raw)
            _write_exclusive(self.dir,target_marker.name,raw)
            # Even if the process crashes in the effect or DB transaction,
            # UNKNOWN remains sticky; no auto retry.
            try:
                yield intent
            except BaseException:
                raise
            else:
                complete=dict(intent,status="COMPLETED_TEST_ONLY")
                new=json.dumps(complete,sort_keys=True,separators=(",",":")).encode()
                tmp=self.dir/(task_marker.name+".new")
                _write_exclusive(self.dir,tmp.name,new)
                os.replace(tmp,task_marker)
                _fsync_dir(self.dir)
        finally:
            try:fcntl.flock(lockfd,fcntl.LOCK_UN)
            finally:os.close(lockfd)

    def inspect(self, task_id):
        _exact_claim(task_id,"inspect","bridge/neurofactory/development/core_owned/inspect.txt","0"*64)
        marker=self.dir/("task-"+hashlib.sha256(task_id.encode()).hexdigest()+".json")
        if not marker.is_file():return {"state":"NEVER_SEEN","auto_retry_allowed":False}
        st=marker.lstat()
        if st.st_uid!=os.geteuid() or st.st_mode&0o077 or not stat.S_ISREG(st.st_mode):
            _denied("protected state swapped")
        data=json.loads(marker.read_text("ascii"))
        if data.get("schema")!="neurofactory.protected_recipient_receipt.fixture.v1":
            _denied("damaged receipt")
        if data.get("task_id")!=task_id or data.get("status") not in (
            "UNKNOWN_MANUAL_RECONCILIATION","COMPLETED_TEST_ONLY"):
            _denied("damaged protected receipt")
        return {"state":data["status"],"auto_retry_allowed":False}
