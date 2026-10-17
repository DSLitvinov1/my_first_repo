"""Fail-closed HOST final-effect receiver in a disposable Linux sandbox ONLY.

Actual durable filesystem creation is exercised, but this is NOT a production
issuer or receiver. All DB identities/owner policies and public pins below are
test-controlled. Protected signer custody, DB-admin-resistant highwater, OS
privilege separation, authenticated HTTPS lease and release approval are absent.

A write is preceded by a committed UNKNOWN intent. Any crash after UNKNOWN,
including AFTER fsync BEFORE receipt, requires human reconciliation; never retry.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import time

from signed_effect_permit import inspect_signed_effect_permit, SignedEffectPermitError


class OfflineReceiverDenied(ValueError):
    pass


class OfflineEffectUnknown(RuntimeError):
    pass


_PREFIX="bridge/neurofactory/development/core_owned/"
_SHA64=re.compile(r"[0-9a-f]{64}\Z")
_TASK=re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_NOFOLLOW=getattr(os,"O_NOFOLLOW",0)
_DIR=os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW | getattr(os,"O_CLOEXEC",0)


def _deny(message):
    raise OfflineReceiverDenied(message)


def _private_dir(path):
    obj=Path(path)
    if not obj.is_absolute() or obj.is_symlink() or not obj.is_dir():
        _deny("missing absolute private sandbox")
    s=obj.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_mode & 0o077:
        _deny("sandbox directory must be private 0700")
    return obj


def _create_fenced_new_file(root, relative_target, content):
    """Open each directory via dirfd/O_NOFOLLOW. Never overwrite existing file.

    Same-UID OS principal is still in trusted computing base for this test
    and a real privileged immutable directory inode is NOT provisioned.
    """
    if type(content) is not bytes or len(content)>65536:
        _deny("content too big or not bytes")
    if type(relative_target) is not str or not relative_target.startswith(_PREFIX):
        _deny("not inside test target root")
    parts=relative_target.split("/")
    if any(not p or p in (".","..") or p.startswith(".") for p in parts):
        _deny("invalid component")
    handle=os.open(root,_DIR)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part,mode=0o700,dir_fd=handle)
            except FileExistsError:
                pass
            next_fd=os.open(part,_DIR,dir_fd=handle)
            os.close(handle)
            handle=next_fd
        filefd=os.open(parts[-1],
                       os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW |
                       getattr(os,"O_CLOEXEC",0),
                       0o600,dir_fd=handle)
        try:
            with os.fdopen(filefd,"wb",closefd=False) as f:
                f.write(content)
                f.flush()
                os.fsync(filefd)
        finally:
            os.close(filefd)
        os.fsync(handle)
    finally:
        os.close(handle)


class OfflineFencedFileReceiver:
    """Never construct with production files, production DB or real keys."""

    def __init__(self, conn, sandbox_root, *, pinned_public_key):
        if os.name!="posix" or os.environ.get("NF_HOST_RECEIVER_FIXTURE_ONLY")!="1":
            _deny("Linux offline explicit fixture gate absent")
        self.root=_private_dir(sandbox_root)
        # An externally managed private temp parent is required even in CI.
        if not self.root.name.startswith("nf-receiver-work-"):
            _deny("only named disposable test workspaces")
        parent=self.root.parent
        if not parent.name.startswith("nf-receiver-test-"):
            _deny("not an isolated test parent")
        _private_dir(parent)
        if getattr(conn,"autocommit",None) is not True:
            _deny("ephemeral autocommit connection required")
        row=conn.execute(
            "SELECT current_database(),current_setting('neurofactory.offline_fixture_mode',true)"
        ).fetchone()
        if row!=("nf_test","on"):
            _deny("not the ephemeral nf_test database")
        self.conn=conn
        self.pinned_key=pinned_public_key

    @staticmethod
    def install_fixture_schema(conn):
        """Called only by test setup, never auto-created by effect operation."""
        row=conn.execute(
            "SELECT current_database(),current_setting('neurofactory.offline_fixture_mode',true)"
        ).fetchone()
        if row!=("nf_test","on"):
            _deny("fixture schema restricted to nf_test")
        conn.execute("""CREATE TABLE IF NOT EXISTS nf_receiver_scope_fixture(
            task_id text PRIMARY KEY REFERENCES nf_task(task_id),
            issuer_id text NOT NULL,
            key_id text NOT NULL,
            owner_id text NOT NULL,
            repository text NOT NULL,
            operation_id text NOT NULL,
            proposed_content_sha256 text NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS nf_receiver_effect_journal(
            task_id text PRIMARY KEY REFERENCES nf_task(task_id),
            idempotency_key text NOT NULL UNIQUE,
            signed_permit_sha256 text NOT NULL,
            status text NOT NULL CHECK(status IN ('UNKNOWN','COMPLETED_TEST')),
            file_sha256 text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp())""")

    def write_fixture_once(self, *, signed_packet, content,
                           simulate_crash_after_fsync=False):
        """Never retries a claimed operation, including status UNKNOWN.

        Test 'success' is a real bounded file creation, NEVER a live approval.
        """
        if (type(signed_packet) is not dict or
            set(signed_packet)!={"payload","signature_base64"} or
            type(content) is not bytes or len(content)>65536 or
            type(simulate_crash_after_fsync) is not bool):
            _deny("invalid effect request")
        body=signed_packet["payload"]
        if type(body) is not dict or not _TASK.fullmatch(body.get("task_id","")
                                 if type(body.get("task_id")) is str else ""):
            _deny("invalid task id")
        task_id=body["task_id"]
        digest=hashlib.sha256(content).hexdigest()
        try:
            with self.conn.transaction():
                task=self.conn.execute(
                    """SELECT phase,fixture_authorized,lease_epoch,holder_id,
                       lease_token_sha256,lease_deadline,project_id,
                       input_core_sha40,source_file_sha256,input_task_sha256,
                       clock_timestamp()
                       FROM nf_task WHERE task_id=%s FOR UPDATE""",
                    (task_id,)).fetchone()
                intent=self.conn.execute(
                    """SELECT project_id,worker_id,lease_epoch,
                       fencing_token_sha256,idempotency_key,source_sha40,
                       source_file_sha256,input_task_sha256,target,policy_sha256
                       FROM nf_effect_intent WHERE task_id=%s""",
                    (task_id,)).fetchone()
                scope=self.conn.execute(
                    """SELECT issuer_id,key_id,owner_id,repository,
                       operation_id,proposed_content_sha256
                       FROM nf_receiver_scope_fixture WHERE task_id=%s""",
                    (task_id,)).fetchone()
                if not task or not intent or not scope:
                    _deny("missing independently configured fixture")
                if task[0]!="LEASED" or task[1] is not True or task[5] is None or task[5]<=task[10]:
                    _deny("HOST blocked unknown or expired")
                if (task[2]!=intent[2] or task[3]!=intent[1] or
                    task[4]!=intent[3] or task[6]!=intent[0] or
                    tuple(task[7:10])!=tuple(intent[5:8])):
                    _deny("current host lease source and fence diverged")
                if digest!=scope[5]:
                    _deny("candidate bytes differ from expected fixture")
                expected={
                    "issuer_id":scope[0],"key_id":scope[1],
                    "owner_id":scope[2],"repository":scope[3],
                    "project_id":intent[0],"task_id":task_id,
                    "worker_id":intent[1],"source_sha40":intent[5],
                    "source_file_sha256":intent[6],"input_task_sha256":intent[7],
                    "policy_sha256":intent[9],"target":intent[8],
                    "proposed_content_sha256":scope[5],
                    "fencing_token_sha256":intent[3],"lease_epoch":intent[2],
                    "idempotency_key":intent[4],"operation_id":scope[4],
                }
                # DB controlled fixture is not a genuine external owner/root.
                report=inspect_signed_effect_permit(
                    signed_packet,externally_pinned_public_key=self.pinned_key,
                    trusted_expected_scope=expected,now_unix=int(time.time()))
                if report["status"]!="CRYPTO_SCOPE_MATCHES_NO_EXECUTION_AUTHORITY":
                    _deny("signed scope refused")
                # Durable reservation *before* effects. Once marked UNKNOWN,
                # even a completed file with missing receipt is never retried.
                result=self.conn.execute(
                    """INSERT INTO nf_receiver_effect_journal
                       (task_id,idempotency_key,signed_permit_sha256,status,file_sha256)
                       VALUES(%s,%s,%s,'UNKNOWN',%s)
                       ON CONFLICT DO NOTHING RETURNING task_id""",
                    (task_id,intent[4],report["signed_permit_sha256"],digest)
                ).fetchone()
                if not result:
                    _deny("duplicate/unknown receiver effect; manual reconciliation only")
        except (SignedEffectPermitError,ValueError) as exc:
            raise OfflineReceiverDenied("signed scope or central lease rejected") from exc
        # The UNKNOWN journal has now COMMITTED. Even a FS or DB failure never
        # authorizes automatic retry; manually reconcile outside this method.
        try:
            _create_fenced_new_file(str(self.root),expected["target"],content)
        except (OSError,OfflineReceiverDenied) as exc:
            raise OfflineEffectUnknown("filesystem result UNKNOWN: stop; no automatic retry") from exc
        if simulate_crash_after_fsync:
            raise OfflineEffectUnknown("crash AFTER fsync BEFORE receipt; manual reconciliation")
        try:
            with self.conn.transaction():
                updated=self.conn.execute(
                    """UPDATE nf_receiver_effect_journal
                       SET status='COMPLETED_TEST'
                       WHERE task_id=%s AND idempotency_key=%s AND status='UNKNOWN'
                       RETURNING task_id""",(task_id,expected["idempotency_key"])
                ).fetchone()
                if not updated:
                    raise OfflineEffectUnknown("receipt update not confirmed")
        except Exception as exc:
            raise OfflineEffectUnknown("receipt unknown; manual reconciliation") from exc
        return {
            "status":"ONE_FILE_COMPLETED_OFFLINE_TEST_ONLY",
            "task_id":task_id,"operation_id":expected["operation_id"],
            "content_sha256":digest,
            "filesystem_effect_observed":True,
            "external_owner_authenticated":False,
            "protected_signer_custody_attested":False,
            "production_lease_authenticated":False,
            "true_independent_recipient_fencing":False,
            "live_execution_allowed":False,
            "auto_retry_allowed":False,"publication_allowed":False,
        }
