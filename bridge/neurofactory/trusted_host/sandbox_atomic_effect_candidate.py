"""Single-use *sandbox* effect: held PostgreSQL lock -> witness -> O_EXCL+fsync -> receipt.

This is executable integration evidence, NOT a production receiver or permission.
CI_ONLY and TEST_ONLY gates prevent accessing non-disposable DB or real project files.
In tests the external witness is a separately supplied in-memory double: this
cannot demonstrate off-machine highwater, hardware key custody or crash recovery.
No retry is allowed if the witness reservation, file or commit is uncertain.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile

from db_bound_four_party_preflight import (
    AdmissionRejected, inspect_current_lease_and_receipt,
)


class SandboxDenied(ValueError):
    pass


class SandboxEffectUnknown(RuntimeError):
    pass


def _deny():
    raise SandboxDenied("sandbox-only authenticated transaction rejected")


def _open_root(root):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        _deny()
    root = Path(root)
    tmp = Path(tempfile.gettempdir()).resolve()
    # A unique, private child of /tmp, never the repo or a user's working tree.
    if (root.is_symlink() or root.parent.resolve() != tmp or
            not root.name.startswith("nf-atomic-ci-")):
        _deny()
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            os.close(fd)
            _deny()
        return fd
    except (OSError, ValueError) as exc:
        raise SandboxDenied("private root cannot be trusted") from exc


def apply_sandbox_once(
    connection, *, expected_effect, signed_operator_acl,
    signed_owner_grant, signed_host_lease, signed_external_witness,
    now_unix, content, sandbox_root, witness,
    inject_crash_after_fsync=False,
):
    """Real disposable file/SQL effect; NEVER usable as a live write authority.

    The witness interface is intentionally not implemented for production.
    Its mock must durably reserve the exact signed operation before filesystem
    writes; no injection is allowed outside explicitly disposable CI mode.
    """
    if (os.environ.get("NF_DB_SCHEMA_CI_ONLY") != "1" or
            os.environ.get("NF_ATOMIC_TEST_ONLY") != "1" or
            type(inject_crash_after_fsync) is not bool or
            type(content) is not bytes or not 1 <= len(content) <= 65536 or
            type(expected_effect) is not dict or
            hashlib.sha256(content).hexdigest() != expected_effect.get("content_sha256") or
            getattr(connection, "autocommit", None) is not True or
            not callable(getattr(witness, "reserve_precommit", None))):
        _deny()
    # Note: a successful signed SQL preflight is NEVER itself a write grant.
    # The outer transaction owns the NOWAIT row locks across the complete
    # witness -> physical effect -> receipt/lease commit sequence.
    root_fd = _open_root(sandbox_root)
    created = False
    reserved = False
    try:
        name = expected_effect["target"].split("/")[-1]
        if (not name or name in (".", "..") or name.startswith(".") or
                "/" in name or "\\" in name or len(name) > 110):
            _deny()
        try:
            with connection.transaction():
                locked = connection.execute(
                    """SELECT task_id FROM nf_trusted_host.lease_register
                       WHERE task_id=%s FOR UPDATE NOWAIT""",
                    (expected_effect["task_id"],),
                ).fetchone()
                intent = connection.execute(
                    """SELECT task_id FROM nf_trusted_host.effect_receipt
                       WHERE task_id=%s AND operation_id=%s FOR UPDATE NOWAIT""",
                    (expected_effect["task_id"], expected_effect["operation_id"]),
                ).fetchone()
                if not locked or not intent:
                    _deny()
                # Existing operator-installed root and four-role verifier must
                # accept the CURRENT lease, policy, UNKNOWN intent and witness.
                observed = inspect_current_lease_and_receipt(
                    connection, expected_effect=expected_effect,
                    signed_operator_acl=signed_operator_acl,
                    signed_owner_grant=signed_owner_grant,
                    signed_host_lease=signed_host_lease,
                    signed_external_witness=signed_external_witness,
                    now_unix=now_unix,
                )
                if (observed["production_effect_authorized"] is not False or
                        observed["receiver_effect_lock_still_held"] is not False):
                    _deny()
                ack = witness.reserve_precommit(
                    scope_sha256=observed["scope_sha256"],
                    operation_id=expected_effect["operation_id"],
                    commit_sequence=signed_external_witness["body"]["commit_sequence"],
                    journal_root_sha256=signed_external_witness["body"][
                        "protected_journal_root_sha256"],
                )
                if (type(ack) is not dict or
                        set(ack) != {"status", "scope_sha256", "operation_id",
                                     "commit_sequence", "journal_root_sha256"} or
                        ack["status"] != "DURABLY_RESERVED_TEST_ONLY" or
                        ack["scope_sha256"] != observed["scope_sha256"] or
                        ack["operation_id"] != expected_effect["operation_id"] or
                        ack["commit_sequence"] !=
                            signed_external_witness["body"]["commit_sequence"] or
                        ack["journal_root_sha256"] !=
                            signed_external_witness["body"][
                                "protected_journal_root_sha256"]):
                    _deny()
                reserved = True
                # No symlinks and no overwrite: inode creation is exclusive.
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                file_fd = os.open(name, flags, 0o600, dir_fd=root_fd)
                created = True
                try:
                    with os.fdopen(file_fd, "wb", closefd=True) as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    # fdopen always owns and closes file_fd.
                    pass
                os.fsync(root_fd)
                if inject_crash_after_fsync:
                    raise SandboxEffectUnknown("simulated crash after fsync: do not retry")
                digest = hashlib.sha256(content).hexdigest()
                receipt = connection.execute(
                    """UPDATE nf_trusted_host.effect_receipt
                       SET status='COMPLETED', receiver_file_sha256=%s,
                           completed_at=clock_timestamp()
                       WHERE task_id=%s AND operation_id=%s AND status='UNKNOWN'
                       RETURNING status""",
                    (digest, expected_effect["task_id"], expected_effect["operation_id"]),
                ).fetchone()
                lease = connection.execute(
                    """UPDATE nf_trusted_host.lease_register SET state='COMPLETED',
                           updated_at=clock_timestamp()
                       WHERE task_id=%s AND state='CLAIMED'
                         AND lease_epoch=%s AND fencing_token_sha256=%s
                         AND lease_deadline>clock_timestamp()
                       RETURNING state""",
                    (expected_effect["task_id"], expected_effect["lease_epoch"],
                     expected_effect["fencing_token_sha256"]),
                ).fetchone()
                if receipt != ("COMPLETED",) or lease != ("COMPLETED",):
                    raise SandboxEffectUnknown("uncertain completion: do not retry")
            # Only a commit that returned successfully counts as a local sandbox result.
            return {
                "status": "SANDBOX_FILE_AND_SQL_COMPLETED_TEST_ONLY",
                "operation_id": expected_effect["operation_id"],
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "live_execution_allowed": False,
                "release_approved": False,
                "automatic_retry_allowed": False,
                "real_external_witness_attested": False,
            }
        except (SandboxDenied, SandboxEffectUnknown):
            raise
        except Exception as exc:
            if reserved or created:
                raise SandboxEffectUnknown("uncertain witness/file/DB result: STOP") from exc
            raise SandboxDenied("SQL lease, witness or file preflight denied") from exc
    finally:
        os.close(root_fd)
