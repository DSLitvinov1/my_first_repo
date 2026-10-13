"""Durable, serialized Neurofactory task checkpoints, never direct publication."""
import hashlib
import json
import os
import pathlib
import tempfile
from contextlib import contextmanager
from recovery_decision import resume_unfinished

STATES = frozenset({"queued", "running", "publishing", "verified_done", "failed", "retry_exhausted", "needs_receipt_check", "needs_manual_review"})

class CheckpointError(ValueError):
    pass


def validate(task):
    if not isinstance(task, dict) or not isinstance(task.get("id"), str) or not 1 <= len(task["id"]) <= 120:
        raise CheckpointError("Invalid task identity")
    if task.get("state") not in STATES:
        raise CheckpointError("Invalid task state")
    n = task.get("attempts")
    if type(n) is not int or n < 0 or n > 10000:
        raise CheckpointError("Invalid attempt count")
    lease = task.get("lease_until")
    if lease is not None and (type(lease) is not int or lease < 0):
        raise CheckpointError("Invalid lease")
    return task


def serialize(task):
    validate(task)
    body = json.dumps(task, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return json.dumps({"schema": 1, "sha256": hashlib.sha256(body).hexdigest(), "data": task}, ensure_ascii=False, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"


def _safe_file(path):
    p = pathlib.Path(path)
    if not p.parent.is_dir() or p.is_symlink() or p.parent.is_symlink():
        raise CheckpointError("Unsafe checkpoint path")
    return p


@contextmanager
def _lock(target):
    lock = target.with_name(target.name + ".lock")
    if lock.is_symlink():
        raise CheckpointError("Unsafe lock link")
    with open(lock, "a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"1")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _save(target, task):
    payload = serialize(task)
    fd, name = tempfile.mkstemp(prefix=".nf-stage4-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, target)
        if os.name != "nt":
            fd = os.open(str(target.parent), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return task.copy()


def _load(target):
    obj = json.loads(target.read_text("utf-8"))
    if obj.get("schema") != 1 or not isinstance(obj.get("data"), dict):
        raise CheckpointError("Unexpected checkpoint schema")
    task = validate(obj["data"])
    body = json.dumps(task, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if obj.get("sha256") != hashlib.sha256(body).hexdigest():
        raise CheckpointError("Checkpoint checksum invalid")
    return task.copy()


def load(path):
    target = _safe_file(path)
    with _lock(target):
        return _load(target)


def initialize(path, task):
    target = _safe_file(path)
    with _lock(target):
        if target.exists():
            raise CheckpointError("Existing job cannot be reinitialized")
        if task.get("state") != "queued" or task.get("attempts") != 0:
            raise CheckpointError("New job must start queued and never attempted")
        return _save(target, task)


def transition(path, expected, state, *, lease_until=None, commit=None):
    target = _safe_file(path)
    allowed = {("queued", "running"), ("running", "publishing"), ("publishing", "needs_receipt_check"), ("needs_receipt_check", "verified_done")}
    if (expected, state) not in allowed:
        raise CheckpointError("Transition forbidden")
    with _lock(target):
        task = _load(target)
        if task["state"] != expected:
            raise CheckpointError("Concurrent or repeated transition refused")
        new = task.copy()
        new["state"] = state
        if state == "running":
            if type(lease_until) is not int or lease_until < 0:
                raise CheckpointError("Worker must hold valid lease")
            new["attempts"] += 1
            new["lease_until"] = lease_until
        if state == "publishing":
            new["lease_until"] = None
        if state == "verified_done":
            if not isinstance(commit, str) or len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
                raise CheckpointError("Verified receipt SHA required; remote proof must be independently checked")
            new["publication_sha"] = commit
        return _save(target, new)


def recover(path, now, max_attempts):
    if type(now) is not int or now < 0 or type(max_attempts) is not int or max_attempts < 1:
        raise CheckpointError("Invalid recovery clock or retry cap")
    target = _safe_file(path)
    with _lock(target):
        old = _load(target)
        new = resume_unfinished(old, now, max_attempts)
        validate(new)
        if new != old:
            _save(target, new)
        return new.copy()
