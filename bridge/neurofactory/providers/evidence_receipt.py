"""Provider-owned, opt-in record of one observed local model response.

Not an attestation of Ollama authenticity or a REVIEW verdict.  The caller
must already own a trusted private directory and durable one-shot reservation.
Never writes project source files, never calls networks, never retries.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import ctypes
import hmac
import stat
from hashlib import sha256
import json
import os
from pathlib import Path
import re

from local_qwen import ALLOWED_MODELS, _no_duplicate_pairs

_TASK = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_RECORD_BYTES = 65536


class EvidenceError(RuntimeError):
    pass


def evidence_name(task_id: str) -> str:
    if type(task_id) is not str or _TASK.fullmatch(task_id) is None:
        raise EvidenceError("invalid stable task identity")
    return sha256(task_id.encode("utf-8")).hexdigest() + ".json"


def check_evidence_directory(directory: Path) -> None:
    if not isinstance(directory, Path) or not directory.is_dir() or directory.is_symlink():
        raise EvidenceError("trusted pre-existing provider-owned evidence directory required")
    # Untrusted shared directories are not acceptable for raw model text.
    # On Windows ACL ownership is external and MUST be supplied by the host.
    if os.name == "posix":
        try:
            if directory.stat().st_mode & 0o077:
                raise EvidenceError("evidence directory must be private (0700)")
        except OSError as exc:
            raise EvidenceError("cannot inspect evidence directory") from exc



def _check_windows_reparse(path: Path) -> None:
    """Reject existing NTFS symlink/junction/reparse components, fail closed."""
    if os.name != "nt":
        return
    # A Windows trusted CORE owner must still restrict directory ACLs:
    # a privileged actor can replace paths despite all local read-only checks.
    try:
        for component in (path.absolute(), *path.absolute().parents):
            flags = ctypes.windll.kernel32.GetFileAttributesW(str(component))
            if flags == 0xFFFFFFFF or flags & 0x400:
                raise EvidenceError("Windows reparse or inaccessible evidence path")
    except (OSError, AttributeError, ValueError) as exc:
        raise EvidenceError("Windows evidence reparse status unknown") from exc


@contextmanager
def _pinned_directory(directory: Path):
    """POSIX dirfd pins inode across path replacement; NT uses trusted ACLs."""
    check_evidence_directory(directory)
    if os.name != "posix":
        _check_windows_reparse(directory)
        yield None
        _check_windows_reparse(directory)
        return
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent_fd = os.open(directory, flags)
    except OSError as exc:
        raise EvidenceError("cannot pin evidence directory inode") from exc
    try:
        info = os.fstat(parent_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise EvidenceError("evidence directory inode is not private")
        yield parent_fd
        try:
            now = directory.lstat()
        except OSError as exc:
            raise EvidenceError("evidence directory replaced after write") from exc
        if (not stat.S_ISDIR(now.st_mode) or
                (info.st_dev, info.st_ino) != (now.st_dev, now.st_ino)):
            raise EvidenceError("evidence directory switched during operation")
    finally:
        os.close(parent_fd)


def _open_local_record(directory: Path, filename: str, *, create: bool,
                       directory_fd: int | None):
    """Only regular files under a pinned, trusted directory are accepted."""
    if directory_fd is not None:
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL) if create else os.O_RDONLY
        flags |= os.O_NOFOLLOW
        descriptor = os.open(filename, flags, 0o600, dir_fd=directory_fd)
    else:
        path = directory / filename
        _check_windows_reparse(directory)
        if not create and path.is_symlink():
            raise EvidenceError("symlink record prohibited")
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL) if create else os.O_RDONLY
        descriptor = os.open(path, flags, 0o600)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise EvidenceError("evidence record must be a regular file")
    return os.fdopen(descriptor, "wb" if create else "rb")

def persist_model_evidence(
    directory: Path, *,
    task_id: str,
    project_id: str,
    input_sha256: str,
    prompt_sha256: str,
    model: str,
    response_text: str,
    elapsed_ms: int,
    observed_at: str | None = None,
) -> dict:
    """Write once, fsync, read back, and return metadata without raw text.

    The receipt is author-owned evidence of what this process *reported*.
    It is not tamper-evident against the host owner and not independent
    proof that the text originated in the named model.  An uncertain write
    must block the task forever until operator inspection.
    """
    check_evidence_directory(directory)
    filename = evidence_name(task_id)
    if type(project_id) is not str or not _TASK.fullmatch(project_id):
        raise EvidenceError("invalid project identity")
    if (type(input_sha256) is not str or not _SHA256.fullmatch(input_sha256)
        or type(prompt_sha256) is not str or not _SHA256.fullmatch(prompt_sha256)):
        raise EvidenceError("invalid input/prompt fingerprint")
    if type(model) is not str or model not in ALLOWED_MODELS:
        raise EvidenceError("unapproved model")
    if (type(response_text) is not str or not response_text.strip() or
        len(response_text) > 16000 or "\x00" in response_text):
        raise EvidenceError("invalid raw model text")
    if type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 120000:
        raise EvidenceError("invalid observed duration")
    if observed_at is None:
        observed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    elif type(observed_at) is not str or not re.fullmatch(
        r"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00", observed_at
    ):
        raise EvidenceError("invalid timestamp")
    response_digest = sha256(response_text.encode("utf-8")).hexdigest()
    receipt = {
        "schema": "neurofactory.providers.evidence.v1",
        "task_id": task_id,
        "project_id": project_id,
        "input_sha256": input_sha256,
        "prompt_sha256": prompt_sha256,
        "model": model,
        "transport_claim": "ollama-ipv4-loopback",
        "offline_mock_claim": False,
        "response_text": response_text,
        "response_sha256": response_digest,
        "elapsed_ms": elapsed_ms,
        "observed_at_utc": observed_at,
        "review_approved": False,
        "source_applied": False,
        "published": False,
        "independent_provenance_verified": False,
    }
    raw = (json.dumps(receipt, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > MAX_RECORD_BYTES:
        raise EvidenceError("oversized model evidence")
    # Crash during creation leaves a partial final record, intentionally
    # retaining its identity so NO second attempt can silently overwrite it.
    try:
        with _pinned_directory(directory) as parent_fd:
            with _open_local_record(directory, filename, create=True,
                                    directory_fd=parent_fd) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if parent_fd is not None:
                os.fsync(parent_fd)
            # Never follow a symlink introduced between initial path check
            # and readback. POSIX uses the same pinned directory inode.
            with _open_local_record(directory, filename, create=False,
                                    directory_fd=parent_fd) as stream:
                readback = stream.read(MAX_RECORD_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise EvidenceError("evidence write/readback uncertain; no model retry") from exc
    if readback != raw:
        raise EvidenceError("evidence readback mismatch; no model retry")
    return {
        "evidence_filename": filename,
        "evidence_sha256": sha256(readback).hexdigest(),
        "response_sha256": response_digest,
        "observed_at_utc": observed_at,
        "elapsed_ms": elapsed_ms,
    }


def verify_model_evidence(directory: Path, task_id: str, *,
                          expected_evidence_sha256: str | None = None) -> dict:
    """Locally reread and optionally bind bytes to a trusted external digest.

    Without an externally recorded expected SHA, locally self-consistent
    evidence is NOT tamper-proof and MUST NOT be trusted for approval.
    """
    if (expected_evidence_sha256 is not None and
            (type(expected_evidence_sha256) is not str or
             not _SHA256.fullmatch(expected_evidence_sha256))):
        raise EvidenceError("invalid external digest")
    filename = evidence_name(task_id)
    try:
        with _pinned_directory(directory) as parent_fd:
            with _open_local_record(directory, filename, create=False,
                                    directory_fd=parent_fd) as stream:
                raw = stream.read(MAX_RECORD_BYTES + 1)
    except OSError as exc:
        raise EvidenceError("missing or unreadable evidence") from exc
    actual_evidence_digest = sha256(raw).hexdigest()
    if (expected_evidence_sha256 is not None and not
            hmac.compare_digest(actual_evidence_digest, expected_evidence_sha256)):
        raise EvidenceError("record differs from independently anchored digest")
    if len(raw) > MAX_RECORD_BYTES:
        raise EvidenceError("oversized evidence")
    try:
        item = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_pairs)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise EvidenceError("corrupted evidence") from exc
    expected = {
        "schema", "task_id", "project_id", "input_sha256", "prompt_sha256",
        "model", "transport_claim", "offline_mock_claim", "response_text",
        "response_sha256", "elapsed_ms", "observed_at_utc",
        "review_approved", "source_applied", "published",
        "independent_provenance_verified"
    }
    if (type(item) is not dict or set(item) != expected or
        item["schema"] != "neurofactory.providers.evidence.v1" or
        item["task_id"] != task_id or
        type(item["project_id"]) is not str or not _TASK.fullmatch(item["project_id"]) or
        type(item["input_sha256"]) is not str or not _SHA256.fullmatch(item["input_sha256"]) or
        type(item["prompt_sha256"]) is not str or not _SHA256.fullmatch(item["prompt_sha256"]) or
        type(item["model"]) is not str or item["model"] not in ALLOWED_MODELS or
        item["transport_claim"] != "ollama-ipv4-loopback" or
        item["offline_mock_claim"] is not False or
        item["review_approved"] is not False or
        item["source_applied"] is not False or
        item["published"] is not False or
        item["independent_provenance_verified"] is not False or
        type(item["response_text"]) is not str or not item["response_text"].strip() or
        len(item["response_text"]) > 16000 or "\x00" in item["response_text"] or
        type(item["response_sha256"]) is not str or not _SHA256.fullmatch(item["response_sha256"]) or
        item["response_sha256"] != sha256(item["response_text"].encode("utf-8")).hexdigest() or
        type(item["elapsed_ms"]) is not int or not 0 <= item["elapsed_ms"] <= 120000 or
        type(item["observed_at_utc"]) is not str or not re.fullmatch(
            r"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00", item["observed_at_utc"]
        )):
        raise EvidenceError("evidence invariant mismatch")
    return {
        "evidence_filename": filename,
        "evidence_sha256": actual_evidence_digest,
        "response_sha256": item["response_sha256"],
        "observed_at_utc": item["observed_at_utc"],
        "elapsed_ms": item["elapsed_ms"],
    }
