"""Single-task, fail-closed CORE sandbox queue (candidate, no model or publishing).

Trusted host alone owns this module's admission API, git checkout and state directory.
Worker output is inert text. OFFLINE_TEST is explicitly not a model execution.
SQLite transactions serialize competing claimants on ONE machine/shared local filesystem;
this is NOT a distributed lease across separate Windows hosts.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import secrets
import sqlite3
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager

TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
PROJECT = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
TARGET = re.compile(r"bridge/neurofactory/development/core_owned/[A-Za-z0-9_./-]{1,110}\Z")
MODELS = frozenset(("qwen3:0.6b", "qwen3:4b", "qwen2.5-coder:7b", "qwen2.5-coder:1.5b"))
SPEC_KEYS = frozenset(("schema", "task_id", "project_id", "target", "objective",
                       "source_sha", "source_sha256", "model", "reserved_units",
                       "approval_commit"))
PROPOSAL_KEYS = frozenset(("schema", "target", "content", "content_sha256", "mode"))
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


class CoreSafetyError(ValueError):
    pass


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _safe_target(path):
    if (type(path) is not str or not TARGET.fullmatch(path)
            or len(path) > 160 or any(not s or s in (".", "..") or s.startswith(".")
                                      for s in path.split("/"))
            or pathlib.PurePosixPath(path).suffix not in (".py", ".md", ".txt", ".json")):
        raise CoreSafetyError("Target is not a single allowed CORE sandbox file")
    # Windows silently resolves device basenames and trailing dots to other objects.
    # Enforce identical path semantics on Linux and Windows before any admission.
    for component in path.split("/"):
        stem = component.split(".", 1)[0].upper()
        if (component.endswith(".") or stem in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(COM|LPT)[1-9]", stem)):
            raise CoreSafetyError("Windows device path or ambiguous trailing dot")
    return path


def _provider_path(core_target):
    """Deterministic one-to-one CORE->proposal path mapping; never a file write."""
    _safe_target(core_target)
    suffix = core_target.removeprefix("bridge/neurofactory/development/core_owned/")
    return ("docs/" if suffix.endswith(".md") else "src/") + suffix


def _safe_directory(path, *, create=False):
    p = pathlib.Path(path)
    if create:
        p.mkdir(mode=0o700, exist_ok=True)
    if p.is_symlink() or not p.is_dir():
        raise CoreSafetyError("Unsafe or missing trusted directory")
    info = p.lstat()
    if not stat.S_ISDIR(info.st_mode) or (
            os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise CoreSafetyError("Reparse directory is not trusted")
    if os.name != "nt" and info.st_mode & 0o077:
        raise CoreSafetyError("Trusted directory must be private (0700)")
    return p


def _git(repo, *arguments):
    try:
        result = subprocess.run(["git", "-C", str(repo), *arguments],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CoreSafetyError("Trusted local Git inspection unavailable") from exc
    if result.returncode:
        raise CoreSafetyError("Source commit not verifiable in local Git object store")
    return result.stdout


def _verify_git_source(repo, spec):
    """Cryptographically bind preimage to an existing local Git commit and HEAD."""
    sha = spec["source_sha"]
    if _git(repo, "rev-parse", "HEAD").decode("ascii").strip() != sha:
        raise CoreSafetyError("Local repository HEAD differs from approved source SHA")
    if _git(repo, "rev-parse", "--verify", sha + "^{commit}").decode("ascii").strip() != sha:
        raise CoreSafetyError("Approved revision is not a commit")
    listing = _git(repo, "ls-tree", "-z", sha, "--", spec["target"])
    if not listing:
        content = b""
    else:
        header, separator, name = listing.partition(b"\t")
        if not separator or name != spec["target"].encode() + b"\0":
            raise CoreSafetyError("Unexpected tree entry")
        if not header.startswith(b"100644 blob "):
            raise CoreSafetyError("Only regular Git-tracked files are admissible")
        content = _git(repo, "show", sha + ":" + spec["target"])
    if len(content) > 65536 or _sha(content) != spec["source_sha256"]:
        raise CoreSafetyError("Git source contents differ from approved checksum")
    return content, bool(listing)


def _validate_spec(spec):
    if type(spec) is not dict or set(spec) != SPEC_KEYS:
        raise CoreSafetyError("Task must have exact trusted schema")
    if (spec["schema"] != "neurofactory.core.task.v1"
            or type(spec["task_id"]) is not str or not TASK.fullmatch(spec["task_id"])
            or type(spec["project_id"]) is not str or not PROJECT.fullmatch(spec["project_id"])
            or type(spec["source_sha"]) is not str or not SHA40.fullmatch(spec["source_sha"])
            or type(spec["source_sha256"]) is not str or not SHA64.fullmatch(spec["source_sha256"])
            or type(spec["approval_commit"]) is not str or not SHA40.fullmatch(spec["approval_commit"])
            or type(spec["objective"]) is not str or not 25 <= len(spec["objective"]) <= 320
            or any(ord(ch) < 32 for ch in spec["objective"])
            or type(spec["model"]) is not str or spec["model"] not in MODELS
            or type(spec["reserved_units"]) is not int
            or not 1 <= spec["reserved_units"] <= 100000):
        raise CoreSafetyError("Unapproved or incompatible task fields")
    _safe_target(spec["target"])


class OneTaskCore:
    """Trusted single-host coordinator; NEVER give its DB, source repo or API to a model."""

    def __init__(self, root, source_repo):
        self.root = _safe_directory(root)
        self.repo = pathlib.Path(source_repo)
        if self.repo.is_symlink() or not self.repo.is_dir():
            raise CoreSafetyError("Trusted Git checkout missing")
        self.state = _safe_directory(self.root / "state", create=True)
        self.sandbox = _safe_directory(self.root / "sandbox", create=True)
        sandbox_stat = self.sandbox.lstat()
        self._sandbox_identity = (sandbox_stat.st_dev, sandbox_stat.st_ino)
        self.db = self.state / "queue.sqlite3"
        if self.db.is_symlink():
            raise CoreSafetyError("Database symlink refused")
        if not self.db.exists():
            try:
                fd = os.open(self.db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        if not self.db.is_file() or self.db.is_symlink():
            raise CoreSafetyError("Unsafe queue database")
        if os.name != "nt" and self.db.stat().st_mode & 0o077:
            raise CoreSafetyError("Queue database must be private")
        with self._connect() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS single_job (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                task_id TEXT NOT NULL UNIQUE,
                spec TEXT NOT NULL,
                spec_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                owner TEXT,
                token_sha256 TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                lease_until INTEGER,
                result_sha256 TEXT,
                receipt TEXT
            )""")

    @contextmanager
    def _connect(self):
        # sqlite3.Connection.__exit__ commits/rolls back but DOES NOT close.
        # A leaked Windows file handle can prevent crash recovery and cleanup.
        con = sqlite3.connect(str(self.db), timeout=10, isolation_level=None)
        try:
            con.execute("PRAGMA busy_timeout=10000")
            con.execute("PRAGMA synchronous=FULL")
            con.execute("PRAGMA journal_mode=DELETE")
            with con:
                yield con
        finally:
            con.close()

    def _row(self, con):
        row = con.execute("SELECT task_id,spec,spec_sha256,state,owner,token_sha256,"
                          "attempts,lease_until,result_sha256,receipt FROM single_job WHERE singleton=1").fetchone()
        if row is None:
            return None
        task, raw, digest, state, owner, token, attempts, lease, result, receipt = row
        try:
            spec = json.loads(raw)
            _validate_spec(spec)
        except (ValueError, TypeError, KeyError) as exc:
            raise CoreSafetyError("Corrupted trusted task checkpoint") from exc
        if _sha(_canonical(spec)) != digest or task != spec["task_id"]:
            raise CoreSafetyError("Checkpoint identity or task fingerprint corrupted")
        allowed_states = {"QUEUED", "CLAIMED", "APPLYING",
                          "CHECKPOINTED_TEST", "NEEDS_MANUAL_REVIEW"}
        if state not in allowed_states or type(attempts) is not int or attempts not in (0, 1):
            raise CoreSafetyError("Unknown or corrupted durable queue state")
        if state == "QUEUED":
            if (attempts != 0 or owner is not None or token is not None or
                    lease is not None or result is not None or receipt is not None):
                raise CoreSafetyError("Queued task contains untrusted execution evidence")
        else:
            if (attempts != 1 or type(owner) is not str or
                    not re.fullmatch(r"[a-zA-Z0-9_-]{1,50}", owner) or
                    type(token) is not str or not SHA64.fullmatch(token) or
                    type(lease) is not int or lease < 0):
                raise CoreSafetyError("Worker claim and lease checkpoint corrupted")
        try:
            parsed_receipt = json.loads(receipt) if receipt is not None else None
        except (TypeError, ValueError) as exc:
            raise CoreSafetyError("Unparseable offline checkpoint receipt") from exc
        if result is not None or parsed_receipt is not None:
            expected_fields = {"schema", "task_id", "source_sha", "source_sha256",
                               "target", "result_sha256", "mode", "model_invoked",
                               "review_approved", "published", "api_cost_usd"}
            if (type(result) is not str or not SHA64.fullmatch(result)
                    or type(parsed_receipt) is not dict
                    or set(parsed_receipt) != expected_fields
                    or parsed_receipt["schema"] != "neurofactory.core.offline_receipt.v1"
                    or parsed_receipt["task_id"] != spec["task_id"]
                    or parsed_receipt["source_sha"] != spec["source_sha"]
                    or parsed_receipt["source_sha256"] != spec["source_sha256"]
                    or parsed_receipt["target"] != spec["target"]
                    or parsed_receipt["result_sha256"] != result
                    or parsed_receipt["mode"] != "OFFLINE_TEST"
                    or parsed_receipt["model_invoked"] is not False
                    or parsed_receipt["review_approved"] is not False
                    or parsed_receipt["published"] is not False
                    or type(parsed_receipt["api_cost_usd"]) is not int
                    or parsed_receipt["api_cost_usd"] != 0):
                raise CoreSafetyError("Receipt metadata or result digest corrupted")
            if state not in ("CHECKPOINTED_TEST", "NEEDS_MANUAL_REVIEW"):
                raise CoreSafetyError("Receipt present before verified local checkpoint")
        elif state == "CHECKPOINTED_TEST":
            raise CoreSafetyError("Completed checkpoint has no offline receipt")
        return {"spec": spec, "state": state, "owner": owner, "token": token,
                "attempts": attempts, "lease_until": lease,
                "result_sha256": result, "receipt": parsed_receipt}

    def _file(self, target, *, make_parents=False):
        path = self.sandbox
        for part in target.split("/")[:-1]:
            path = path / part
            if make_parents and not path.exists():
                path.mkdir(mode=0o700)
            if path.is_symlink() or (path.exists() and not path.is_dir()):
                raise CoreSafetyError("Sandbox parent link or non-directory")
            if path.exists():
                _safe_directory(path)
        file = path / target.split("/")[-1]
        if file.is_symlink() or (file.exists() and not file.is_file()):
            raise CoreSafetyError("Sandbox target link or non-file")
        if file.exists() and file.stat().st_nlink != 1:
            raise CoreSafetyError("Hardlinked sandbox file refused")
        return file

    def _write_one_pinned(self, target, payload, previous_sha, resulting_sha):
        """POSIX descriptor-relative sandbox mutation; Windows fails closed.

        Pin each directory inode (O_NOFOLLOW); never resolve the destination
        by a mutable pathname during os.replace. A same-UID attacker can still
        move already-open directories: identity/readback guards then STOP,
        rather than accepting a false trusted checkpoint.
        """
        if (os.name != "posix" or not all(hasattr(os, name) for name in
                ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"))):
            raise CoreSafetyError("Windows writer disabled pending authorized ACL/reparse host sandbox")
        parts = target.split("/")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        handles = []
        identifiers = []
        temporary = None
        try:
            root_fd = os.open(self.sandbox, flags)
            handles.append(root_fd)
            for index, part in enumerate(("", *parts[:-1])):
                if index:
                    try:
                        child = os.open(part, flags, dir_fd=handles[-1])
                    except FileNotFoundError:
                        os.mkdir(part, mode=0o700, dir_fd=handles[-1])
                        child = os.open(part, flags, dir_fd=handles[-1])
                    handles.append(child)
                stat_dir = os.fstat(handles[-1])
                if (not stat.S_ISDIR(stat_dir.st_mode) or stat_dir.st_mode & 0o077
                        or (index == 0 and
                            (stat_dir.st_dev, stat_dir.st_ino) != self._sandbox_identity)):
                    raise CoreSafetyError("Sandbox directory ownership/identity invalid")
                identifiers.append((stat_dir.st_dev, stat_dir.st_ino))
            parent = handles[-1]
            basename = parts[-1]
            try:
                existing = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                if previous_sha != EMPTY_SHA:
                    raise CoreSafetyError("Approved original disappeared before write")
            else:
                try:
                    info = os.fstat(existing)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                            _sha(os.read(existing, 65537)) != previous_sha):
                        raise CoreSafetyError("Original source inode or checksum changed")
                finally:
                    os.close(existing)
            temporary = ".core-once-" + secrets.token_hex(16)
            temporary_fd = os.open(temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                0o600, dir_fd=parent)
            with os.fdopen(temporary_fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, basename, src_dir_fd=parent, dst_dir_fd=parent)
            temporary = None
            os.fsync(parent)
            result_fd = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                info = os.fstat(result_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        _sha(os.read(result_fd, 12001)) != resulting_sha):
                    raise CoreSafetyError("Pinned output readback failed")
            finally:
                os.close(result_fd)
            # If a directory was renamed away while pinned, never acknowledge it.
            check_fds = []
            try:
                check_fds.append(os.open(self.sandbox, flags))
                for part in parts[:-1]:
                    check_fds.append(os.open(part, flags, dir_fd=check_fds[-1]))
                if any((os.fstat(fd).st_dev, os.fstat(fd).st_ino) != expected
                       for fd, expected in zip(check_fds, identifiers)):
                    raise CoreSafetyError("Sandbox path moved during write")
            finally:
                for fd in reversed(check_fds):
                    os.close(fd)
        except (OSError, ValueError) as exc:
            raise CoreSafetyError("Pinned sandbox write could not be trusted: STOP") from exc
        finally:
            if temporary is not None and handles:
                try:
                    os.unlink(temporary, dir_fd=handles[-1])
                except OSError:
                    pass
            for fd in reversed(handles):
                os.close(fd)

    def enqueue(self, spec, *, trusted_approval_check=None):
        """Admission requires EXTERNAL authenticated approval + actual local Git preimage."""
        _validate_spec(spec)
        if (not callable(trusted_approval_check)
                or trusted_approval_check(json.loads(_canonical(spec))) is not True):
            raise CoreSafetyError("No authenticated CORE approval from trusted host")
        initial, tracked = _verify_git_source(self.repo, spec)
        path = self._file(spec["target"])
        if tracked:
            if not path.is_file() or path.read_bytes() != initial:
                raise CoreSafetyError("Sandbox baseline not equal to approved source")
        elif path.exists():
            raise CoreSafetyError("New target already exists in sandbox")
        blob = _canonical(spec).decode("utf-8")
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            if con.execute("SELECT COUNT(*) FROM single_job").fetchone()[0]:
                raise CoreSafetyError("Single-task queue already occupied; no replay")
            con.execute("INSERT INTO single_job (singleton,task_id,spec,spec_sha256,state) "
                        "VALUES(1,?,?,?,'QUEUED')", (spec["task_id"], blob, _sha(blob.encode())))
            con.execute("COMMIT")
        return self.snapshot()

    def snapshot(self):
        with self._connect() as con:
            row = self._row(con)
            if row is None:
                return {"state": "EMPTY"}
            if row["state"] == "CHECKPOINTED_TEST":
                target = self._file(row["spec"]["target"])
                if (not target.exists()
                        or _sha(target.read_bytes()) != row["result_sha256"]):
                    raise CoreSafetyError(
                        "Checkpoint content changed; require explicit manual recovery")
            return {"task_id": row["spec"]["task_id"], "state": row["state"],
                    "attempts": row["attempts"], "lease_until": row["lease_until"],
                    "source_sha": row["spec"]["source_sha"],
                    "result_sha256": row["result_sha256"],
                    "receipt": row["receipt"]}

    def claim(self, worker, *, now=None, lease_seconds=120):
        """BEGIN IMMEDIATE prevents two workers from claiming the same slot."""
        if type(worker) is not str or not re.fullmatch(r"[a-zA-Z0-9_-]{1,50}", worker):
            raise CoreSafetyError("Invalid trusted worker identifier")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise CoreSafetyError("Invalid lease")
        now = int(time.time()) if now is None else now
        if type(now) is not int or now < 0:
            raise CoreSafetyError("Invalid clock")
        secret = secrets.token_hex(32)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = self._row(con)
            if row is None or row["state"] != "QUEUED":
                raise CoreSafetyError("Already claimed, completed or unresolved: STOP")
            con.execute("UPDATE single_job SET state='CLAIMED', owner=?, token_sha256=?, "
                        "attempts=1, lease_until=? WHERE singleton=1",
                        (worker, _sha(secret.encode()), now + lease_seconds))
            con.execute("COMMIT")
        return {"task_id": row["spec"]["task_id"], "token": secret,
                "lease_until": now + lease_seconds, "target": row["spec"]["target"],
                "model": row["spec"]["model"], "objective": row["spec"]["objective"]}

    def provider_preview(self, task_id):
        """Pure read-only coordinator/provider bridge; ALL execution permissions false."""
        with self._connect() as con:
            row = self._row(con)
        if row is None or row["spec"]["task_id"] != task_id:
            raise CoreSafetyError("Unknown task")
        p = row["spec"]
        trusted_input = _sha(_canonical(p))
        provider_path = _provider_path(p["target"])
        request = {"schema": "neurofactory.providers.request.v1",
                   "task_id": p["task_id"], "project_id": p["project_id"],
                   "input_sha256": trusted_input, "target_path": provider_path,
                   "instruction": p["objective"]}
        binding = {"task_id": p["task_id"], "project_id": p["project_id"],
                   "source_sha": p["source_sha"],
                   "source_sha256": p["source_sha256"],
                   "core_target": p["target"], "provider_target": provider_path,
                   "model": p["model"], "input_sha256": trusted_input}
        return {"schema": "neurofactory.coordination.provider_bridge.v1",
                "request": request, "binding": binding,
                "permissions": {"execution": False, "retry": False,
                                "publication": False, "paid_api": False}}

    def apply_offline_test(self, task_id, token, proposal, *, now=None):
        """Only trusted deterministic TEST output. No subprocess/model/remote publication."""
        if type(proposal) is not dict or set(proposal) != PROPOSAL_KEYS:
            raise CoreSafetyError("One exact inert text proposal required")
        if (proposal["schema"] != "neurofactory.core.proposal.v1"
                or proposal["mode"] != "OFFLINE_TEST"
                or type(proposal["content"]) is not str
                or not 1 <= len(proposal["content"].encode("utf-8")) <= 12000
                or type(proposal["content_sha256"]) is not str
                or not SHA64.fullmatch(proposal["content_sha256"])
                or _sha(proposal["content"].encode("utf-8")) != proposal["content_sha256"]):
            raise CoreSafetyError("Untrusted output or checksum; no model execution permitted")
        now = int(time.time()) if now is None else now
        if type(now) is not int or now < 0 or type(token) is not str:
            raise CoreSafetyError("Invalid claimant context")
        if os.name != "posix":
            raise CoreSafetyError("Windows sandbox writer intentionally disabled until trusted host approval")
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = self._row(con)
            if (row is None or row["spec"]["task_id"] != task_id
                    or row["state"] != "CLAIMED" or row["lease_until"] < now
                    or not secrets.compare_digest(row["token"], _sha(token.encode()))
                    or proposal["target"] != row["spec"]["target"]):
                raise CoreSafetyError("No valid live exclusive CORE claim")
            target = self._file(row["spec"]["target"])
            if target.exists():
                if _sha(target.read_bytes()) != row["spec"]["source_sha256"]:
                    raise CoreSafetyError("Sandbox source preimage changed after admission")
            elif row["spec"]["source_sha256"] != EMPTY_SHA:
                raise CoreSafetyError("Sandbox source disappeared")
            # Durable intent BEFORE any file mutation: unknown effect can never be replayed.
            con.execute("UPDATE single_job SET state='APPLYING' WHERE singleton=1")
            con.execute("COMMIT")
        payload = proposal["content"].encode("utf-8")
        self._write_one_pinned(row["spec"]["target"], payload,
                               row["spec"]["source_sha256"], proposal["content_sha256"])
        receipt = {"schema": "neurofactory.core.offline_receipt.v1",
                   "task_id": task_id, "source_sha": row["spec"]["source_sha"],
                   "source_sha256": row["spec"]["source_sha256"],
                   "target": row["spec"]["target"],
                   "result_sha256": proposal["content_sha256"],
                   "mode": "OFFLINE_TEST", "model_invoked": False,
                   "review_approved": False, "published": False, "api_cost_usd": 0}
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            current = self._row(con)
            if (current["state"] != "APPLYING" or current["token"] != _sha(token.encode())):
                raise CoreSafetyError("Claim invalidated during effect: STOP")
            con.execute("UPDATE single_job SET state='CHECKPOINTED_TEST', "
                        "result_sha256=?, receipt=? WHERE singleton=1",
                        (receipt["result_sha256"], _canonical(receipt).decode()))
            con.execute("COMMIT")
        return receipt

    def recover(self, *, now=None):
        """Expired CLAIMED/APPLYING is UNKNOWN; never automatically retry or publish."""
        now = int(time.time()) if now is None else now
        if type(now) is not int or now < 0:
            raise CoreSafetyError("Invalid recovery clock")
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = self._row(con)
            if row is None:
                raise CoreSafetyError("No checkpoint exists")
            if row["state"] in ("CLAIMED", "APPLYING") and now >= row["lease_until"]:
                con.execute("UPDATE single_job SET state='NEEDS_MANUAL_REVIEW' WHERE singleton=1")
            elif row["state"] == "CHECKPOINTED_TEST":
                target = self._file(row["spec"]["target"])
                if not target.exists() or _sha(target.read_bytes()) != row["result_sha256"]:
                    con.execute("UPDATE single_job SET state='NEEDS_MANUAL_REVIEW' WHERE singleton=1")
            con.execute("COMMIT")
        return self.snapshot()
