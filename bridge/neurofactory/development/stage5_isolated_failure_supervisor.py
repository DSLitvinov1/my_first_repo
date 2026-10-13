"""Isolated Stage-5 failure supervisor; no models, secrets, GitHub writes or chat delivery.

This module is a bounded, local checkpoint and decision layer, not a live
production dispatcher. Never use it to replay an uncertain publication.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time
from contextlib import contextmanager

BRANCH = "neurofactory-stage5-isolated-acceptance-20261013"
SCOPE = "neurofactory_only"
TASK_PATTERN = re.compile(r"NF-DEV-05-FAULT-[0-9]{3}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
ROLES = ("writer", "reviewer", "publisher")
ALLOWED_RUNNERS = ("WIN-LIDC05TBOQD-chatgpt", "recovery", "neurofactory-reserve-3")
MAX_RETRIES = 2

class UnsafeState(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def digest(value):
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()

class FailureLedger:
    def __init__(self, root, task_id, *, branch=BRANCH):
        if not isinstance(task_id, str) or not TASK_PATTERN.fullmatch(task_id):
            raise UnsafeState("Unapproved fault-test identity")
        if branch != BRANCH:
            raise UnsafeState("Wrong branch; fail closed")
        self.root = Path(root)
        if not self.root.is_dir() or self.root.is_symlink():
            raise UnsafeState("An existing isolated nonsymlink directory is required")
        self.task_id = task_id
        self.file = self.root / (task_id + "-checkpoint.json")
        self.lock_file = self.root / (task_id + "-checkpoint.lock")

    @contextmanager
    def _lock(self):
        try:
            fd = os.open(self.lock_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise UnsafeState("Concurrent or stale owner: stop, do not overwrite") from exc
        try:
            os.close(fd)
            yield
        finally:
            self.lock_file.unlink(missing_ok=True)

    def _read(self):
        if not self.file.exists():
            return None
        if self.file.is_symlink():
            raise UnsafeState("Checkpoint symlink forbidden")
        doc = json.loads(self.file.read_bytes())
        if not isinstance(doc, dict) or set(doc) != {"payload", "sha256"}:
            raise UnsafeState("Bad checkpoint envelope")
        body = doc["payload"]
        if not isinstance(body, dict) or doc["sha256"] != digest(canonical(body)):
            raise UnsafeState("Checkpoint digest mismatch")
        if (body.get("scope") != SCOPE or body.get("branch") != BRANCH
                or body.get("task_id") != self.task_id or body.get("chat_delivery") != "paused"):
            raise UnsafeState("Foreign checkpoint scope")
        return body

    def snapshot(self):
        return self._read()

    def _write(self, state):
        state["revision"] += 1
        doc = {"payload": state, "sha256": digest(canonical(state))}
        temp = self.root / (self.task_id + "-checkpoint.tmp")
        if temp.exists() or temp.is_symlink():
            raise UnsafeState("Unreconciled interrupted checkpoint write")
        try:
            with open(temp, "xb") as f:
                f.write(canonical(doc) + b"\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, self.file)
        finally:
            temp.unlink(missing_ok=True)

    def _change(self, fn):
        with self._lock():
            state = self._read()
            if state is None:
                raise UnsafeState("Checkpoint must be initialized")
            result = fn(state)
            if result is not None:
                self._write(state)
            return self._read()

    def initialize(self):
        with self._lock():
            old = self._read()
            if old is not None:
                return old
            state = dict(schema=1, scope=SCOPE, branch=BRANCH,
                         task_id=self.task_id, chat_delivery="paused",
                         phase=None, status="queued", retries=0,
                         runner=None, started=None, candidate=None,
                         candidate_sha256=None, reviewer=None,
                         review_sha256=None, publication_sha=None,
                         error=None, revision=0)
            self._write(state)
            return self._read()

    def start(self, phase, runner, *, now):
        if phase not in ROLES or runner not in ALLOWED_RUNNERS:
            raise UnsafeState("Unknown phase or unauthorized runner")
        if not isinstance(now, int) or now < 0:
            raise UnsafeState("Invalid checkpoint clock")
        def modify(s):
            allowed = {"writer": "queued", "reviewer": "writer_ready",
                       "publisher": "review_ok"}
            if s["status"] == "verified_done":
                return None
            if s["status"] == "retry_wait":
                if s["phase"] != phase:
                    raise UnsafeState("Cannot change role during recovery")
            elif s["status"] != allowed[phase]:
                raise UnsafeState("Task phase out of order")
            if phase == "publisher" and not self._independent_approval(s):
                raise UnsafeState("Exact independent approval missing")
            s.update(status="running" if phase != "publisher" else "publishing",
                     phase=phase, runner=runner, started=now, error=None)
            return True
        return self._change(modify)

    @staticmethod
    def _independent_approval(s):
        return (isinstance(s.get("candidate"), str)
                and digest(s["candidate"]) == s.get("candidate_sha256")
                and s.get("reviewer") == "qwen3:4b"
                and s.get("review_sha256") == s.get("candidate_sha256"))

    def writer_result(self, candidate):
        if not isinstance(candidate, str) or not 1 <= len(candidate) <= 9000:
            raise UnsafeState("Empty or oversized writer result")
        def modify(s):
            if s["status"] != "running" or s["phase"] != "writer":
                raise UnsafeState("Writer did not own this execution")
            s.update(candidate=candidate, candidate_sha256=digest(candidate),
                     status="writer_ready", started=None, retries=0)
            return True
        return self._change(modify)

    def reviewer_result(self, *, model, reviewed_candidate, approved):
        if model != "qwen3:4b" or type(approved) is not bool:
            raise UnsafeState("Untrusted reviewer verdict")
        def modify(s):
            if s["status"] != "running" or s["phase"] != "reviewer":
                raise UnsafeState("Reviewer did not own this execution")
            if digest(s["candidate"]) != s["candidate_sha256"] or reviewed_candidate != s["candidate"]:
                s.update(status="blocked", error="Reviewer saw different candidate")
            elif not approved:
                s.update(status="blocked", error="Independent review rejected")
            else:
                s.update(status="review_ok", reviewer=model,
                         review_sha256=s["candidate_sha256"], retries=0, started=None)
            return True
        return self._change(modify)

    def failure(self, reason, *, available_runners=()):
        """Count at most two retries; unverified publication never retries."""
        allowed = {"owned_child_stopped", "model_timeout", "worker_unavailable",
                   "github_unavailable", "publication_unknown", "out_of_memory",
                   "model_invalid_output"}
        if reason not in allowed:
            raise UnsafeState("Unknown failure reason")
        if not isinstance(available_runners, (tuple, list)):
            raise UnsafeState("Invalid failover list")
        def modify(s):
            if s["status"] in ("verified_done", "blocked", "needs_receipt_check"):
                return None
            if s["status"] == "publishing" or reason in ("publication_unknown", "github_unavailable"):
                s.update(status="needs_receipt_check", error=reason, started=None)
                return True
            if s["status"] != "running":
                raise UnsafeState("No active owned task to recover")
            if reason == "out_of_memory":
                s.update(status="blocked", error="Resource pressure; never kill user programs")
                return True
            s["retries"] += 1
            if s["retries"] > MAX_RETRIES:
                s.update(status="blocked", error="Retry limit exhausted", started=None)
                return True
            new_runner = next((x for x in available_runners
                               if x in ALLOWED_RUNNERS and x != s["runner"]), None)
            if reason == "worker_unavailable" and new_runner is None:
                s.update(status="blocked", error="No verified reserve executor", started=None)
            else:
                s.update(status="retry_wait", error=reason, started=None,
                         runner=new_runner or s["runner"])
            return True
        return self._change(modify)

    def resume_expired(self, *, now, lease_seconds=120, available_runners=()):
        s = self.snapshot()
        if s is None:
            raise UnsafeState("No checkpoint")
        if s["status"] in ("verified_done", "blocked", "needs_receipt_check"):
            return s
        if s["status"] == "publishing":
            return self.failure("publication_unknown")
        if s["status"] != "running":
            return s
        if (not isinstance(now, int) or not isinstance(s["started"], int)
                or now < s["started"] or now - s["started"] < lease_seconds):
            return s
        return self.failure("owned_child_stopped", available_runners=available_runners)

    def reconcile_receipt(self, receipt, *, github_reachable):
        """Only exact read-back of trusted remote receipt can confirm publication."""
        def modify(s):
            if s["status"] == "verified_done":
                return None
            if s["status"] not in ("publishing", "needs_receipt_check"):
                raise UnsafeState("No publication requiring reconciliation")
            if not github_reachable:
                s.update(status="needs_receipt_check", error="GitHub unavailable; no replay")
                return True
            if not isinstance(receipt, dict):
                s.update(status="blocked", error="Missing or ambiguous remote receipt")
                return True
            valid = (receipt.get("task_id") == self.task_id
                     and receipt.get("branch") == BRANCH
                     and receipt.get("source_sha256") == s["candidate_sha256"]
                     and receipt.get("reviewed_sha256") == s["review_sha256"]
                     and isinstance(receipt.get("commit_sha"), str)
                     and SHA40.fullmatch(receipt["commit_sha"]) is not None)
            if not valid:
                s.update(status="blocked", error="Mismatched remote receipt")
            elif not self._independent_approval(s):
                s.update(status="blocked", error="Review integrity failed")
            else:
                s.update(status="verified_done", publication_sha=receipt["commit_sha"],
                         error=None, started=None)
            return True
        return self._change(modify)
