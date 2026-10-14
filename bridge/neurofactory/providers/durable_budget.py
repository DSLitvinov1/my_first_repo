"""Local-only, cross-process durable reservation ledger for Qwen attempts.

Failures are deliberately sticky. No implicit recovery or network effects.
Trusted exclusive directory is required; this is not a distributed database.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import json
import os
import re

_TASK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_STATE_NAME = "reservations.json"
_LOCK_NAME = "reservation.lock"
_TEMP_NAME = "reservations.pending"


class DurableBudgetError(RuntimeError):
    """Budget state cannot be trusted: STOP instead of retrying a model."""


class DuplicateTask(DurableBudgetError):
    """Task was already reserved; unknown outcomes must not be retried."""


class DurableLimitExceeded(DurableBudgetError):
    """Persistent attempt or approximate prompt-size limit reached."""


@dataclass(frozen=True)
class DurableBudget:
    directory: Path
    max_attempts: int = 10
    max_reserved_units: int = 250000

    def __post_init__(self) -> None:
        if not isinstance(self.directory, Path):
            raise ValueError("explicit pathlib.Path required")
        if not self.directory.is_dir() or self.directory.is_symlink():
            raise ValueError("trusted pre-existing non-symlink budget directory required")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 100:
            raise ValueError("invalid persistent attempt limit")
        if (type(self.max_reserved_units) is not int or
                not 1024 <= self.max_reserved_units <= 1_000_000):
            raise ValueError("invalid persistent reservation limit")

    def _read(self) -> dict:
        state_path = self.directory / _STATE_NAME
        if state_path.is_symlink():
            raise DurableBudgetError("symlink state prohibited")
        try:
            with state_path.open("rb") as stream:
                raw = stream.read(65537)
        except FileNotFoundError:
            if (self.directory / _TEMP_NAME).exists():
                raise DurableBudgetError("pending state: manual intervention required")
            return {
                "version": 1,
                "max_attempts": self.max_attempts,
                "max_reserved_units": self.max_reserved_units,
                "attempts": 0,
                "reserved_units": 0,
                "tasks": [],
            }
        except OSError as exc:
            raise DurableBudgetError("cannot read reservation ledger") from exc
        if len(raw) > 65536:
            raise DurableBudgetError("oversized reservation ledger")

        def no_duplicates(pairs):
            result = {}
            for k, v in pairs:
                if k in result:
                    raise ValueError("duplicate key in persistent ledger")
                result[k] = v
            return result

        try:
            state = json.loads(raw, object_pairs_hook=no_duplicates)
        except (UnicodeError, ValueError, TypeError) as exc:
            raise DurableBudgetError("invalid persistent ledger") from exc
        if (type(state) is not dict or
                set(state) != {"version", "max_attempts", "max_reserved_units", "attempts", "reserved_units", "tasks"} or
                type(state["version"]) is not int or state["version"] != 1 or
                type(state["max_attempts"]) is not int or state["max_attempts"] != self.max_attempts or
                type(state["max_reserved_units"]) is not int or state["max_reserved_units"] != self.max_reserved_units or
                type(state["attempts"]) is not int or not 0 <= state["attempts"] <= self.max_attempts or
                type(state["reserved_units"]) is not int or not 0 <= state["reserved_units"] <= self.max_reserved_units or
                type(state["tasks"]) is not list or len(state["tasks"]) != state["attempts"] or
                any(type(x) is not str or not re.fullmatch(r"[0-9a-f]{64}", x) for x in state["tasks"]) or
                len(set(state["tasks"])) != len(state["tasks"])):
            raise DurableBudgetError("reservation ledger invariant violation")
        if (self.directory / _TEMP_NAME).exists():
            raise DurableBudgetError("unresolved pending state: manual intervention required")
        return state

    def reserve(self, units: int, task_id: str) -> None:
        if type(units) is not int or units <= 0:
            raise ValueError("invalid reservation size")
        if type(task_id) is not str or not _TASK_ID.fullmatch(task_id):
            raise ValueError("safe task ID required for durable reservation")
        # mkdir is exclusive across processes. If an owner crashes, this lock
        # remains and blocks all work until deliberate operator inspection.
        lock_path = self.directory / _LOCK_NAME
        try:
            lock_path.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise DurableBudgetError("reservation locked or interrupted; STOP") from exc
        except OSError as exc:
            raise DurableBudgetError("cannot acquire persistent lock") from exc
        release_lock = False
        try:
            state = self._read()
            task_digest = sha256(task_id.encode("utf-8")).hexdigest()
            if task_digest in state["tasks"]:
                release_lock = True
                raise DuplicateTask("task reservation exists; retry prohibited")
            if (state["attempts"] >= self.max_attempts or
                    state["reserved_units"] + units > self.max_reserved_units):
                release_lock = True
                raise DurableLimitExceeded("persistent reservation limit reached")
            state["attempts"] += 1
            state["reserved_units"] += units
            state["tasks"].append(task_digest)
            serialized = (json.dumps(state, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
            pending = self.directory / _TEMP_NAME
            # Exclusive create; pending remains on any write failure.
            with pending.open("xb") as output:
                output.write(serialized)
                output.flush()
                os.fsync(output.fileno())
            os.replace(pending, self.directory / _STATE_NAME)
            # POSIX: durable directory entry before allowing side effect.
            if os.name == "posix":
                handle = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(handle)
                finally:
                    os.close(handle)
            verified = self._read()
            if verified != state:
                raise DurableBudgetError("ledger readback mismatch")
            release_lock = True
        finally:
            # Preserve the lock after ANY uncertain IO failure for manual inspection.
            if release_lock and not (self.directory / _TEMP_NAME).exists():
                try:
                    lock_path.rmdir()
                except OSError as exc:
                    raise DurableBudgetError("failed to release reservation lock") from exc

    def snapshot(self) -> dict:
        if (self.directory / _LOCK_NAME).exists():
            raise DurableBudgetError("locked reservation ledger")
        return self._read()
