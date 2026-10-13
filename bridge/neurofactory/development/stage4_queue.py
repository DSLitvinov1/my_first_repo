"""Scoped Stage-4 queue: durable claims and explicit receipt-gated completion.

No subprocesses, models, network calls, GitHub writes, or ChatGPT delivery occur here.
External operators must verify actual remote receipts before acknowledgement.
"""
import pathlib
import re
import durable_checkpoint as checkpoint
from control_plane import validate as validate_roadmap

STAGES = ("writer", "reviewer", "publisher")
ACTOR = {"writer": "qwen2.5-coder:7b", "reviewer": "qwen3:4b", "publisher": "trusted-github-publisher"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class Stage4Error(ValueError):
    pass


def approved_plan(plan):
    validate_roadmap(plan)
    states = {m["id"]: m["state"] for m in plan["milestones"]}
    if (plan.get("chat_delivery_paused") is not True
            or states.get("NF-DEV-02") != "deferred"
            or states.get("NF-DEV-03") != "verified"
            or states.get("NF-DEV-04") != "active"):
        raise Stage4Error("Stage 4 is not authorized or ChatGPT delivery was unpaused")


class Stage4Queue:
    def __init__(self, root, plan):
        approved_plan(plan)
        self.root = pathlib.Path(root)
        if not self.root.is_dir() or self.root.is_symlink():
            raise Stage4Error("Existing isolated checkpoint directory required")
        self.guard = self.root / "neurofactory-stage4-coordinator"
        self.paths = {role: self.root / ("nf-dev-04-" + role + ".json") for role in STAGES}

    def prepare(self):
        with checkpoint._lock(self.guard):
            for role in STAGES:
                path = self.paths[role]
                if not path.exists():
                    checkpoint.initialize(path, {
                        "id": "NF-DEV-04-" + role,
                        "role": role,
                        "actor": ACTOR[role],
                        "state": "queued",
                        "attempts": 0,
                        "lease_until": None,
                        "scope": "neurofactory_only",
                        "chat_delivery": "paused_by_user"
                    })
                else:
                    self._read(role)
            return self._states()

    def _read(self, role):
        task = checkpoint.load(self.paths[role])
        if (task["id"] != "NF-DEV-04-" + role
                or task.get("role") != role
                or task.get("actor") != ACTOR[role]
                or task.get("scope") != "neurofactory_only"
                or task.get("chat_delivery") != "paused_by_user"):
            raise Stage4Error("Role or task identity changed")
        return task

    def _states(self):
        return {role: self._read(role) for role in STAGES}

    def recover(self, now, max_attempts=2):
        with checkpoint._lock(self.guard):
            for role in STAGES:
                checkpoint.recover(self.paths[role], now, max_attempts)
            return self._states()

    def claim(self, role, now, lease_seconds=120, max_attempts=2):
        if role not in STAGES or type(now) is not int or now < 0:
            raise Stage4Error("Unknown actor or clock")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise Stage4Error("Unsafe lease")
        with checkpoint._lock(self.guard):
            states = {}
            for actor in STAGES:
                checkpoint.recover(self.paths[actor], now, max_attempts)
                states[actor] = self._read(actor)
            previous = STAGES[:STAGES.index(role)]
            if any(states[r]["state"] != "verified_done" for r in previous):
                raise Stage4Error("Prior independent agent or receipt incomplete")
            if any(t["state"] in {"running", "publishing", "needs_receipt_check"}
                   for actor, t in states.items() if actor != role):
                raise Stage4Error("Another agent has an unresolved claim")
            if states[role]["state"] != "queued":
                raise Stage4Error("Duplicate or unresolved task claim")
            return checkpoint.transition(self.paths[role], "queued", "running",
                                         lease_until=now + lease_seconds)

    def before_external_effect(self, role, *, source_sha256=None, verdict=None):
        """Store immutable evidence then publishing intent, before any external effect."""
        if role not in STAGES:
            raise Stage4Error("Unrecognized agent")
        with checkpoint._lock(self.guard):
            self._read(role)
            if role == "writer":
                if not isinstance(source_sha256, str) or not DIGEST.fullmatch(source_sha256):
                    raise Stage4Error("Writer needs exact candidate SHA-256")
                proof = {"source_sha256": source_sha256}
            elif role == "reviewer":
                writer = self._read("writer")
                if writer["state"] != "verified_done":
                    raise Stage4Error("Writer candidate not acknowledged")
                if source_sha256 != writer.get("proof", {}).get("source_sha256") or verdict != "REVIEW_OK":
                    raise Stage4Error("Reviewer did not approve writer's exact source")
                proof = {"source_sha256": source_sha256, "verdict": verdict}
            else:
                reviewer = self._read("reviewer")
                if reviewer["state"] != "verified_done" or reviewer.get("proof", {}).get("verdict") != "REVIEW_OK":
                    raise Stage4Error("Reviewer proof missing")
                proof = {"source_sha256": reviewer["proof"]["source_sha256"]}
            path = self.paths[role]
            with checkpoint._lock(path):
                task = checkpoint._load(path)
                if task["state"] != "running":
                    raise Stage4Error("Publication must follow a fresh claimed task")
                task["proof"] = proof
                checkpoint._save(path, task)
            return checkpoint.transition(path, "running", "publishing")

    def acknowledge(self, role, commit_sha, *, remote_verified=False):
        """Never resend: acknowledgement requires an independently checked receipt."""
        if role not in STAGES or not isinstance(commit_sha, str) or not SHA.fullmatch(commit_sha):
            raise Stage4Error("Invalid remote receipt")
        if remote_verified is not True:
            raise Stage4Error("Remote GitHub receipt must be independently verified")
        with checkpoint._lock(self.guard):
            self._read(role)
            task = self._read(role)
            if role == "reviewer":
                if (self._read("writer")["state"] != "verified_done"
                        or task.get("proof", {}).get("verdict") != "REVIEW_OK"
                        or task.get("proof", {}).get("source_sha256") != self._read("writer").get("proof", {}).get("source_sha256")):
                    raise Stage4Error("Missing independent review of writer's exact source")
            elif role == "publisher":
                if (self._read("reviewer")["state"] != "verified_done"
                        or task.get("proof", {}).get("source_sha256") != self._read("reviewer").get("proof", {}).get("source_sha256")):
                    raise Stage4Error("Production publishing requires confirmed review")
            state = self._read(role)["state"]
            if state == "publishing":
                checkpoint.recover(self.paths[role], 0, 2)
                state = self._read(role)["state"]
            if state != "needs_receipt_check":
                raise Stage4Error("Receipt already consumed or publication not prepared")
            return checkpoint.transition(self.paths[role], "needs_receipt_check",
                                         "verified_done", commit=commit_sha)
