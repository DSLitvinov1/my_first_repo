"""Sequential real-development queue over the already verified durable Stage-4 lanes.

Only explicitly approved Neurofactory tasks, two independent model roles and a trusted
publisher. No models, paid APIs, ChatGPT sender, or GitHub writes occur in this module.
"""
import hashlib
import json
import os
import pathlib
import re

import durable_checkpoint as checkpoint
from stage4_queue import Stage4Queue, Stage4Error, STAGES, approved_plan

REPO = "DSLitvinov1/my_first_repo"
BRANCH = "neurofactory-public-lab-20261012"
SAFE = "bridge/neurofactory/development/"
ID = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
HEX = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class DevelopmentQueueError(ValueError):
    pass


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def validate_jobs(jobs):
    if not isinstance(jobs, list) or not 2 <= len(jobs) <= 8:
        raise DevelopmentQueueError("Need two to eight distinct approved jobs")
    seen_ids = set()
    seen_paths = set()
    for entry in jobs:
        if not isinstance(entry, dict) or set(entry) != {"id", "target", "objective"}:
            raise DevelopmentQueueError("Unrecognized approved-task fields")
        job_id, target, objective = entry["id"], entry["target"], entry["objective"]
        if not isinstance(job_id, str) or not ID.fullmatch(job_id) or job_id in seen_ids:
            raise DevelopmentQueueError("Repeated or unapproved job identity")
        if not isinstance(target, str) or not target.startswith(SAFE) or target in seen_paths:
            raise DevelopmentQueueError("Outside development-only path or duplicated file")
        if not re.fullmatch(r"[a-zA-Z0-9_./-]{1,180}", target) or any(
                part in ("", ".", "..") for part in target.split("/")):
            raise DevelopmentQueueError("Unsafe destination path")
        if not isinstance(objective, str) or not 25 <= len(objective) <= 320:
            raise DevelopmentQueueError("Bounded approved goal required")
        seen_ids.add(job_id)
        seen_paths.add(target)
    return jobs


class DevelopmentQueue:
    def __init__(self, root, plan, jobs):
        approved_plan(plan)
        if next((x["state"] for x in plan["milestones"] if x["id"] == "NF-DEV-04"), None) != "verified":
            raise DevelopmentQueueError("Stage 4 must already be verified")
        self.root = pathlib.Path(root)
        if not self.root.is_dir() or self.root.is_symlink():
            raise DevelopmentQueueError("Existing isolated working folder required")
        self.plan = plan
        self.jobs = [dict(x) for x in validate_jobs(jobs)]
        self.identity = hashlib.sha256(_canonical(self.jobs)).hexdigest()
        self.lock = self.root / "nf-stage5-global-serial"
        self.manifest = self.root / "nf-stage5-manifest.json"
        self.lanes = {x["id"]: Stage4Queue(self.root, plan, task_id=x["id"]) for x in self.jobs}

    def _check_manifest(self):
        doc = checkpoint.load(self.manifest)
        if (doc["id"] != "NF-DEV-05-QUEUE" or
                doc["identity_sha256"] != self.identity or
                doc.get("scope") != "neurofactory_only" or
                doc.get("chat_delivery") != "paused_by_user"):
            raise DevelopmentQueueError("Job list changed after checkpoint initialization")
        return doc

    def prepare(self):
        with checkpoint._lock(self.lock):
            if not self.manifest.exists():
                # An interrupted restore can leave uncommitted role files.
                # Never initialize a fresh manifest over those files: this
                # would silently adopt half of an older, unverified snapshot.
                role_files = [p for lane in self.lanes.values()
                              for p in lane.paths.values()]
                if any(path.exists() for path in role_files):
                    raise DevelopmentQueueError(
                        "Incomplete restoration detected: no committed manifest; "
                        "restore only into a fresh empty directory")
                checkpoint.initialize(self.manifest, {
                    "id": "NF-DEV-05-QUEUE", "state": "queued",
                    "attempts": 0, "lease_until": None,
                    "identity_sha256": self.identity, "scope": "neurofactory_only",
                    "chat_delivery": "paused_by_user"
                })
            self._check_manifest()
            for lane in self.lanes.values():
                lane.prepare()
            return self._snapshot()

    def _snapshot(self):
        self._check_manifest()
        return {x["id"]: self.lanes[x["id"]]._states() for x in self.jobs}

    def snapshot(self):
        with checkpoint._lock(self.lock):
            return self._snapshot()

    def _next(self):
        states = self._snapshot()
        for entry in self.jobs:
            job_id = entry["id"]
            if states[job_id]["publisher"]["state"] != "verified_done":
                return entry, states[job_id]
        return None, None

    def next_job(self):
        with checkpoint._lock(self.lock):
            entry, state = self._next()
            return None if entry is None else {
                "id": entry["id"], "target": entry["target"],
                "roles": {name: state[name]["state"] for name in STAGES}
            }

    def recover(self, now):
        with checkpoint._lock(self.lock):
            self._check_manifest()
            for item in self.jobs:
                self.lanes[item["id"]].recover(now, max_attempts=2)
            return self._snapshot()

    def _authorized_current(self, job_id):
        if job_id not in self.lanes:
            raise DevelopmentQueueError("Unknown job")
        entry, _ = self._next()
        if entry is None or entry["id"] != job_id:
            raise DevelopmentQueueError("Cannot skip or replay another task")
        return entry

    def claim(self, job_id, role, now, lease_seconds=120):
        with checkpoint._lock(self.lock):
            self._authorized_current(job_id)
            if role not in STAGES:
                raise DevelopmentQueueError("Unapproved executor")
            return self.lanes[job_id].claim(role, now, lease_seconds=lease_seconds)

    def before_effect(self, job_id, role, **proof):
        with checkpoint._lock(self.lock):
            self._authorized_current(job_id)
            if role not in STAGES:
                raise DevelopmentQueueError("Unapproved executor")
            return self.lanes[job_id].before_external_effect(role, **proof)

    def acknowledge(self, job_id, role, sha, *, verify_remote):
        """Trusted caller MUST verify a real remote commit/path/hash before completing.

        An arbitrary Boolean does not count as a remote receipt; the callback must
        be a separate read-only GitHub receipt verifier, not a model's self-report.
        """
        with checkpoint._lock(self.lock):
            entry = self._authorized_current(job_id)
            if role not in STAGES or not isinstance(sha, str) or not HEX.fullmatch(sha):
                raise DevelopmentQueueError("Unknown role or invalid commit receipt")
            if not callable(verify_remote):
                raise DevelopmentQueueError("Independent remote verifier required")
            task = self.lanes[job_id]._read(role)
            source_hash = task.get("proof", {}).get("source_sha256")
            if not isinstance(source_hash, str) or not DIGEST.fullmatch(source_hash):
                raise DevelopmentQueueError("Source fingerprint not checkpointed")
            if verify_remote(REPO, BRANCH, entry["target"], sha, source_hash) is not True:
                raise DevelopmentQueueError("GitHub commit and exact source not independently verified")
            return self.lanes[job_id].acknowledge(role, sha, remote_verified=True)

    def sealed_snapshot(self):
        """Portable, tamper-evident checkpoint journal for transport to trusted GitHub storage."""
        with checkpoint._lock(self.lock):
            self._snapshot()
            paths = [self.manifest] + [self.lanes[job["id"]].paths[role]
                                        for job in self.jobs for role in STAGES]
            encoded = {p.name: p.read_text("utf-8") for p in paths}
            packed = {"schema": 1, "identity_sha256": self.identity,
                      "scope": "neurofactory_only", "chat_delivery": "paused_by_user",
                      "files": encoded}
            return {"body": packed, "sha256": hashlib.sha256(_canonical(packed)).hexdigest()}

    def restore_snapshot(self, record):
        """Only to a NEW empty folder; never overwrite another runner's live checkpoints."""
        if not isinstance(record, dict) or set(record) != {"body", "sha256"}:
            raise DevelopmentQueueError("Untrusted snapshot")
        body = record["body"]
        if (not isinstance(body, dict) or
                hashlib.sha256(_canonical(body)).hexdigest() != record["sha256"] or
                body.get("identity_sha256") != self.identity or
                body.get("scope") != "neurofactory_only" or
                body.get("chat_delivery") != "paused_by_user"):
            raise DevelopmentQueueError("Snapshot corrupted or from another project")
        expected = {self.manifest.name} | {p.name for x in self.jobs for p in self.lanes[x["id"]].paths.values()}
        if not isinstance(body.get("files"), dict) or set(body["files"]) != expected:
            raise DevelopmentQueueError("Incomplete or extra checkpoint files")
        with checkpoint._lock(self.lock):
            if any((self.root / name).exists() for name in expected):
                raise DevelopmentQueueError("Cannot restore over existing checkpoint")
            for name in expected:
                doc = json.loads(body["files"][name])
                if doc.get("schema") != 1 or not isinstance(doc.get("data"), dict):
                    raise DevelopmentQueueError("Checkpoint schema changed")
                checkpoint.validate(doc["data"])
                if doc.get("sha256") != hashlib.sha256(_canonical(doc["data"])).hexdigest():
                    raise DevelopmentQueueError("Tampered role checkpoint")
            # Reserve every checkpoint with O_EXCL. A concurrent initializer may
            # create a file after the existence preflight; never overwrite it.
            created = []
            try:
                # Manifest is an atomic commit marker: publish the role files
                # first. Other coordinators acquire the same global process
                # lock; readers must not see a committed, partial restore.
                names = sorted(expected - {self.manifest.name}) + [self.manifest.name]
                for name in names:
                    path = self.root / name
                    try:
                        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    except FileExistsError as exc:
                        raise DevelopmentQueueError(
                            "Concurrent checkpoint initialization; restore refused") from exc
                    created.append(path)
                    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                        stream.write(body["files"][name])
                        stream.flush()
                        os.fsync(stream.fileno())
                self._snapshot()
            except BaseException:
                # Only remove checkpoints created by this restore invocation.
                for path in reversed(created):
                    path.unlink(missing_ok=True)
                raise
            return True
