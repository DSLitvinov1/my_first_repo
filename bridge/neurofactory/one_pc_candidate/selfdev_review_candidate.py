"""Review-only self-development: saved Qwen -> external signed reviewed Git diff.

Does NOT execute AI text, publish a PR, change protected CORE/HOST, grant
production authority, or install anything. Disposable hosted CI only.
"""
from __future__ import annotations
import base64
import binascii
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time

DOMAIN = b"NF_SELFDEV_REVIEW_CANDIDATE_V2\x00"
SCOPE = "DISPOSABLE_REVIEWED_SOURCE_TO_PATCH_NO_APPLY_NO_PR"
FIELDS = {"schema", "scope", "descriptor", "nonce", "issued_at", "expires_at", "signature"}
DESCRIPTOR = {"schema", "base_sha", "reviewed_sha", "draft_id", "project_id",
              "model", "proposal_sha256", "changes"}
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
UUID32 = re.compile(r"[a-f0-9]{32}\Z")
ALLOWED = re.compile(
    r"(?:bridge/neurofactory/one_pc_candidate/[a-z][a-z0-9_]*\.py|"
    r"bridge/neurofactory/control_ui/[a-z][a-z0-9_-]*\.(?:js|css))\Z"
)
MAX_FILE = 80_000
MAX_PATCH = 160_000

class SelfDevGateDenied(ValueError):
    pass

def _deny(reason):
    raise SelfDevGateDenied(reason)

def _canon(obj):
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, OverflowError) as exc:
        raise SelfDevGateDenied("Noncanonical signed candidate") from exc

def _digest(raw):
    return sha256(raw).hexdigest()

def _git(repo, *args, cap=MAX_PATCH):
    try:
        result = subprocess.run(["git", "-C", str(repo), *args],
                                capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SelfDevGateDenied("Exact local Git source inaccessible") from exc
    if result.returncode or len(result.stdout) > cap:
        _deny("Local Git identity, diff or patch invalid")
    return result.stdout

def _regular(path):
    if path.is_symlink() or not path.is_file():
        _deny("Regular, nonlinked file required")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or (os.name == "nt" and
            info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        _deny("Windows reparse or nonregular file")
    return info

def _run_root():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("NF_SELFDEV_DISPOSABLE_CI") != "1"):
        _deny("Selfdev patch preparation allowed on disposable CI only")
    runner = Path(os.environ["RUNNER_TEMP"])
    if not runner.is_absolute() or runner.is_symlink() or not runner.is_dir():
        _deny("Explicit isolated runner root required")
    return runner.resolve(strict=True)

def _within(path, runner):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        _deny("Absolute nonlinked CI data path required")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(runner) or resolved == runner:
        _deny("Input not in isolated test workspace")
    return resolved

def _evidence(database, descriptor, runner):
    database = _within(database, runner)
    if _regular(database).st_size > 100_000_000:
        _deny("Oversized model evidence SQLite")
    if not all(type(descriptor.get(x)) is str for x in
               ("draft_id", "project_id", "model", "proposal_sha256")):
        _deny("Missing exact signed evidence binding")
    if not UUID32.fullmatch(descriptor["draft_id"]) or not SHA64.fullmatch(descriptor["proposal_sha256"]):
        _deny("Invalid task or response digest")
    try:
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1",
                                     uri=True, timeout=5)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            if db.execute("PRAGMA user_version").fetchone()[0] != 3:
                _deny("Self-development requires saved Qwen workspace v3")
            rows = db.execute(
                "SELECT t.project_id,t.model_preference,t.state,"
                "p.model,p.status,p.content_sha256,p.proposal_text "
                "FROM tasks t JOIN task_proposals p ON p.task_id=t.id "
                "JOIN projects j ON j.id=t.project_id WHERE t.id=?",
                (descriptor["draft_id"],)).fetchall()
    except (sqlite3.DatabaseError, OSError) as exc:
        raise SelfDevGateDenied("Unreadable saved Qwen evidence") from exc
    if len(rows) != 1:
        _deny("Missing or ambiguous saved proposal")
    project, preferred, state, model, status, digest, text = rows[0]
    if ("p-" + project != descriptor["project_id"] or
            not UUID32.fullmatch(project) or
            state != "DRAFT_PENDING_OWNER_AUTH" or
            preferred not in ("auto", model) or
            model != descriptor["model"] or
            model not in ("qwen3:0.6b", "qwen2.5-coder:1.5b") or
            status != "PROPOSED_UNVERIFIED" or
            type(text) is not str or not 1 <= len(text.encode("utf-8")) <= 12000 or
            type(digest) is not str or not SHA64.fullmatch(digest) or
            not secrets.compare_digest(digest, _digest(text.encode("utf-8"))) or
            digest != descriptor["proposal_sha256"]):
        _deny("Saved Qwen response and signed review scope differ")
    return digest

def _validated_changes(changes):
    if type(changes) is not list or not 1 <= len(changes) <= 3:
        _deny("At most three exact reviewed source files")
    names = []
    for item in changes:
        if (type(item) is not dict or set(item) != {"path", "base_sha256", "reviewed_sha256"} or
                any(type(v) is not str for v in item.values()) or
                not ALLOWED.fullmatch(item["path"]) or
                not SHA64.fullmatch(item["base_sha256"]) or
                not SHA64.fullmatch(item["reviewed_sha256"]) or
                item["base_sha256"] == item["reviewed_sha256"]):
            _deny("Unapproved, privileged or ambiguous source file")
        names.append(item["path"])
    if names != sorted(set(names)):
        _deny("Reviewed paths must be unique and ordered")
    return names

def _verify_permit(permit, pinned_public, now):
    if (type(permit) is not dict or set(permit) != FIELDS or
            type(pinned_public) is not bytes or len(pinned_public) != 32 or
            type(now) is not int or now < 0 or
            len(_canon(permit)) > 5000 or
            permit.get("schema") != "nf.selfdev.signed_review_candidate.v2" or
            permit.get("scope") != SCOPE or
            type(permit.get("nonce")) is not str or not UUID32.fullmatch(permit["nonce"]) or
            type(permit.get("issued_at")) is not int or
            type(permit.get("expires_at")) is not int or
            not permit["issued_at"] <= now < permit["expires_at"] or
            not 0 < permit["expires_at"] - permit["issued_at"] <= 300 or
            type(permit.get("signature")) is not str):
        _deny("Untrusted external signer, permit age or invalid envelope")
    d = permit["descriptor"]
    if (type(d) is not dict or set(d) != DESCRIPTOR or
            d.get("schema") != "nf.selfdev.review_descriptor.v2" or
            type(d.get("base_sha")) is not str or not SHA40.fullmatch(d["base_sha"]) or
            type(d.get("reviewed_sha")) is not str or not SHA40.fullmatch(d["reviewed_sha"]) or
            d["base_sha"] == d["reviewed_sha"] or
            type(d.get("project_id")) is not str or
            not re.fullmatch(r"p-[a-f0-9]{32}", d["project_id"])):
        _deny("Invalid immutable reviewed Git commit or project")
    _validated_changes(d["changes"])
    try:
        signature = base64.b64decode(permit["signature"], validate=True)
        if len(signature) != 64:
            _deny("Invalid signature length")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        body = {key: value for key, value in permit.items() if key != "signature"}
        Ed25519PublicKey.from_public_bytes(pinned_public).verify(
            signature, DOMAIN + _canon(body))
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise SelfDevGateDenied("Signature not valid for pinned external reviewer") from exc
    return d

def _git_blob(repo, sha, path):
    line = _git(repo, "ls-tree", "-z", sha, "--", path, cap=220)
    if line.count(b"\x00") != 1 or not line.startswith(b"100644 blob "):
        _deny("Reviewed path is missing, executable, or symlinked")
    meta, sep, file_name = line[:-1].partition(b"\t")
    if not sep or file_name.decode("utf-8") != path:
        _deny("Git file name mismatch")
    blob = meta.split(b" ")[2].decode("ascii")
    if not SHA40.fullmatch(blob):
        _deny("Unapproved blob identity")
    data = _git(repo, "cat-file", "blob", blob, cap=MAX_FILE + 1)
    if not 0 < len(data) <= MAX_FILE:
        _deny("Reviewed file outside fixed limit")
    return data

def prepare_candidate(repo, sqlite_backup, permit, pinned_public, output_dir, *, now=None):
    """Produce review-only patch and manifest; no execution, automatic PR or merge."""
    runner = _run_root()
    now = int(time.time()) if now is None else now
    descriptor = _verify_permit(permit, pinned_public, now)
    evidence_digest = _evidence(sqlite_backup, descriptor, runner)
    repo = Path(repo)
    if not repo.is_absolute() or repo.is_symlink() or not repo.is_dir():
        _deny("Trusted checked-out Git directory required")
    if _git(repo, "rev-parse", "HEAD").decode().strip() != descriptor["reviewed_sha"]:
        _deny("Reviewed source HEAD changed")
    if _git(repo, "status", "--porcelain"):
        _deny("Reviewed working tree is not pristine")
    _git(repo, "merge-base", "--is-ancestor",
         descriptor["base_sha"], descriptor["reviewed_sha"])
    names = _validated_changes(descriptor["changes"])
    actual = _git(repo, "diff", "--name-only", "--no-renames",
                  descriptor["base_sha"], descriptor["reviewed_sha"]).decode("utf-8").splitlines()
    if actual != names:
        _deny("Reviewed Git diff changes unexpected files")
    if _git(repo, "diff", "--check", descriptor["base_sha"], descriptor["reviewed_sha"]):
        _deny("Patch has invalid whitespace")
    staged = []
    for item in descriptor["changes"]:
        before = _git_blob(repo, descriptor["base_sha"], item["path"])
        after = _git_blob(repo, descriptor["reviewed_sha"], item["path"])
        if _digest(before) != item["base_sha256"] or _digest(after) != item["reviewed_sha256"]:
            _deny("Source blob modified after review approval")
        staged.append((item["path"], after, item["base_sha256"]))
    target = Path(output_dir)
    if (not target.is_absolute() or target.is_symlink() or target.exists() or
            target.parent.resolve(strict=True) != runner):
        _deny("New output must be directly under isolated runner temp")
    worktree = Path(tempfile.mkdtemp(prefix="nf-gated-worktree-", dir=runner))
    worktree.rmdir()
    added = False
    try:
        _git(repo, "worktree", "add", "--detach", str(worktree), descriptor["base_sha"])
        added = True
        for path, data, old_sha in staged:
            dest = worktree / path
            if dest.is_symlink() or not dest.is_file() or _digest(dest.read_bytes()) != old_sha:
                _deny("Isolated source baseline mismatch")
            dest.write_bytes(data)
            if _digest(dest.read_bytes()) != _digest(data):
                _deny("Isolated write was not read back")
        if (_git(worktree, "diff", "--name-only").decode().splitlines() != names or
                _git(worktree, "diff", "--check")):
            _deny("Prepared worktree has unexpected changes")
        patch = _git(worktree, "diff", "--binary", cap=MAX_PATCH + 1)
        if not 50 < len(patch) <= MAX_PATCH:
            _deny("Missing or oversized isolated patch")
        if _git(worktree, "status", "--porcelain").decode().splitlines() != [
                " M " + path for path in names]:
            _deny("Unexpected untracked worktree output")
        manifest = {
            "schema": "nf.selfdev.review_only_bundle.v2",
            "base_sha": descriptor["base_sha"],
            "reviewed_sha": descriptor["reviewed_sha"],
            "draft_id": descriptor["draft_id"],
            "project_id": descriptor["project_id"],
            "model": descriptor["model"],
            "proposal_sha256": evidence_digest,
            "patch_sha256": _digest(patch),
            "modified_paths": names,
            "signature_checked": True,
            "reviewed_source_is_not_model_output": True,
            "source_executed": False,
            "source_published": False,
            "independent_review_complete": False,
            "production_authorized": False,
            "core_queue_or_host_effect_enabled": False,
            "status": "SIGNED_CANDIDATE_PREPARED_NOT_TESTED_NOT_PUBLISHED",
        }
        target.mkdir(mode=0o700)
        try:
            (target / "review_only.patch").write_bytes(patch)
            (target / "manifest.json").write_bytes(_canon(manifest) + b"\n")
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            raise
        return manifest
    finally:
        if added:
            _git(repo, "worktree", "remove", "--force", str(worktree))
        elif worktree.exists():
            shutil.rmtree(worktree, ignore_errors=True)
