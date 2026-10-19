"""CI-only, fail-closed Qwen evidence -> separately approved isolated Git change.

Never executes/patches model text, never touches owner checkout, CORE queue,
SCM, deployment, paid API, skills or repository remotes.  Trusted CI signer
approves an EXACT pair of source digests from pre-reviewed PR #46; user
production signing/host privilege DOES NOT exist in this module.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

BASE_SHA = "23c9464548c137ba75dac3a1ba55af5c5f89b460"
REVIEWED_SHA = "a46b5e48685008f6a556d6b1c2aaeffaa0ad136b"
QWEN_RESPONSE_SHA = "3f7eda7bb0d6f2b50494797947de17454addfdc3b2f146965bd6edbc0da2c35c"
QWEN_EVIDENCE_SHA = "0e805b80696f33d438b005c900c0bb0d0a3c8e985a1936321dc57dd437d43c56"
QWEN_REPORT_SHA = "5f94b0697f22a0d998121254dde07a6ea8cf0de12868148daa882a857a8ae296"
QWEN_PROJECT = "p-5341f60d650a454c92af2ba0045def64"
TASK = "NF-DEV-05-Q953"
ALLOWED = (
    "bridge/neurofactory/one_pc_candidate/signed_owner_admission.py",
    "bridge/neurofactory/one_pc_candidate/test_signed_owner_admission.py",
)
EVIDENCE_FILE = ("nf-signed-qwen-evidence/"
                 "98f769fe2351186369fa1ad619fb38a2660d8fe47417dba21ad39e3d968e45b3.json")
REPORT_FILE = "nf-signed-qwen-report/evidence_summary.json"
MODEL_FILE = "nf-signed-qwen-report/proposal_for_independent_review.txt"
DOMAIN = b"NF_SELFDEV_ISOLATED_REVIEWED_PATCH_V1\x00"
SCOPE = "CI_DISPOSABLE_SIGNED_REVIEWED_PATCH_ONLY_NO_MERGE"
BASE_LIMIT = 1_000_000


class SelfDevDenied(ValueError):
    """Stop without attempting an effect after any mismatch."""


def _fail(reason):
    raise SelfDevDenied(reason)


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _dir(path):
    if (type(path) is not Path or not path.is_absolute() or
            not path.is_dir() or path.is_symlink()):
        _fail("Private explicit nonlinked absolute path required")
    if os.name == "nt" and path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        _fail("Windows reparse point not permitted")
    return path


def _safe_file(root, rel, *, max_bytes=BASE_LIMIT):
    if (type(rel) is not str or rel.startswith("/") or
            "\\" in rel or ":" in rel or "\x00" in rel or
            any(x in ("", ".", "..") or x.startswith(".")
                for x in rel.split("/"))):
        _fail("Unsafe relative evidence or source path")
    current = _dir(root)
    for piece in rel.split("/")[:-1]:
        current = current / piece
        if current.is_symlink() or not current.is_dir():
            _fail("Symlink or missing parent directory")
        if os.name == "nt" and current.stat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            _fail("Windows evidence path reparse point")
    path = current / rel.split("/")[-1]
    if path.is_symlink() or not path.is_file():
        _fail("Symlinked or missing file")
    s = path.stat()
    if not stat.S_ISREG(s.st_mode) or not 0 < s.st_size <= max_bytes:
        _fail("Incorrect file type or size")
    if os.name == "nt" and s.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        _fail("Windows file reparse point")
    raw = path.read_bytes()
    if len(raw) != s.st_size:
        _fail("Evidence file changed while being read")
    return raw


def _json_unique(pairs):
    obj = {}
    for key, val in pairs:
        if key in obj:
            _fail("Duplicated JSON field")
        obj[key] = val
    return obj


def _read_json(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_json_unique)
    except (ValueError, UnicodeError, TypeError, OverflowError) as exc:
        raise SelfDevDenied("Invalid JSON evidence") from exc


def inspect_original_qwen_evidence(evidence_root):
    """Read real archived Q953 evidence; an attached .seal is not external attest."""
    root = _dir(evidence_root)
    report_raw = _safe_file(root, REPORT_FILE, max_bytes=8_000)
    model_raw = _safe_file(root, MODEL_FILE, max_bytes=12_000)
    evidence_raw = _safe_file(root, EVIDENCE_FILE, max_bytes=16_000)
    seal_raw = _safe_file(root, EVIDENCE_FILE + ".seal", max_bytes=128)
    if (_sha(report_raw) != QWEN_REPORT_SHA or
            _sha(model_raw) != QWEN_RESPONSE_SHA or
            _sha(evidence_raw) != QWEN_EVIDENCE_SHA or
            seal_raw != (QWEN_EVIDENCE_SHA + "\n").encode("ascii")):
        _fail("Pinned Qwen evidence or local receipt seal mismatch")
    report = _read_json(report_raw)
    evidence = _read_json(evidence_raw)
    if (type(report) is not dict or
            report.get("schema") != "nf.ci.signed_real_qwen_selfdev.v1" or
            report.get("core_task_id") != TASK or
            report.get("core_project_id") != QWEN_PROJECT or
            report.get("core_state_after_proposal") != "QUEUED" or
            report.get("requested_model") != "qwen2.5-coder:1.5b" or
            report.get("signed_admission_accepted") is not True or
            report.get("status") != "PROPOSED_UNVERIFIED_REVIEW_ONLY" or
            report.get("model_second_attempt") != "BLOCKED" or
            report.get("source_applied") is not False or
            report.get("host_effect_performed") is not False or
            report.get("review_approved") is not False or
            report.get("production_queue_enabled") is not False or
            report.get("independent_review_complete") is not False or
            report.get("proposal_sha256") != QWEN_RESPONSE_SHA or
            report.get("provider_evidence_sha256") != QWEN_EVIDENCE_SHA):
        _fail("Qwen report metadata cannot authorize a patch")
    if (type(evidence) is not dict or
            evidence.get("schema") != "neurofactory.providers.evidence.v1" or
            evidence.get("task_id") != TASK or
            evidence.get("project_id") != QWEN_PROJECT or
            evidence.get("model") != "qwen2.5-coder:1.5b" or
            evidence.get("transport_claim") != "ollama-ipv4-loopback" or
            evidence.get("offline_mock_claim") is not False or
            evidence.get("response_sha256") != QWEN_RESPONSE_SHA or
            evidence.get("response_text") != model_raw.decode("utf-8") or
            evidence.get("independent_provenance_verified") is not False or
            evidence.get("review_approved") is not False or
            evidence.get("source_applied") is not False or
            evidence.get("published") is not False):
        _fail("Qwen record does not match explicitly untrusted model answer")
    # The unsafe original suggestion must be REVIEWED, not executed.
    model_text = model_raw.decode("utf-8")
    unsafe = all(x in model_text for x in ("re.IGNORECASE", "raise ValueError", "    pass"))
    if not unsafe:
        _fail("Unexpected model text; human rejection basis no longer matches")
    return {
        "evidence_sha256": QWEN_EVIDENCE_SHA,
        "response_sha256": QWEN_RESPONSE_SHA,
        "model": "qwen2.5-coder:1.5b",
        "project_id": QWEN_PROJECT,
        "task_id": TASK,
        "model_patch_applied": False,
        "unsafe_model_code_rejected": True,
        "independent_review": False,
    }


def _git(repo, *args, max_bytes=200_000):
    if not all(type(a) is str and "\x00" not in a for a in args):
        _fail("Invalid literal Git command")
    done = subprocess.run(
        ["git", "-C", str(_dir(repo)), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=45)
    if done.returncode or len(done.stdout) > max_bytes:
        _fail("Isolated Git operation failed")
    return done.stdout.decode("utf-8", errors="strict").rstrip("\r\n")


def make_reviewed_descriptor(base_repo, reviewed_repo, qwen):
    """Pin reviewed PR #46 Git sources, exact two approved paths, no model patch."""
    base = _dir(base_repo)
    reviewed = _dir(reviewed_repo)
    if (_git(base, "rev-parse", "HEAD") != BASE_SHA or
            _git(reviewed, "rev-parse", "HEAD") != REVIEWED_SHA):
        _fail("Git source revision does not match approved head")
    diff_names = _git(reviewed, "diff", "--name-only", BASE_SHA, REVIEWED_SHA)
    expected_reviewed_diff = set(ALLOWED) | {
        ".github/workflows/neurofactory-onepc-project-uuid-guard-ci.yml"
    }
    if (set(diff_names.splitlines()) != expected_reviewed_diff or
            len(diff_names.splitlines()) != 3):
        _fail("Reviewed PR touches unapproved files")
    if _git(reviewed, "diff", "--check", BASE_SHA, REVIEWED_SHA):
        _fail("Reviewed PR diff has whitespace errors")
    changes = []
    for rel in ALLOWED:
        original = _safe_file(base, rel)
        reviewed_bytes = _safe_file(reviewed, rel)
        if original == reviewed_bytes:
            _fail("Approved patch must actually change target")
        if b"re.IGNORECASE" in reviewed_bytes or re.search(rb"(?m)^\s*pass\s*$", reviewed_bytes):
            _fail("Unsafe Qwen shortcut or placeholder detected in reviewed source")
        changes.append({"path": rel, "base_sha256": _sha(original),
                        "reviewed_sha256": _sha(reviewed_bytes)})
    return {
        "schema": "nf.selfdev.reviewed_change_descriptor.v1",
        "base_git_sha": BASE_SHA,
        "reviewed_git_sha": REVIEWED_SHA,
        "project_id": qwen["project_id"],
        "model_evidence_sha256": qwen["evidence_sha256"],
        "model_response_sha256": qwen["response_sha256"],
        "changes": changes,
        "scope": SCOPE,
        "force_false": True,
    }


def verify_reviewed_permit(permit, expected, pinned_authority_public_raw, *, now=None):
    """Signer is *separately supplied* trusted CI authority, NOT a model or browser."""
    if type(permit) is not dict or set(permit) != {
        "schema", "scope", "descriptor", "nonce", "issued_at", "expires_at", "signature"
    }:
        _fail("Unrecognized approval envelope")
    now = int(time.time()) if now is None else now
    if (type(now) is not int or now < 0 or
            permit["schema"] != "nf.selfdev.reviewed_patch_permit.v1" or
            permit["scope"] != SCOPE or
            permit["descriptor"] != expected or
            type(permit["nonce"]) is not str or not
            re.fullmatch(r"[a-f0-9]{32}", permit["nonce"]) or
            type(permit["issued_at"]) is not int or
            type(permit["expires_at"]) is not int or
            not permit["issued_at"] <= now < permit["expires_at"] or
            not 0 < permit["expires_at"] - permit["issued_at"] <= 300 or
            type(pinned_authority_public_raw) is not bytes or
            len(pinned_authority_public_raw) != 32 or
            type(permit["signature"]) is not str):
        _fail("Approval issuer, expiry, project or scope invalid")
    import base64
    import binascii
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        signature = base64.b64decode(permit["signature"], validate=True)
        if len(signature) != 64:
            _fail("Incorrect Ed25519 signature size")
        body = {key: val for key, val in permit.items() if key != "signature"}
        Ed25519PublicKey.from_public_bytes(pinned_authority_public_raw).verify(
            signature, DOMAIN + _canon(body))
    except (ValueError, TypeError, InvalidSignature, binascii.Error) as exc:
        raise SelfDevDenied("Owner-approved disposable patch signature rejected") from exc
    return True


def prepare_isolated_worktree(base_repo, reviewed_repo, worktree_path,
                              expected_descriptor, permit, trusted_public_raw,
                              *, evidence_root, report_out):
    """Write ONLY to an ephemeral isolated Git worktree after verified CI permit.

    Caller has already pinned two exact Git checkouts, model evidence digest,
    and an external authority public key. Never pushes a branch or merges PR.
    """
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("NF_SELFDEV_ISOLATED_CI_ONLY") != "1"):
        _fail("Disposable Windows GitHub-hosted test exclusively")
    _dir(base_repo)
    _dir(reviewed_repo)
    out = _dir(report_out)
    if (type(worktree_path) is not Path or not worktree_path.is_absolute() or
            worktree_path.exists() or worktree_path.is_symlink() or
            worktree_path.parent != out.parent):
        _fail("Worktree must be new isolated sibling of CI-only report directory")
    qwen = inspect_original_qwen_evidence(evidence_root)
    fresh = make_reviewed_descriptor(base_repo, reviewed_repo, qwen)
    if fresh != expected_descriptor:
        _fail("Source, Qwen evidence or reviewed patch changed")
    verify_reviewed_permit(permit, fresh, trusted_public_raw)
    if _git(base_repo, "status", "--porcelain"):
        _fail("Source checkout is not pristine")
    # worktree add changes only disposable Git checkout's local .git metadata,
    # never user/host files; neither source repo nor target app is overwritten.
    _git(base_repo, "worktree", "add", "--detach", str(worktree_path), BASE_SHA)
    worktree = _dir(worktree_path)
    # Keep even failed worktree local/unpublished; no automatic retry.
    _git(worktree, "switch", "-c", "nf-isolated-reviewed-pr46-ci-only")
    for change in fresh["changes"]:
        rel = change["path"]
        src = _safe_file(reviewed_repo, rel)
        target = worktree / rel
        if _sha(_safe_file(worktree, rel)) != change["base_sha256"]:
            _fail("Unexpected modified destination preimage")
        if _sha(src) != change["reviewed_sha256"]:
            _fail("Reviewed candidate bytes differ from permit")
        with target.open("wb") as dest:
            dest.write(src)
            dest.flush()
            os.fsync(dest.fileno())
        if _sha(_safe_file(worktree, rel)) != change["reviewed_sha256"]:
            _fail("Isolated destination readback mismatch")
    modified = _git(worktree, "diff", "--name-only")
    if set(modified.splitlines()) != set(ALLOWED):
        _fail("Isolated patch wrote outside explicit approved path set")
    if _git(worktree, "diff", "--check"):
        _fail("Isolated candidate has invalid whitespace")
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    python = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover",
         "-s", "bridge/neurofactory/one_pc_candidate",
         "-p", "test_signed_owner_admission.py", "-v"],
        cwd=worktree, env=env, capture_output=True, timeout=100,
        check=False, text=True)
    if python.returncode or "Ran 9 tests" not in python.stderr or "\nOK" not in python.stderr:
        _fail("Real CORE/SQLite signed owner 9-test Windows regression did not pass")
    if set(_git(worktree, "status", "--porcelain").splitlines()) != {
            " M " + ALLOWED[0], " M " + ALLOWED[1]}:
        _fail("Regression left unexpected source changes")
    _git(worktree, "add", "--", *ALLOWED)
    _git(worktree, "-c", "user.name=NF isolated CI",
         "-c", "user.email=ci@example.invalid", "commit", "-qm",
         "DRAFT CI-only reviewed lowercase UUID guard and SQLite regression")
    created = _git(worktree, "rev-parse", "HEAD")
    changed = _git(worktree, "diff-tree", "--no-commit-id", "--name-only",
                   "-r", "HEAD").splitlines()
    if set(changed) != set(ALLOWED) or len(changed) != 2:
        _fail("Final isolated commit contains unexpected paths")
    patch = subprocess.run(
        ["git", "-C", str(worktree), "format-patch", "-1", "--stdout"],
        capture_output=True, timeout=20, check=False)
    if patch.returncode or not 500 <= len(patch.stdout) <= 100_000:
        _fail("Isolated patch export invalid")
    patch_file = out / "REVIEW_ONLY_isolated_pr46_candidate.patch"
    with patch_file.open("xb") as stream:
        stream.write(patch.stdout)
        stream.flush()
        os.fsync(stream.fileno())
    summary = {
        "schema": "nf.selfdev.isolated_git_review_candidate.v1",
        "status": "TESTED_ISOLATED_DRAFT_UNAPPROVED",
        "project_id": QWEN_PROJECT,
        "model_input_task": TASK,
        "model_evidence_sha256": QWEN_EVIDENCE_SHA,
        "model_response_sha256": QWEN_RESPONSE_SHA,
        "unsafe_qwen_model_patch_rejected": True,
        "reviewed_not_model_patch_source_git_sha": REVIEWED_SHA,
        "source_base_git_sha": BASE_SHA,
        "isolated_local_commit": created,
        "only_modified_paths": list(ALLOWED),
        "test_count": 9,
        "test_environment": "TEMP_WINDOWS_GITHUB_HOSTED",
        "ci_ephemeral_signature_verified": True,
        "independent_reviewer_approved": False,
        "owner_production_authority": False,
        "published_remote_branch": False,
        "github_pr_created_by_ci": False,
        "model_applied_patch": False,
        "host_effect_performed": False,
        "production_queue_enabled": False,
        "full_disk_rollback_fence": False,
        "installer_retested": False,
        "new_model_inference_called": False,
        "isolated_patch_sha256": _sha(patch.stdout),
    }
    raw = _canon(summary) + b"\n"
    with (out / "REVIEW_ONLY_isolated_pr_manifest.json").open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    pr_text = (
        "DRAFT PR ONLY — NOT MERGED OR OWNER-AUTHORIZED\n"
        "Base: " + BASE_SHA + "\nReviewed candidate: " + REVIEWED_SHA + "\n"
        "Source model: Qwen2.5 Coder 1.5B; evidence " + QWEN_RESPONSE_SHA + "\n"
        "WARNING: the original model patch was unsafe and REJECTED.\n"
        "Separate reviewed candidate copied only into disposable Git worktree.\n"
        "Windows targeted real SQLite + owner-signature tests: 9/9 passed.\n"
        "PR must be created via separately authenticated GitHub connector, "
        "remain DRAFT and be independently reviewed before any merge.\n"
        "NO HOST or user-PC installation, NO SKILLS, NO LIVE, NO MODEL REPLAY.\n"
    )
    (out / "REVIEW_ONLY_pr_description.txt").write_text(
        pr_text, encoding="utf-8", newline="\n")
    return summary
