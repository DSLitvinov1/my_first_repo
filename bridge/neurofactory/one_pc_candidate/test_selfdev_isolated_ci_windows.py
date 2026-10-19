"""Windows CI gates for quarantined original Qwen evidence and trusted reviewed diff.

No real owner key or PR token, no Ollama API, no installer, no Git remote push.
Ephemeral CI signature grants only the local disposable worktree write.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from selfdev_isolated_worktree import (
    BASE_SHA, REVIEWED_SHA, QWEN_RESPONSE_SHA, QWEN_EVIDENCE_SHA,
    QWEN_PROJECT, SCOPE, DOMAIN, _canon, _dir, _git, SelfDevDenied,
    inspect_original_qwen_evidence, make_reviewed_descriptor,
    verify_reviewed_permit, prepare_isolated_worktree,
)


def assert_denied(fn, *, reason):
    try:
        fn()
    except SelfDevDenied:
        print("NF_SELFDEV_ISOLATION_NEGATIVE_" + reason + "=DENIED")
        return
    raise RuntimeError("Security negative case accepted: " + reason)


def signed_permit(signer, descriptor, *, now=None, nonce=None):
    now = int(time.time()) if now is None else now
    body = {
        "schema": "nf.selfdev.reviewed_patch_permit.v1",
        "scope": SCOPE,
        "descriptor": descriptor,
        "nonce": os.urandom(16).hex() if nonce is None else nonce,
        "issued_at": now - 2,
        "expires_at": now + 240,
    }
    signature = signer.sign(DOMAIN + _canon(body))
    return {**body, "signature": base64.b64encode(signature).decode("ascii")}


def main():
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("NF_SELFDEV_ISOLATED_CI_ONLY") != "1"):
        raise RuntimeError("Disposable GitHub-hosted Windows action required")
    root = _dir(Path(os.environ["NF_SELFDEV_QWEN_EVIDENCE"]))
    base = _dir(Path(os.environ["NF_SELFDEV_BASE_REPO"]))
    reviewed = _dir(Path(os.environ["NF_SELFDEV_REVIEWED_REPO"]))
    report_dir = _dir(Path(os.environ["NF_SELFDEV_REPORT_DIR"]))
    worktree = report_dir.parent / "nf-disposable-isolated-source"
    if worktree.exists():
        raise RuntimeError("No reuse of previous isolated worktree")

    original_sha = {
        rel: sha256((base / rel).read_bytes()).hexdigest()
        for rel in (
            "bridge/neurofactory/one_pc_candidate/signed_owner_admission.py",
            "bridge/neurofactory/one_pc_candidate/test_signed_owner_admission.py",
        )
    }
    evidence = inspect_original_qwen_evidence(root)
    assert evidence["unsafe_model_code_rejected"] is True
    assert evidence["model_patch_applied"] is False
    descriptor = make_reviewed_descriptor(base, reviewed, evidence)
    assert descriptor["base_git_sha"] == BASE_SHA
    assert descriptor["reviewed_git_sha"] == REVIEWED_SHA
    assert descriptor["project_id"] == QWEN_PROJECT
    assert descriptor["model_response_sha256"] == QWEN_RESPONSE_SHA
    assert descriptor["model_evidence_sha256"] == QWEN_EVIDENCE_SHA
    print("NF_SELFDEV_QWEN_ORIGINAL_SEALED_EVIDENCE=VERIFIED_REVIEW_ONLY")
    print("NF_SELFDEV_QWEN_UNSAFE_CODE=REJECTED_NO_APPLY")

    # Explicitly CI-only authority created *outside* production/imported module.
    ephemeral = Ed25519PrivateKey.generate()
    pub = ephemeral.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw)
    permit = signed_permit(ephemeral, descriptor)
    now = int(time.time())
    assert verify_reviewed_permit(permit, descriptor, pub, now=now)
    fake = Ed25519PrivateKey.generate()
    fake_sig = signed_permit(fake, descriptor)
    assert_denied(lambda: verify_reviewed_permit(fake_sig, descriptor, pub, now=now),
                  reason="FORGED_SIGNER")
    altered = {**descriptor, "project_id": "p-" + "f" * 32}
    assert_denied(lambda: verify_reviewed_permit(permit, altered, pub, now=now),
                  reason="FOREIGN_PROJECT")
    forged_files = {**descriptor, "changes": descriptor["changes"] + [{
        "path": "../../Windows/System32/evil.py",
        "base_sha256": "0" * 64, "reviewed_sha256": "1" * 64
    }]}
    assert_denied(lambda: verify_reviewed_permit(
        signed_permit(ephemeral, forged_files), descriptor, pub, now=now),
        reason="AUTHORIZED_EXTRA_PATH")
    expired = {**permit, "issued_at": now - 900, "expires_at": now - 700}
    assert_denied(lambda: verify_reviewed_permit(expired, descriptor, pub, now=now),
                  reason="EXPIRED_PERMIT")
    bad_commit = {**descriptor, "reviewed_git_sha": "0" * 40}
    assert_denied(lambda: verify_reviewed_permit(
        signed_permit(ephemeral, bad_commit), descriptor, pub, now=now),
        reason="OTHER_SOURCE_COMMIT")
    assert not worktree.exists()

    # Prove a tampered raw Qwen response in a separate artifact directory
    # does not satisfy the pinned SHA even when its local seal is untouched.
    mutated = report_dir.parent / "nf-tampered-qwen-evidence"
    shutil.copytree(root, mutated)
    qwen_file = mutated / "nf-signed-qwen-report/proposal_for_independent_review.txt"
    qwen_file.write_bytes(qwen_file.read_bytes() + b"\n# attacker-added approval")
    assert_denied(lambda: inspect_original_qwen_evidence(mutated),
                  reason="TAMPERED_QWEN_BYTES")
    shutil.rmtree(mutated)

    # Positive: a verified, EXACT reviewed PR46 diff is copied only to
    # a disposable worktree and tested using real existing CORE SQLite.
    result = prepare_isolated_worktree(
        base, reviewed, worktree, descriptor, permit, pub,
        evidence_root=root, report_out=report_dir)
    assert result["status"] == "TESTED_ISOLATED_DRAFT_UNAPPROVED"
    assert result["test_count"] == 9
    assert result["unsafe_qwen_model_patch_rejected"] is True
    assert result["github_pr_created_by_ci"] is False
    assert result["production_queue_enabled"] is False
    assert result["model_applied_patch"] is False
    assert result["host_effect_performed"] is False
    assert result["owner_production_authority"] is False
    assert len(result["only_modified_paths"]) == 2
    assert len(result["isolated_local_commit"]) == 40
    assert _git(worktree, "status", "--porcelain") == ""
    assert _git(base, "rev-parse", "HEAD") == BASE_SHA
    assert _git(base, "status", "--porcelain") == ""
    for rel, baseline_sha in original_sha.items():
        assert sha256((base / rel).read_bytes()).hexdigest() == baseline_sha
        assert sha256((worktree / rel).read_bytes()).hexdigest() != baseline_sha
    patch_path = report_dir / "REVIEW_ONLY_isolated_pr46_candidate.patch"
    assert patch_path.stat().st_size > 500
    assert sha256(patch_path.read_bytes()).hexdigest() == result["isolated_patch_sha256"]
    print("NF_SELFDEV_REAL_WINDOWS_ISOLATED_WORKTREE=PASS")
    print("NF_SELFDEV_REVIEWED_PATCH_REAL_SQLITE_9_TESTS=PASS")
    print("NF_SELFDEV_CI_SIGNED_EXACT_SCOPE=PASS")
    print("NF_SELFDEV_AUTOMATIC_PR_PACKAGE=PREPARED_NOT_PUBLISHED")
    print("NF_SELFDEV_GIT_BASE_SOURCE=UNCHANGED")
    print("NF_SELFDEV_ISOLATED_COMMIT=" + result["isolated_local_commit"])
    print("NF_SELFDEV_PATCH_SHA256=" + result["isolated_patch_sha256"])
    print("NF_SELFDEV_NO_MODEL_INFERENCE_REPEAT=PASS")

    # Clean up the temporary checked-out file tree, retain only review bundle.
    _git(base, "worktree", "remove", "--force", str(worktree))
    assert not worktree.exists()
    assert _git(base, "status", "--porcelain") == ""
    print("NF_SELFDEV_DISPOSABLE_WORKTREE_CLEANED=PASS")


if __name__ == "__main__":
    main()
