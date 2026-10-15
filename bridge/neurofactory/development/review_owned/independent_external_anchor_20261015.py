"""REVIEW-only narrow external-anchor negatives on pinned CORE SHA.

No model calls, no external project writes, no CORE source modifications.
Only synthetic temporary Git and SQLite/files.  This does NOT attest any real host.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

EXPECTED_CORE_SHA = "ef8ce6acc64ac1d4ad2c8e8018e67e28b8549fe3"
sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
import one_task_core as core

TARGET = "bridge/neurofactory/development/core_owned/review_anchor_fixture.txt"
CONTENT = "REVIEW_CHECK = 1\n"


def run_git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args],
                                   stderr=subprocess.PIPE, text=True).strip()


def prepare(base):
    repository = base / "synthetic_git"
    repository.mkdir(mode=0o700)
    run_git(repository, "init", "-q")
    run_git(repository, "config", "user.name", "review-only")
    run_git(repository, "config", "user.email", "review@example.invalid")
    (repository / "README.md").write_text("isolated fixture\n", encoding="utf8")
    run_git(repository, "add", "README.md")
    run_git(repository, "commit", "-qm", "review-only")
    sha = run_git(repository, "rev-parse", "HEAD")
    work = base / "work"
    work.mkdir(mode=0o700)
    q = core.OneTaskCore(work, repository)
    spec = {
        "schema": "neurofactory.core.task.v1",
        "task_id": "NF-DEV-05-Q994",
        "project_id": "review-anchor",
        "target": TARGET,
        "objective": "Review an external checkpoint digest using synthetic local files.",
        "source_sha": sha,
        "source_sha256": core.EMPTY_SHA,
        "model": "qwen2.5-coder:1.5b",
        "reserved_units": 1,
        "approval_commit": sha
    }
    q.enqueue(copy.deepcopy(spec), trusted_approval_check=lambda d: d == spec)
    claim = q.claim("independent-review", now=1000, lease_seconds=200)
    proposal = {"schema": "neurofactory.core.proposal.v1",
                "target": TARGET, "content": CONTENT,
                "content_sha256": hashlib.sha256(CONTENT.encode()).hexdigest(),
                "mode": "OFFLINE_TEST"}
    q.apply_offline_test(spec["task_id"], claim["token"], proposal, now=1001)
    return q


def must_reject(q, fingerprint, case):
    try:
        q.check_external_checkpoint(fingerprint)
    except core.CoreSafetyError:
        print(case + "=REJECTED")
        return
    raise AssertionError(case + " unexpectedly accepted")


def main():
    if os.name != "posix":
        raise RuntimeError("Only isolated POSIX fixture; no Windows proof")
    with tempfile.TemporaryDirectory() as p:
        q = prepare(Path(p))
        pinned_before = q.checkpoint_fingerprint()
        must_reject(q, None, "REVIEW_MISSING_ANCHOR")
        must_reject(q, "0" * 64, "REVIEW_MISMATCHED_ANCHOR")

        initially_matched = q.check_external_checkpoint(pinned_before)
        assert initially_matched["matches_supplied_external_digest"] is True
        assert initially_matched["external_origin_attested"] is False
        assert initially_matched["execution_allowed"] is False
        print("REVIEW_GENUINE_LOCAL_DIGEST=ONLY_UNATTESTED_COMPARISON")

        # The adversary is assumed to possess same-principal write access to
        # BOTH the output and the local SQLite. That is NOT cross-user access.
        path = q.sandbox / TARGET
        path.write_text("REVIEW_CHECK = FORGED\n", encoding="utf8")
        forged_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        with sqlite3.connect(q.db) as db:
            receipt = json.loads(db.execute(
                "SELECT receipt FROM single_job").fetchone()[0])
            receipt["result_sha256"] = forged_sha
            db.execute("UPDATE single_job SET result_sha256=?,receipt=? WHERE singleton=1",
                       (forged_sha, json.dumps(receipt)))

        # Source-of-truth digest genuinely pinned BEFORE alteration is useful.
        must_reject(q, pinned_before, "REVIEW_COHERENT_FORGERY_OLD_EXTERNAL_ANCHOR")
        assert q.snapshot()["state"] == "CHECKPOINTED_TEST"

        # Without external authenticated storage, an attacker can submit
        # their newly calculated matching digest. No origin claim may result.
        forged_local = q.checkpoint_fingerprint()
        assert forged_local != pinned_before
        recomputed = q.check_external_checkpoint(forged_local)
        assert recomputed["matches_supplied_external_digest"] is True
        assert recomputed["external_origin_attested"] is False
        assert recomputed["review_approved"] is False
        assert recomputed["model_invoked"] is False
        assert recomputed["published"] is False
        assert recomputed["execution_allowed"] is False
        print("REVIEW_ATTACKER_RECOMPUTED_ANCHOR=ACCEPTED_AS_UNATTESTED_ONLY")
        print("REVIEW_EXTERNAL_SIGNER_STORAGE=NOT_IMPLEMENTED")
        print("REVIEW_RESULT=ANCHOR_COMPARISON_WORKS_WITH_TRUSTED_EXTERNAL_PIN_NOT_PROVENANCED")


if __name__ == "__main__":
    main()
