"""REVIEW-owned independent exact-SHA security boundary rerun.

Three deliberately small isolated POSIX negative scenarios; no CORE source edits,
no external user project, network, paid API, Ollama or production operations.
Exit 0 means observations match expectations, not security APPROVE.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
from unittest.mock import patch

AUDITED_SHA = "fa92a2eb2d23ce1575da7090444eb6b82b63dee8"
CORE_PATH = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(CORE_PATH))
import one_task_core as core

TARGET = "bridge/neurofactory/development/core_owned/review_only_fixture.txt"
PAYLOAD = "REVIEW_FILE = 73\n"


def fixture():
    temp = tempfile.TemporaryDirectory()
    base = pathlib.Path(temp.name)
    repo = base / "synthetic_git"
    repo.mkdir(mode=0o700)
    for args in [
        ["init", "-q"], ["config", "user.name", "isolated-review"],
        ["config", "user.email", "review@example.invalid"]
    ]:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    (repo / "README.md").write_text("review-only input\n", encoding="utf-8")
    for args in [["add", "README.md"], ["commit", "-qm", "isolated input"]]:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    source_sha = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    root = base / "workspace"
    root.mkdir(mode=0o700)
    q = core.OneTaskCore(root, repo)
    spec = {
        "schema": "neurofactory.core.task.v1",
        "task_id": "NF-DEV-05-Q993",
        "project_id": "review-only",
        "target": TARGET,
        "objective": "Review a locally isolated synthetic file transaction.",
        "source_sha": source_sha,
        "source_sha256": core.EMPTY_SHA,
        "approval_commit": source_sha,
        "model": "qwen2.5-coder:1.5b",
        "reserved_units": 1
    }
    q.enqueue(copy.deepcopy(spec), trusted_approval_check=lambda s: s == spec)
    claim = q.claim("review-worker", now=1000, lease_seconds=200)
    proposal = {
        "schema": "neurofactory.core.proposal.v1",
        "target": TARGET,
        "content": PAYLOAD,
        "content_sha256": hashlib.sha256(PAYLOAD.encode()).hexdigest(),
        "mode": "OFFLINE_TEST"
    }
    return temp, base, q, spec, claim, proposal


def attempt_swap(*, move_original_outside):
    temp, base, q, spec, claim, proposal = fixture()
    try:
        parent = q.sandbox / TARGET.rsplit("/", 1)[0]
        outside = base / "untrusted_outside"
        outside.mkdir(mode=0o700)
        original_replace = core.os.replace
        attempts = []

        def swap_when_os_replace(src, dst, **kwargs):
            if not attempts:
                # Mutation precisely after all original fd checks, before kernel rename.
                # The attacker's premise is ability to rename a private path via same UID.
                if move_original_outside:
                    parked = outside / "moved_parent"
                else:
                    parked = q.sandbox / "parked_parent"
                parent.rename(parked)
                parent.symlink_to(outside, target_is_directory=True)
                attempts.append((parked, kwargs.copy()))
            return original_replace(src, dst, **kwargs)

        failed_closed = False
        with patch.object(core.os, "replace", side_effect=swap_when_os_replace):
            try:
                q.apply_offline_test(spec["task_id"], claim["token"], proposal, now=1001)
            except core.CoreSafetyError:
                failed_closed = True
        assert len(attempts) == 1, "The exact fs mutation boundary was not exercised"
        parked, call_kwargs = attempts[0]
        assert "dst_dir_fd" in call_kwargs and "src_dir_fd" in call_kwargs, (
            "Write was not descriptor-pinned")
        assert failed_closed, "CORE acknowledged success after directory substitution"
        assert not (outside / "review_only_fixture.txt").exists(), (
            "Attacker symlink target unexpectedly received bytes")
        actual_output = parked / "review_only_fixture.txt"
        written = actual_output.exists() and actual_output.read_text() == PAYLOAD
        assert written, "Pinned directory inode did not receive the atomic output"
        assert q.snapshot()["state"] == "APPLYING"
        assert q.recover(now=1201)["state"] == "NEEDS_MANUAL_REVIEW"

        if move_original_outside:
            print("REVIEW_PARENT_RENAME_OUTSIDE=BYTES_WRITTEN_OUTSIDE_AND_STOP")
            print("REVIEW_PARENT_RENAME_THREAT=SAME_UID_CAN_RENAME_OPEN_PARENT")
        else:
            print("REVIEW_ORIGINAL_SYMLINK_SWAP=BLOCKED_NO_EXTERNAL_SYMLINK_WRITE")
        return True
    finally:
        temp.cleanup()


def attempt_forged_receipts():
    temp, base, q, spec, claim, proposal = fixture()
    try:
        q.apply_offline_test(spec["task_id"], claim["token"], proposal, now=1001)
        with sqlite3.connect(q.db) as con:
            row = con.execute("SELECT receipt FROM single_job").fetchone()[0]
            forged = json.loads(row)
            forged["model_invoked"] = True
            forged["review_approved"] = True
            forged["published"] = True
            con.execute("UPDATE single_job SET receipt=? WHERE singleton=1",
                        (json.dumps(forged),))
        rejected = False
        try:
            q.snapshot()
        except core.CoreSafetyError:
            rejected = True
        assert rejected, "CORE trusted forged reviewer/model flags from local SQLite"
        print("REVIEW_FORGED_APPROVAL_FLAGS=REJECTED")
    finally:
        temp.cleanup()

    # Separate boundary: attacker controls BOTH SQLite and the sandbox output.
    # No external signature/monotonic checkpoint is available to detect this.
    temp, base, q, spec, claim, proposal = fixture()
    try:
        q.apply_offline_test(spec["task_id"], claim["token"], proposal, now=1001)
        target = q.sandbox / TARGET
        target.write_text("REVIEW_FILE = 999\n", encoding="utf-8")
        attacker_sha = hashlib.sha256(target.read_bytes()).hexdigest()
        with sqlite3.connect(q.db) as con:
            original = json.loads(con.execute(
                "SELECT receipt FROM single_job").fetchone()[0])
            original["result_sha256"] = attacker_sha
            con.execute("UPDATE single_job SET result_sha256=?, receipt=? WHERE singleton=1",
                        (attacker_sha, json.dumps(original)))
        snapshot = q.snapshot()
        assert snapshot["state"] == "CHECKPOINTED_TEST"
        assert snapshot["result_sha256"] == attacker_sha
        assert q.recover(now=1050)["state"] == "CHECKPOINTED_TEST"
        print("REVIEW_CONSISTENT_LOCAL_DB_AND_FILE_FORGERY=UNDETECTED")
        print("REVIEW_TRUST_BOUNDARY=REQUIRES_INDEPENDENT_OFF_HOST_ATTESTATION")
    finally:
        temp.cleanup()
    return True


def main():
    assert os.name == "posix", "Focused test is POSIX-only; no Windows proof"
    assert len(sys.argv) == 2
    assert attempt_swap(move_original_outside=False)
    assert attempt_forged_receipts()
    assert attempt_swap(move_original_outside=True)
    print("REVIEW_CASES=3/3_EXERCISED")
    print("REVIEW_VERDICT=PARTIAL_FIX_WITH_UNRESOLVED_SAME_UID_AND_DB_TRUST_BOUNDARIES")


if __name__ == "__main__":
    main()
