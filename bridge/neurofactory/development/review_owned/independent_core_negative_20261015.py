"""Independent REVIEW-only two-case negative repro for pinned CORE candidate.
No real Ollama/model calls, no external writes, no reliance on author's assertions.
Only isolated tempfile fixtures are touched.
"""
from __future__ import annotations

import json
import pathlib
import sqlite3
import sys
from unittest.mock import patch

CORE_DIR = pathlib.Path(sys.argv[1]).resolve()
EXPECTED_SHA = "a6677ca6de0f995a297d6f75824e9e8b91ee8de9"
sys.path.insert(0, str(CORE_DIR))
import one_task_core as core
from test_one_task_core import CoreOnceTests, TARGET


def make_fixture():
    case = CoreOnceTests("test_one_file_real_offline_write_and_checkpoint")
    case.setUp()
    return case


def parent_swap_repro():
    case = make_fixture()
    try:
        case.admit()
        claim = case.q.claim("review-race", now=1000, lease_seconds=200)
        outside = case.base / "outside_approved_sandbox"
        outside.mkdir(mode=0o700)
        original_replace = core.os.replace
        swapped = []

        def replace_after_parent_validation(src, dst):
            parent = pathlib.Path(dst).parent
            # Deterministically model an untrusted same-UID path mutation
            # AFTER CORE _file(make_parents=True), BEFORE the atomic replace.
            if not swapped:
                parent.rmdir()
                parent.symlink_to(outside, target_is_directory=True)
                swapped.append(True)
            return original_replace(src, dst)

        with patch.object(core.os, "replace", side_effect=replace_after_parent_validation):
            receipt = case.q.apply_offline_test(
                case.spec["task_id"], claim["token"], case.proposal(), now=1001)
        escaped = outside / pathlib.PurePosixPath(TARGET).name
        vulnerable = (
            bool(swapped)
            and escaped.exists()
            and escaped.read_text(encoding="utf8") == "VALUE = 123\n"
            and case.q.snapshot()["state"] == "CHECKPOINTED_TEST"
            and receipt["model_invoked"] is False
        )
        print("REVIEW_REPRO_PARENT_SWAP=" + ("VULNERABLE" if vulnerable else "NOT_REPRODUCED"))
        print("REVIEW_SCOPE=POSIX_SAME_UID_PARENT_MUTATION_IN_PRIVATE_FIXTURE")
        return vulnerable
    finally:
        case.doCleanups()


def forged_db_receipt_repro():
    case = make_fixture()
    try:
        case.admit()
        claim = case.q.claim("review-receipt", now=1000, lease_seconds=200)
        case.q.apply_offline_test(
            case.spec["task_id"], claim["token"], case.proposal(), now=1001)
        forged = {
            "schema": "neurofactory.core.offline_receipt.v1",
            "task_id": case.spec["task_id"],
            "model_invoked": True,
            "review_approved": True,
            "published": True,
            "attestation": "FORGED_UNTRUSTED_SAME_UID_LOCAL_DB"
        }
        with sqlite3.connect(case.q.db) as connection:
            connection.execute(
                "UPDATE single_job SET receipt=? WHERE singleton=1",
                (json.dumps(forged),))
        snapshot = case.q.snapshot()
        after_recover = case.q.recover(now=1050)
        vulnerable = bool(
            snapshot["receipt"]["review_approved"]
            and snapshot["receipt"]["model_invoked"]
            and after_recover["state"] == "CHECKPOINTED_TEST"
            and after_recover["receipt"]["published"]
        )
        print("REVIEW_REPRO_FORGED_LOCAL_DB_RECEIPT=" +
              ("VULNERABLE" if vulnerable else "NOT_REPRODUCED"))
        print("REVIEW_SCOPE=ATTACKER_HAS_LOCAL_SQLITE_WRITE_NOT_AN_EXTERNAL_SIGNATURE")
        return vulnerable
    finally:
        case.doCleanups()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: independent_negative_core.py <pinned-core-dir>")
    a = parent_swap_repro()
    b = forged_db_receipt_repro()
    print("REVIEW_NEGATIVE_REPROS_TRIGGERED=" + str(int(a) + int(b)) + "/2")
    # Success here means the security counterexamples WERE reproduced.
    raise SystemExit(0 if a and b else 6)
