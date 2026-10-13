"""Verify actual two-agent-published Neurofactory source with repository proof.

Read-only. No GitHub token, no model calls, no tests of external projects.
"""
import hashlib
import json
import pathlib

import real_self_improve as author
import publish_real_improvement as publisher

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "path_policy.py"
PROOF = HERE / "path-policy-verification.json"

def verify():
    if not SOURCE.is_file() or not PROOF.is_file():
        raise ValueError("Neurofactory accepted source or audit receipt absent")
    checkout_bytes = SOURCE.read_bytes()
    # Git for Windows may convert LF into CRLF during checkout; normalize only
    # that reversible platform conversion before checking the signed source.
    data = checkout_bytes.replace(b"\r\n", b"\n")
    if b"\r" in data:
        raise ValueError("Unexpected carriage return in published source")
    receipt = json.loads(PROOF.read_text(encoding="utf-8"))
    required = {
        "stage": "NF-DEV-03",
        "scope": "neurofactory_only",
        "writer": author.WRITER,
        "reviewer": author.REVIEWER,
        "review_verdict": "REVIEW_OK",
        "publication_status": "verified_candidate",
        "github_branch": publisher.BRANCH,
        "file": publisher.TARGET,
    }
    for key, expected in required.items():
        if receipt.get(key) != expected:
            raise ValueError("Invalid independent acceptance proof: " + key)
    if receipt.get("sha256") != hashlib.sha256(data).hexdigest():
        raise ValueError("Published source differs from independently reviewed bytes")
    tested = author.acceptance(data.decode("utf-8"))
    if receipt.get("tests_passed") != tested:
        raise ValueError("Published source acceptance test count mismatch")
    if not publisher.enforce_generated_policy(data):
        raise ValueError("Published security policy blocks its own safe repository files")
    print("NEUROFACTORY_VERIFIED_SOURCE", hashlib.sha256(data).hexdigest())
    print("NEUROFACTORY_INDEPENDENT_AGENTS", author.WRITER, author.REVIEWER)
    print("NEUROFACTORY_REAL_PRODUCTION_PATH_CHECKS", tested)
    return tested

if __name__ == "__main__":
    verify()
