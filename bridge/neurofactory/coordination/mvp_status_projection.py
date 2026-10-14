"""Coordinator-owned projection for UI/OPS: read-only and never a release gate.

Inputs are observations, NOT authorization. Never turn self-reported success into
independent verification, approve, merged, execution or model provenance.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

LANES = ("CORE", "PROVIDERS", "COORDINATOR", "REVIEW", "OPS", "SKILLS", "UI", "HANDOFF", "GODMODE")
PHASES = frozenset(("candidate", "implementation", "testing", "waiting_dependency",
                    "waiting_review", "blocked", "paused"))
GITHUB = re.compile(r"^https://github\.com/DSLitvinov1/(?:my_first_repo|lesson3\.1)/(?:issues|pull)/[1-9][0-9]{0,8}$")
REPO = re.compile(r"^DSLitvinov1/(?:my_first_repo|lesson3\.1)$")
BRANCH = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,180}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
ALLOWED = frozenset(("lane", "repository", "branch", "sha", "issue_url", "phase"))

class InvalidSnapshot(ValueError):
    pass

def projection(observations):
    """Produce bounded user-visible statuses from untrusted, pinned metadata."""
    if not isinstance(observations, list) or len(observations) > len(LANES):
        raise InvalidSnapshot("unexpected observation list")
    output = {lane: {
        "lane": lane, "reported_phase": "unknown", "evidence_status": "not_verified",
        "release_allowed": False, "commit": None, "issue_url": None, "source": None
    } for lane in LANES}
    seen = set()
    for row in observations:
        if not isinstance(row, dict) or set(row) != ALLOWED:
            raise InvalidSnapshot("unknown or missing observation field")
        lane = row["lane"]
        if not isinstance(lane, str) or lane not in output or lane in seen:
            raise InvalidSnapshot("unknown/duplicate lane")
        seen.add(lane)
        repo, branch, sha, url, phase = [row[k] for k in ("repository", "branch", "sha", "issue_url", "phase")]
        if not all(isinstance(x, str) for x in (repo, branch, sha, url, phase)):
            raise InvalidSnapshot("invalid observation type")
        if (not REPO.fullmatch(repo) or not BRANCH.fullmatch(branch) or
                ".." in branch or "//" in branch or not SHA.fullmatch(sha) or
                not GITHUB.fullmatch(url) or phase not in PHASES):
            raise InvalidSnapshot("unsafe, unpinned or unverifiable observation")
        if url.split("/")[3] != repo.split("/")[1]:
            raise InvalidSnapshot("evidence repository mismatch")
        if lane == "HANDOFF" and phase != "paused":
            raise InvalidSnapshot("HANDOFF must remain paused")
        output[lane] = {
            "lane": lane, "reported_phase": phase,
            "evidence_status": "not_verified",
            "release_allowed": False, "commit": sha,
            "issue_url": url, "source": {"repository": repo, "branch": branch}
        }
    return {"schema": 1, "kind": "read_only_coordination_board",
            "provenance": "self_reported_git_refs_not_attested", "cost_authorized_usd": 0,
            "external_execution_allowed": False, "external_publication_allowed": False,
            "automatic_retry_allowed": False, "lanes": list(output.values())}

def _unique_pairs(pairs):
    result={}
    for k,v in pairs:
        if k in result:
            raise InvalidSnapshot("duplicate JSON key")
        result[k]=v
    return result

def read_fixture(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32_768:
        raise InvalidSnapshot("untrusted or oversized fixture")
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f, object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError) as e:
        raise InvalidSnapshot("corrupted fixture") from e

def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate read-only board from candidate snapshot")
    parser.add_argument("snapshot", type=Path)
    args=parser.parse_args(argv)
    print(json.dumps(projection(read_fixture(args.snapshot)),ensure_ascii=False,sort_keys=True,indent=2))

if __name__ == "__main__":
    main()
