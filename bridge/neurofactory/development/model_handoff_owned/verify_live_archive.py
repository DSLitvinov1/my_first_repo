"""Read-only verifier of one exact HANDOFF GitHub Actions evidence archive.

Only proves internal consistency of the archive. Independent REVIEW owner approval,
GitHub-run provenance and verified publishing receipts remain separate requirements.
"""
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

from model_handoff_owned import handoff_gate as gate

MEMBERS = (
    "NF-DEV-05-Q090/candidate.json",
    "NF-DEV-05-Q090/review.json",
    "NF-DEV-05-Q090/handoff.json",
    "candidate_review-response-1.json",
    "checkpoint.json",
    "module_review-response-1.json",
    "module_review.json",
    "summary.json",
)
MAX_ARCHIVE = 350000
MAX_MEMBER = 40000
TASK = "NF-DEV-05-Q090"

class ArtifactError(ValueError):
    pass

def _json(raw):
    def no_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ArtifactError("Duplicate key in evidence")
            out[key] = value
        return out
    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=no_duplicates)
    except (UnicodeError, TypeError, ValueError) as exc:
        raise ArtifactError("Invalid JSON evidence") from exc

def verify_archive(path, expected_candidate_sha, expected_module_sha):
    if not isinstance(expected_candidate_sha, str) or not isinstance(expected_module_sha, str):
        raise ArtifactError("Expected independent digests required")
    for item in (expected_candidate_sha, expected_module_sha):
        if len(item) != 64 or any(c not in "0123456789abcdef" for c in item):
            raise ArtifactError("Expected SHA256 must be exact")
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_ARCHIVE:
        raise ArtifactError("Missing or oversized evidence archive")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [x.filename for x in entries]
        if len(names) != len(set(names)) or set(names) != set(MEMBERS):
            raise ArtifactError("Incomplete, duplicate or foreign archive entries")
        if any(x.is_dir() or x.file_size > MAX_MEMBER or x.flag_bits & 1
               for x in entries):
            raise ArtifactError("Oversized or encrypted evidence")
        raw = {name: archive.read(name) for name in MEMBERS}
    d = {name: _json(value) for name, value in raw.items()}
    candidate = d[MEMBERS[0]]
    review = d[MEMBERS[1]]
    dossier = d[MEMBERS[2]]
    writer_response = d[MEMBERS[3]]
    checkpoint = d[MEMBERS[4]]
    module_response = d[MEMBERS[5]]
    module_review = d[MEMBERS[6]]
    summary = d[MEMBERS[7]]
    try:
        gate.validate_packet(candidate)
        gate.validate_review(candidate, review)
        gate.verify_dossier(candidate, review, dossier)
    except gate.HandoffError as exc:
        raise ArtifactError("HANDOFF evidence integrity failed") from exc
    if (candidate["task_id"] != TASK or
            candidate["candidate_sha256"] != expected_candidate_sha or
            hashlib.sha256(candidate["candidate"].encode("utf-8")).hexdigest() != expected_candidate_sha):
        raise ArtifactError("Candidate source differs from independently expected SHA256")
    if review["verdict"] != "APPROVE":
        raise ArtifactError("Qwen3 did not explicitly approve the candidate")
    for data, phase, expected in ((writer_response, "candidate_review", expected_candidate_sha),
                                  (module_response, "module_review", expected_module_sha)):
        if (data.get("model") != gate.REVIEWER or
                data.get("phase") != phase or
                data.get("attempt") != 1 or
                data.get("publication_enabled") is not False or
                data.get("subject_sha256") != expected):
            raise ArtifactError("Raw model reply origin/digest mismatch")
    try:
        writer_object = gate.strict_object(writer_response["raw_model_reply"])
        module_object = gate.strict_object(module_response["raw_model_reply"])
    except (gate.HandoffError, KeyError, TypeError) as exc:
        raise ArtifactError("Raw Qwen3 reply malformed") from exc
    if (writer_object != {"verdict": review["verdict"],
                          "candidate_sha256": expected_candidate_sha,
                          "findings": review["findings"]}):
        raise ArtifactError("Processed candidate verdict differs from raw Qwen3 response")
    if (module_object.get("verdict") != "APPROVE" or
            module_object.get("candidate_sha256") != expected_module_sha or
            module_review.get("verdict") != "APPROVE" or
            module_review.get("source_sha256") != expected_module_sha or
            module_review.get("findings") != module_object.get("findings") or
            module_review.get("release_authorized") is not False):
        raise ArtifactError("Module audit is not a source-bound Qwen3 approval")
    if (summary.get("task_id") != TASK or
            summary.get("candidate_sha256") != expected_candidate_sha or
            summary.get("module_sha256") != expected_module_sha or
            summary.get("candidate_verdict") != "APPROVE" or
            summary.get("module_verdict") != "APPROVE" or
            summary.get("publication_count") != 0 or
            summary.get("release_authorized") is not False):
        raise ArtifactError("Summary does not match checked evidence")
    if summary.get("writer", {}).get("model") != gate.WRITER or summary.get("reviewer", {}).get("model") != gate.REVIEWER:
        raise ArtifactError("Two different approved local models not confirmed")
    for field, name in (("candidate.json", MEMBERS[0]), ("review.json", MEMBERS[1]),
                        ("handoff.json", MEMBERS[2])):
        if summary.get("evidence_hashes", {}).get(field) != hashlib.sha256(raw[name]).hexdigest():
            raise ArtifactError("Saved evidence raw bytes differ from handoff receipt")
    if (checkpoint.get("stage") != "awaiting_review_owner" or
            checkpoint.get("candidate_sha256") != expected_candidate_sha or
            checkpoint.get("module_sha256") != expected_module_sha or
            checkpoint.get("publication_enabled") is not False or
            checkpoint.get("publisher_enabled") is not False or
            checkpoint.get("branch") != gate.BRANCH or
            checkpoint.get("task_id") != TASK):
        raise ArtifactError("Release gate or checkpoint not sealed")
    return {"evidence_consistent": True, "candidate_sha256": expected_candidate_sha,
            "module_sha256": expected_module_sha, "reviewer_model": gate.REVIEWER,
            "independent_review_owner": "PENDING",
            "publication_allowed": False, "publication_count": 0,
            "files": len(MEMBERS)}

if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("Expected archive path and two trusted SHA256 digests")
    try:
        print(json.dumps(verify_archive(sys.argv[1], sys.argv[2], sys.argv[3]),
                         ensure_ascii=False))
    except (OSError, zipfile.BadZipFile, ArtifactError) as error:
        print("HANDOFF_ARCHIVE_REJECTED:", str(error), file=sys.stderr)
        raise SystemExit(1)
