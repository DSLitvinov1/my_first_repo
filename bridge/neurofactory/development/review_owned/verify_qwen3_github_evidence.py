"""Independent REVIEW-owned verifier of GitHub-bound Qwen3 source audit.

The HANDOFF model response is untrusted. A verdict is never a merge/publish
authorization, even when its source checksum and public GitHub metadata match.
This module has NO write/merge/publish operations and needs no model access.
"""
import hashlib
import io
import json
import re
import stat
import zipfile

REPO = "DSLitvinov1/my_first_repo"
BRANCH = "neurofactory-model-handoff-owned-20261013"
WORKFLOW = ".github/workflows/neurofactory-handoff-owned-qwen3-remediation.yml"
MODEL = "qwen3:4b"
EXPECTED_MEMBERS = frozenset(("request.json", "ollama-response.json",
                              "result.json", "checkpoint.json"))
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_ARCHIVE_SIZE = 500000
MAX_MEMBER_SIZE = 140000


class ReviewProofError(ValueError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def no_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ReviewProofError("Duplicate evidence JSON key")
            out[key] = value
        return out
    try:
        text = raw.decode("utf-8", "strict") if isinstance(raw, bytes) else raw
        value = json.loads(text, object_pairs_hook=no_duplicates,
                           parse_constant=lambda x: (_ for _ in ()).throw(
                               ReviewProofError("Nonfinite JSON evidence")))
        if not isinstance(value, dict):
            raise ReviewProofError("Expected object evidence")
        return value
    except (UnicodeError, ValueError, TypeError) as exc:
        if isinstance(exc, ReviewProofError):
            raise
        raise ReviewProofError("Malformed JSON evidence") from exc


def _exact_bool_false(document, *names):
    if any(document.get(key) is not False for key in names):
        raise ReviewProofError("Release/attestation flag is unsafe")


def _check_run(run, jobs, artifact, expected_commit, artifact_id):
    if not SHA40.fullmatch(expected_commit):
        raise ReviewProofError("Expected HEAD SHA invalid")
    if (not isinstance(run, dict) or type(run.get("id")) is not int
            or run["id"] <= 0 or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("run_attempt") != 1
            or run.get("head_sha") != expected_commit
            or run.get("head_branch") != BRANCH
            or run.get("path") != WORKFLOW
            or run.get("event") not in ("push", "workflow_dispatch")
            or run.get("repository", {}).get("full_name") != REPO
            or run.get("head_repository", {}).get("full_name") != REPO):
        raise ReviewProofError("Untrusted run, branch, commit, workflow or status")
    if not isinstance(jobs, list):
        raise ReviewProofError("Job evidence missing")
    matches = [j for j in jobs if isinstance(j, dict)
               and j.get("name") == "real_qwen3_review"]
    if len(matches) != 1:
        raise ReviewProofError("Expected exactly one real Qwen3 job")
    job = matches[0]
    steps = job.get("steps", [])
    if (job.get("status") != "completed" or job.get("conclusion") != "success"
            or job.get("run_id") not in (None, run["id"])
            or not isinstance(steps, list)):
        raise ReviewProofError("Real Qwen3 job did not complete successfully")
    required = (
        "Acquire exact free Qwen3 locally, no paid API",
        "Independently inspect exact repaired source and save raw evidence",
        "Preserve read-only reviewer evidence even on failure",
    )
    for name in required:
        found = [s for s in steps if isinstance(s, dict) and s.get("name") == name]
        if len(found) != 1 or found[0].get("conclusion") != "success":
            raise ReviewProofError("Real model/audit/archive step not successful")
    if (not isinstance(artifact, dict) or type(artifact_id) is not int
            or artifact_id <= 0 or artifact.get("id") != artifact_id
            or artifact.get("name") !=
            "neurofactory-handoff-owned-remediation-qwen3-evidence"
            or artifact.get("expired") is not False):
        raise ReviewProofError("Original GitHub artifact identity invalid")
    if artifact.get("workflow_run") is not None:
        if artifact["workflow_run"].get("id") != run["id"]:
            raise ReviewProofError("Artifact was produced by another run")


def _extract(archive_bytes):
    if not isinstance(archive_bytes, bytes) or len(archive_bytes) > MAX_ARCHIVE_SIZE:
        raise ReviewProofError("Oversized or missing archive")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
            files = z.infolist()
            names = [f.filename for f in files]
            if len(files) != 4 or set(names) != EXPECTED_MEMBERS:
                raise ReviewProofError("Unexpected/missing/duplicate evidence")
            if sum(f.file_size for f in files) > 220000:
                raise ReviewProofError("Unbounded ZIP inflation")
            for f in files:
                file_type = (f.external_attr >> 16) & 0o170000
                if (f.is_dir() or f.file_size > MAX_MEMBER_SIZE
                        or f.flag_bits & 1
                        or file_type not in (0, stat.S_IFREG)):
                    raise ReviewProofError("Unsafe ZIP member")
            raw = {name: z.read(name) for name in EXPECTED_MEMBERS}
            return raw
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise ReviewProofError("Unreadable ZIP evidence") from exc


def inspect_evidence(run, jobs, artifact, artifact_id, archive_bytes,
                     expected_commit, exact_source_bytes):
    """Returns evidence observations only; cannot grant owner approval."""
    if not isinstance(exact_source_bytes, bytes):
        raise ReviewProofError("Trusted exact source bytes required")
    _check_run(run, jobs, artifact, expected_commit, artifact_id)
    raw = _extract(archive_bytes)
    documents = {name: strict_json(value) for name, value in raw.items()}
    request = documents["request.json"]
    response = documents["ollama-response.json"]
    result = documents["result.json"]
    checkpoint = documents["checkpoint.json"]
    source_digest = sha256(exact_source_bytes)

    if (result.get("git_commit") != expected_commit
            or result.get("source_sha256") != source_digest
            or checkpoint.get("git_commit") != expected_commit
            or checkpoint.get("source_sha256") != source_digest
            or result.get("requested_model") != MODEL
            or not isinstance(result.get("ollama_model_digest_claim"), str)
            or not SHA64.fullmatch(result["ollama_model_digest_claim"])):
        raise ReviewProofError("Model result not tied to exact source/commit")
    if (result.get("request_sha256") != sha256(raw["request.json"])
            or result.get("ollama_response_sha256") != sha256(raw["ollama-response.json"])
            or checkpoint.get("result_sha256") != sha256(raw["result.json"])):
        raise ReviewProofError("Raw request/response/result checksum mismatch")
    prompt = request.get("prompt")
    if request.get("model") != MODEL or not isinstance(prompt, str):
        raise ReviewProofError("Model request is not exact Qwen3 input")
    asked = strict_json(prompt)
    if (asked.get("source_sha256") != source_digest
            or asked.get("full_python_module") !=
            exact_source_bytes.decode("utf-8", "strict")):
        raise ReviewProofError("Model prompt did not contain exact source")
    if response.get("model") != MODEL:
        raise ReviewProofError("Raw response model claim differs")
    reply = response.get("response")
    if not isinstance(reply, str) or not reply.strip() or len(reply) > 6000:
        raise ReviewProofError("Missing/oversized raw model response")
    verdict = strict_json(reply)
    if (set(verdict) != {"verdict", "candidate_sha256", "findings"}
            or verdict.get("candidate_sha256") != source_digest
            or verdict.get("verdict") not in ("APPROVE", "REJECT")
            or not isinstance(verdict.get("findings"), list)
            or any(not isinstance(x, str) or not x.strip() or len(x) > 500
                   for x in verdict["findings"])):
        raise ReviewProofError("Malformed, forged or source-unbound verdict")
    if verdict["verdict"] == "REJECT" and not verdict["findings"]:
        raise ReviewProofError("Unexplained model rejection")
    if result.get("review") != verdict:
        raise ReviewProofError("Saved model verdict was modified")
    for record in (result, checkpoint):
        _exact_bool_false(record, "independent_review_owner_approved",
                          "release_authorized")
        if record.get("publication_count") != 0 or isinstance(
                record.get("publication_count"), bool):
            raise ReviewProofError("Publication claimed without approval")
    _exact_bool_false(result, "trusted_external_provenance_confirmed",
                      "publisher_enabled")
    if result.get("model_review_only") is not True:
        raise ReviewProofError("Review was promoted to publishing approval")
    expected_checkpoint = (
        "awaiting_external_review_owner" if verdict["verdict"] == "APPROVE"
        else "rejected")
    if checkpoint.get("state") != expected_checkpoint:
        raise ReviewProofError("Model review checkpoint status mismatch")

    return {"scope": "INDEPENDENT_REVIEW_ONLY",
            "github_run_id": run["id"],
            "github_run_head": expected_commit,
            "github_artifact_id": artifact_id,
            "archive_sha256": sha256(archive_bytes),
            "exact_module_sha256": source_digest,
            "model_opinion": verdict["verdict"],
            "model_digest": result["ollama_model_digest_claim"],
            "github_metadata_consistent": True,
            "raw_bytes_integrity_verified": True,
            "model_process_cryptographically_authenticated": False,
            "independent_review_owner_approved": False,
            "release_authorized": False,
            "merge_authorized": False,
            "publisher_allowed": False}
