"""Coordinator-only read-only metadata binding for private PROVIDERS v1 evidence.

Never reads raw model text, local files or network; cannot attest a model,
grant CORE source verification, replay or publish. One reported receipt is not
proof of source authenticity or independent REVIEW.
"""
from __future__ import annotations

from hashlib import sha256
import re


class EvidenceBindingError(ValueError):
    pass


_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\+00:00\Z")
_SUMMARY_FIELDS = {
    "schema", "status", "task_id", "source_sha", "provider_status",
    "proposed_path", "proposed_content_sha256", "model_output_digest",
    "source_verified", "automatic_retry_allowed", "publication_allowed",
}

_ALLOWED_EXTENSIONS = (".py", ".md", ".txt", ".json")
_SAFE_RELATIVE = re.compile(r"[A-Za-z0-9_./-]{1,160}\\Z")


def _safe_proposal_path(path):
    if (type(path) is not str or _SAFE_RELATIVE.fullmatch(path) is None or
        not path.startswith(("src/", "docs/")) or
        not path.endswith(_ALLOWED_EXTENSIONS)):
        return False
    return all(segment and segment not in (".", "..") and
               not segment.startswith(".") for segment in path.split("/"))


_METADATA_FIELDS = {
    "evidence_filename", "evidence_sha256", "response_sha256",
    "observed_at_utc", "elapsed_ms",
}


def bind_reported_receipt(summary, metadata):
    """Validate reported identifiers/digests; return only UNTRUSTED metadata.

    Authenticating the Windows host and private readback, verifying the actual
    local model or approving a CORE writer are strictly separate operations.
    """
    if (type(summary) is not dict or set(summary) != _SUMMARY_FIELDS or
        type(metadata) is not dict or set(metadata) != _METADATA_FIELDS):
        raise EvidenceBindingError("unexpected fields or leaked raw response")
    task_id = summary["task_id"]
    digest = summary["model_output_digest"]
    if (type(summary["schema"]) is not int or summary["schema"] != 1 or
        summary["status"] != "RESPONSE_UNVERIFIED" or
        summary["provider_status"] != "PROPOSED_UNVERIFIED" or
        type(task_id) is not str or _TASK.fullmatch(task_id) is None or
        type(summary["source_sha"]) is not str or
        _SHA40.fullmatch(summary["source_sha"]) is None or
        type(digest) is not str or _SHA64.fullmatch(digest) is None or
        type(summary["proposed_content_sha256"]) is not str or
        _SHA64.fullmatch(summary["proposed_content_sha256"]) is None or
        not _safe_proposal_path(summary["proposed_path"]) or
        summary["source_verified"] is not False or
        summary["automatic_retry_allowed"] is not False or
        summary["publication_allowed"] is not False):
        raise EvidenceBindingError("untrusted or blocked source status")
    expected_filename = sha256(task_id.encode("utf-8")).hexdigest() + ".json"
    if (metadata["evidence_filename"] != expected_filename or
        type(metadata["response_sha256"]) is not str or
        metadata["response_sha256"] != digest or
        type(metadata["evidence_sha256"]) is not str or
        _SHA64.fullmatch(metadata["evidence_sha256"]) is None or
        type(metadata["observed_at_utc"]) is not str or
        _UTC.fullmatch(metadata["observed_at_utc"]) is None or
        type(metadata["elapsed_ms"]) is not int or
        not 0 <= metadata["elapsed_ms"] <= 120000):
        raise EvidenceBindingError("reported receipt does not match result")
    return {
        "schema": "neurofactory.coordination.evidence_view.v1",
        "task_id": task_id,
        "source_sha": summary["source_sha"],
        "reported_response_sha256": digest,
        "reported_receipt_sha256": metadata["evidence_sha256"],
        "reported_at_utc": metadata["observed_at_utc"],
        "receipt_reported": True,
        "receipt_externally_authenticated": False,
        "local_model_proven": False,
        "independent_review_approved": False,
        "source_verified": False,
        "automatic_retry_allowed": False,
        "publication_allowed": False,
        "handoff": "PAUSED_BY_USER",
    }
