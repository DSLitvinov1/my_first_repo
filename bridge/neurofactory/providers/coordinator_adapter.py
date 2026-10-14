"""Pure-data adapter to coordinator MVP exchange's candidate contract.

No CORE authorization, filesystem writes or model calls; an already authenticated
CORE host must admit the proposal and reserve lease before using these objects.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from local_qwen import ALLOWED_MODELS, _no_duplicate_pairs
from ollama_worker import ProviderTask, validate_target

_COORD_SCHEMA = "neurofactory.providers.coordinator_pair.v1"
_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_CORE_TARGET = "bridge/neurofactory/development/core_owned/"
_PROPOSAL_FIELDS = {
    "task_id", "project_id", "target", "objective", "source_sha",
    "source_sha256", "model", "reserved_units"
}
_PREPARED_FIELDS = {
    "task_id", "source_sha", "model", "budget_units", "local_only", "purpose"
}


@dataclass(frozen=True)
class PreparedProviderCall:
    """Unprivileged candidate; no authorization is implied by parsing."""
    task: ProviderTask
    source_sha: str
    model: str
    max_reserved_units: int


def _strict_envelope(data: dict) -> PreparedProviderCall:
    if (type(data) is not dict or set(data) != {"schema", "proposal", "prepared_request"} or
            data["schema"] != _COORD_SCHEMA):
        raise ValueError("invalid coordinator envelope")
    p, r = data["proposal"], data["prepared_request"]
    if (type(p) is not dict or set(p) != _PROPOSAL_FIELDS or
            type(r) is not dict or set(r) != _PREPARED_FIELDS):
        raise ValueError("coordinator fields do not match version 1")
    if (type(p["task_id"]) is not str or not _TASK.fullmatch(p["task_id"]) or
            type(p["project_id"]) is not str or not _PROJECT.fullmatch(p["project_id"]) or
            type(p["source_sha"]) is not str or not _SHA40.fullmatch(p["source_sha"]) or
            type(p["source_sha256"]) is not str or not _SHA64.fullmatch(p["source_sha256"])):
        raise ValueError("coordinator identity or source not pinned")
    if (type(p["model"]) is not str or p["model"] not in ALLOWED_MODELS or
            type(p["reserved_units"]) is not int or not 1024 <= p["reserved_units"] <= 50_000):
        raise ValueError("model or reservation out of bounded provider policy")
    if type(p["target"]) is not str or not p["target"].startswith(_CORE_TARGET):
        raise ValueError("foreign CORE target")
    validate_target(p["target"])
    if (type(p["objective"]) is not str or
            not 25 <= len(p["objective"]) <= 320 or
            any(ord(ch) < 32 for ch in p["objective"])):
        raise ValueError("unsafe objective")
    if (r["task_id"] != p["task_id"] or r["source_sha"] != p["source_sha"] or
            r["model"] != p["model"] or
            type(r["budget_units"]) is not int or
            r["budget_units"] != p["reserved_units"] or
            r["local_only"] is not True or
            r["purpose"] != "CORE_SANDBOX_PROPOSAL"):
        raise ValueError("prepared request was changed or mismatched")
    task = ProviderTask(
        task_id=p["task_id"],
        project_id=p["project_id"],
        input_sha256=p["source_sha256"],
        target_path=p["target"],
        instruction=p["objective"],
    )
    # Reservation check is separate from durable ledger's exact task-ID check.
    if len(task.prompt()) + 4 * 256 > p["reserved_units"]:
        raise ValueError("coordinator reserved too few units for this provider")
    return PreparedProviderCall(task, p["source_sha"], p["model"], p["reserved_units"])


def parse_coordinator_pair(raw: bytes) -> PreparedProviderCall:
    if type(raw) is not bytes or not 1 <= len(raw) <= 16384:
        raise ValueError("invalid coordinator input type or size")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_pairs)
        return _strict_envelope(data)
    except (UnicodeError, TypeError, ValueError) as exc:
        raise ValueError("invalid coordinator pair; cannot admit to provider") from exc


def coordinator_result(candidate: PreparedProviderCall, provider_result: dict) -> dict:
    """Translate only a real *proposed* local result into coordinator v1.

    This is NOT external CORE authorization, a model provenance attestation or
    evidence of a file being written or reviewed.  The trusted host must verify.
    """
    if type(candidate) is not PreparedProviderCall or type(provider_result) is not dict:
        raise ValueError("invalid result")
    if (provider_result.get("status") != "PROPOSED_UNVERIFIED" or
            provider_result.get("task_id") != candidate.task.task_id or
            provider_result.get("project_id") != candidate.task.project_id or
            provider_result.get("input_sha256") != candidate.task.input_sha256 or
            provider_result.get("model") != candidate.model or
            provider_result.get("provider") != "ollama-loopback" or
            provider_result.get("offline_mock") is not False or
            provider_result.get("published") is not False or
            provider_result.get("review_approved") is not False or
            provider_result.get("observed_local_reply") is not True or
            provider_result.get("attempt_consumed") is not True or
            type(provider_result.get("prompt_sha256")) is not str or
            not _SHA64.fullmatch(provider_result["prompt_sha256"]) or
            type(provider_result.get("response_sha256")) is not str or
            not _SHA64.fullmatch(provider_result["response_sha256"]) or
            provider_result.get("api_cost_usd") != 0):
        raise ValueError("blocked or untrusted provider result")
    files = provider_result.get("proposed_files")
    if type(files) is not list or len(files) != 1:
        raise ValueError("no single scoped proposal")
    item = files[0]
    if (type(item) is not dict or
            item.get("relative_path") != candidate.task.target_path or
            item.get("applied") is not False or
            item.get("verified_by_core") is not False or
            type(item.get("content_sha256")) is not str or
            type(item.get("content")) is not str or not item["content"].strip() or
            len(item["content"]) > 12000):
        raise ValueError("invalid candidate proposal")
    if sha256(item["content"].encode("utf-8")).hexdigest() != item["content_sha256"]:
        raise ValueError("proposed file digest mismatch")
    # The coordinator currently stores digest of candidate text, not files.
    # Files still go ONLY through CORE's authenticated sandbox writer.
    return {
        "task_id": candidate.task.task_id,
        "source_sha": candidate.source_sha,
        "model": candidate.model,
        "text": item["content"],
        "local_only": True,
        "published": False,
        "mode": "local",
    }
