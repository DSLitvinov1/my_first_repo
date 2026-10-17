"""Strict CORE JSON entrypoint for isolated PROVIDERS proposal generation.

Caller CORE must authenticate the task independently before calling this
function. This parser does NOT authorize the task or own the queue/lease.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from local_qwen import _no_duplicate_pairs
from ollama_worker import ProviderTask, execute_one


class InvalidCoreRequest(ValueError):
    pass


def parse_core_request(payload: bytes) -> ProviderTask:
    if type(payload) is not bytes or not 1 <= len(payload) <= 8192:
        raise InvalidCoreRequest("invalid request payload length or type")
    try:
        envelope = json.loads(payload.decode("utf-8"), object_pairs_hook=_no_duplicate_pairs)
        return ProviderTask.from_json(envelope)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise InvalidCoreRequest("invalid schema or duplicate JSON keys") from exc


def produce_unverified_result(
    payload: bytes,
    *,
    trusted_core_call: bool = False,
    model: str = "qwen2.5-coder:1.5b",
    ledger_dir: Path,
) -> dict:
    """Deliberate caller opt-in; not an authentication/independent review gate."""
    if trusted_core_call is not True:
        raise PermissionError("CORE caller has not opted into a pre-approved sandbox task")
    request = parse_core_request(payload)
    return execute_one(request, model=model, ledger_dir=ledger_dir)
