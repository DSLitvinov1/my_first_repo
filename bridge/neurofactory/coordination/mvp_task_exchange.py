"""Coordinator-only, pure-data, fail-closed MVP exchange.

No IO, network, model invocation, filesystem mutation, publisher or queue calls.
All authentication is external. Hashes detect accidents, not forged authorship.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re

class ExchangeError(ValueError):
    pass

SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
PROJ = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
TARGET = re.compile(r"bridge/neurofactory/development/core_owned/[A-Za-z0-9_./-]{1,110}\Z")
MODELS = frozenset({"qwen3:0.6b", "qwen3:4b", "qwen2.5-coder:7b"})
ORDER = ("CREATED", "AUTHORIZED", "REQUEST_PREPARED", "PROVIDER_RETURNED", "SOURCE_VERIFIED")
STATUS = ("PENDING_APPROVAL", "AUTHORIZED", "READY_FOR_CORE", "RESPONSE_UNVERIFIED", "SOURCE_VERIFIED")
PROPOSAL_FIELDS = {"task_id", "project_id", "target", "objective", "source_sha",
                   "source_sha256", "model", "reserved_units"}
EVIDENCE_FIELDS = {"task_id", "source_sha", "owner", "approval_commit", "scope"}
RESULT_FIELDS = {"task_id", "source_sha", "model", "text", "local_only", "published", "mode"}
SOURCE_FIELDS = {"task_id", "source_before", "source_after", "file_sha256", "review_commit"}

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")

def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()

def _exact(value, fields):
    return type(value) is dict and set(value) == fields

def _hex(value, regex):
    return type(value) is str and bool(regex.fullmatch(value))

def _validate_proposal(p):
    if not _exact(p, PROPOSAL_FIELDS):
        raise ExchangeError("unexpected proposal keys")
    if not _hex(p["task_id"], TASK) or not _hex(p["project_id"], PROJ):
        raise ExchangeError("invalid task/project identity")
    path = p["target"]
    if (type(path) is not str or not TARGET.fullmatch(path)
        or any(s in ("", ".", "..") for s in path.split("/"))):
        raise ExchangeError("target outside isolated CORE sandbox")
    if (type(p["objective"]) is not str or not 25 <= len(p["objective"]) <= 320
        or any(ord(ch) < 32 for ch in p["objective"])):
        raise ExchangeError("objective is unsafe")
    if not _hex(p["source_sha"], SHA40) or not _hex(p["source_sha256"], SHA64):
        raise ExchangeError("unversioned source")
    if type(p["model"]) is not str or p["model"] not in MODELS:
        raise ExchangeError("unsupported local model")
    if type(p["reserved_units"]) is not int or not 1 <= p["reserved_units"] <= 100_000:
        raise ExchangeError("unbounded reservation")

def _append(state, kind, payload):
    if len(state["events"]) >= len(ORDER) or kind != ORDER[len(state["events"])]:
        raise ExchangeError("out of order or duplicate stage")
    previous = state["events"][-1]["digest"] if state["events"] else "0" * 64
    event = {"kind": kind, "payload": copy.deepcopy(payload), "prev": previous}
    event["digest"] = _digest(event)
    state["events"].append(event)

def start(proposal):
    """Prepare a single scoped candidate, with NO permission to execute it."""
    _validate_proposal(proposal)
    state = {"schema": 1, "proposal": copy.deepcopy(proposal), "status": STATUS[0],
             "approval_ref": None, "request": None, "result": None,
             "source_proof": None, "events": [], "cost_limit_usd": 0,
             "live_execution_allowed": False, "publication_allowed": False,
             "retry_allowed": False, "handoff": "PAUSED_BY_USER"}
    _append(state, "CREATED", {"task_id": proposal["task_id"],
                               "proposal_digest": _digest(proposal)})
    return state

def _valid_state(state):
    if (type(state) is not dict or set(state) !=
        {"schema", "proposal", "status", "approval_ref", "request", "result",
         "source_proof", "events", "cost_limit_usd", "live_execution_allowed",
         "publication_allowed", "retry_allowed", "handoff"}):
        raise ExchangeError("invalid state shape")
    _validate_proposal(state["proposal"])
    if (type(state["schema"]) is not int or state["schema"] != 1 or
        state["cost_limit_usd"] != 0 or state["live_execution_allowed"] is not False or
        state["publication_allowed"] is not False or state["retry_allowed"] is not False or
        state["handoff"] != "PAUSED_BY_USER" or type(state["events"]) is not list or
        not 1 <= len(state["events"]) <= len(ORDER) or
        state["status"] != STATUS[len(state["events"])-1]):
        raise ExchangeError("unsafe or incompatible state")
    previous = "0" * 64
    for n, event in enumerate(state["events"]):
        if (not _exact(event, {"kind", "payload", "prev", "digest"}) or
            event["kind"] != ORDER[n] or event["prev"] != previous or
            not _hex(event["digest"], SHA64) or
            _digest({"kind": event["kind"], "payload": event["payload"], "prev": previous}) != event["digest"]):
            raise ExchangeError("corrupted event chain")
        previous = event["digest"]
    if state["events"][0]["payload"] != {"task_id": state["proposal"]["task_id"],
                                         "proposal_digest": _digest(state["proposal"])}:
        raise ExchangeError("proposal differs from event")
    if len(state["events"]) >= 2:
        if state["events"][1]["payload"] != state["approval_ref"]:
            raise ExchangeError("approval record mismatch")
    elif state["approval_ref"] is not None:
        raise ExchangeError("spurious approval")
    if len(state["events"]) >= 3:
        if state["events"][2]["payload"] != state["request"]:
            raise ExchangeError("request mismatch")
    elif state["request"] is not None:
        raise ExchangeError("spurious request")
    if len(state["events"]) >= 4:
        if state["events"][3]["payload"] != state["result"]:
            raise ExchangeError("provider record mismatch")
    elif state["result"] is not None:
        raise ExchangeError("spurious provider result")
    if len(state["events"]) >= 5:
        if state["events"][4]["payload"] != state["source_proof"]:
            raise ExchangeError("source proof mismatch")
    elif state["source_proof"] is not None:
        raise ExchangeError("spurious source proof")

def _advance(state, expected):
    _valid_state(state)
    if state["status"] != expected:
        raise ExchangeError("illegal or repeated transition")
    return copy.deepcopy(state)

def authorize(state, receipt, *, trusted_approval_check=None):
    """External host must authenticate approval; supplied text NEVER suffices."""
    next_state = _advance(state, "PENDING_APPROVAL")
    p = next_state["proposal"]
    if (not _exact(receipt, EVIDENCE_FIELDS) or
        receipt["task_id"] != p["task_id"] or receipt["source_sha"] != p["source_sha"] or
        receipt["scope"] != p["target"] or receipt["owner"] != "CORE" or
        not _hex(receipt["approval_commit"], SHA40)):
        raise ExchangeError("invalid external approval reference")
    if not callable(trusted_approval_check) or trusted_approval_check(copy.deepcopy(receipt),
                                                                       copy.deepcopy(p)) is not True:
        raise ExchangeError("trusted external approval not available")
    next_state["approval_ref"] = copy.deepcopy(receipt)
    _append(next_state, "AUTHORIZED", receipt)
    next_state["status"] = "AUTHORIZED"
    return next_state

def prepare_request(state):
    """Data exchange only: does NOT invoke CORE/Ollama or lift HANDOFF pause."""
    next_state = _advance(state, "AUTHORIZED")
    p = next_state["proposal"]
    request = {"task_id": p["task_id"], "source_sha": p["source_sha"],
               "model": p["model"], "budget_units": p["reserved_units"],
               "local_only": True, "purpose": "CORE_SANDBOX_PROPOSAL"}
    next_state["request"] = request
    _append(next_state, "REQUEST_PREPARED", request)
    next_state["status"] = "READY_FOR_CORE"
    return next_state

def record_provider_result(state, result):
    """Correlate external provider return to task and immutable input version."""
    next_state = _advance(state, "READY_FOR_CORE")
    p = next_state["proposal"]
    if (not _exact(result, RESULT_FIELDS) or result["task_id"] != p["task_id"] or
        result["source_sha"] != p["source_sha"] or result["model"] != p["model"] or
        result["local_only"] is not True or result["published"] is not False or
        result["mode"] not in ("mock", "local") or
        type(result["text"]) is not str or not 1 <= len(result["text"]) <= 16000):
        raise ExchangeError("unsafe, mismatched or incomplete provider result")
    summary = {"task_id": p["task_id"], "source_sha": p["source_sha"],
               "model": result["model"], "mode": result["mode"],
               "text_sha256": hashlib.sha256(result["text"].encode("utf-8")).hexdigest(),
               "verified": False}
    next_state["result"] = summary
    _append(next_state, "PROVIDER_RETURNED", summary)
    next_state["status"] = "RESPONSE_UNVERIFIED"
    return next_state

def attest_source(state, proof, *, trusted_source_check=None):
    """Never trust model self-report or checksum alone as a signed GitHub receipt."""
    next_state = _advance(state, "RESPONSE_UNVERIFIED")
    p = next_state["proposal"]
    if (not _exact(proof, SOURCE_FIELDS) or proof["task_id"] != p["task_id"] or
        proof["source_before"] != p["source_sha"] or
        not all(_hex(proof[k], SHA40) for k in ("source_after", "review_commit")) or
        not _hex(proof["file_sha256"], SHA64) or
        proof["source_after"] == p["source_sha"] or next_state["result"]["mode"] != "local"):
        raise ExchangeError("invalid source version proof or mock origin")
    if not callable(trusted_source_check) or trusted_source_check(copy.deepcopy(proof),
                                                                  copy.deepcopy(next_state)) is not True:
        raise ExchangeError("independent authenticated readback required")
    next_state["source_proof"] = copy.deepcopy(proof)
    _append(next_state, "SOURCE_VERIFIED", proof)
    next_state["status"] = "SOURCE_VERIFIED"
    return next_state

def checkpoint(state):
    """Portable sealed snapshot, NOT durable until trusted host stores it."""
    _valid_state(state)
    return {"body": copy.deepcopy(state), "sha256": _digest(state)}

def restore(record, *, trusted_checkpoint_check=None):
    if (not _exact(record, {"body", "sha256"}) or
        not _hex(record["sha256"], SHA64) or _digest(record["body"]) != record["sha256"]):
        raise ExchangeError("tampered checkpoint")
    _valid_state(record["body"])
    if (not callable(trusted_checkpoint_check) or
        trusted_checkpoint_check(copy.deepcopy(record)) is not True):
        raise ExchangeError("externally trusted checkpoint provenance missing")
    return copy.deepcopy(record["body"])

def project(state):
    """Bounded UI/OPS projection with no authorization, even at SOURCE_VERIFIED."""
    _valid_state(state)
    p = state["proposal"]
    return {"schema": 1, "task_id": p["task_id"], "project_id": p["project_id"],
            "source_sha": p["source_sha"], "stage": state["status"],
            "result_digest": state["result"]["text_sha256"] if state["result"] else None,
            "review_provenance": "NOT_ATTESTED_BY_PROJECTION",
            "source_verified_by_host": False,
            "external_execution_allowed": False, "publication_allowed": False,
            "automatic_retry_allowed": False, "handoff": "PAUSED_BY_USER"} 
