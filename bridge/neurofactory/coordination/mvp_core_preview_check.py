"""Coordinator-only validation of the actual CORE one-task provider_preview packet.

Pure data. It DOES NOT check actual Git objects, attest CORE approval,
reserve an attempt, claim a lease, invoke a model or confer execution rights.
"""
from __future__ import annotations
import hashlib
import json
import re
from mvp_provider_wire import WireError, _validate_packet

class CorePreviewError(ValueError):
    pass

_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_PROJ = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
_SHA40 = re.compile(r"[a-f0-9]{40}\Z")
_SHA64 = re.compile(r"[a-f0-9]{64}\Z")
_SEGMENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*\Z")
_CORE_PREFIX = "bridge/neurofactory/development/core_owned/"
_CORE_SPEC = {"schema","task_id","project_id","target","objective","source_sha",
              "source_sha256","model","reserved_units","approval_commit"}
_WINDOWS_DEVICES = frozenset({"CON","PRN","AUX","NUL"} |
    {"COM"+str(i) for i in range(1,10)} |
    {"LPT"+str(i) for i in range(1,10)})
_MODELS = frozenset({"qwen3:0.6b","qwen3:4b",
                     "qwen2.5-coder:7b","qwen2.5-coder:1.5b"})

def _sha(s, pat):
    return type(s) is str and pat.fullmatch(s) is not None

def _expected_target(target):
    if type(target) is not str or not target.startswith(_CORE_PREFIX):
        raise CorePreviewError("target outside CORE-owned sandbox")
    suffix = target[len(_CORE_PREFIX):]
    if not 1 <= len(suffix) <= 110 or len(target) > 160:
        raise CorePreviewError("invalid scoped target length")
    parts = suffix.split("/")
    if any(not seg or seg in (".","..") or seg.startswith(".") or
           _SEGMENT.fullmatch(seg) is None or
           seg.split(".")[0].upper() in _WINDOWS_DEVICES for seg in parts):
        raise CorePreviewError("unsafe scoped target segment")
    if not suffix.endswith((".py",".md",".txt",".json")):
        raise CorePreviewError("unsupported target extension")
    return ("docs/" if suffix.endswith(".md") else "src/") + suffix

def _valid_spec(spec):
    if type(spec) is not dict or set(spec) != _CORE_SPEC:
        raise CorePreviewError("not an exact CORE v1 task manifest")
    if (spec["schema"] != "neurofactory.core.task.v1" or
        not _sha(spec["task_id"],_TASK) or not _sha(spec["project_id"],_PROJ) or
        not _sha(spec["source_sha"],_SHA40) or
        not _sha(spec["source_sha256"],_SHA64) or
        not _sha(spec["approval_commit"],_SHA40) or
        type(spec["objective"]) is not str or not 25 <= len(spec["objective"]) <= 320 or
        any(ord(c) < 32 for c in spec["objective"]) or
        type(spec["model"]) is not str or spec["model"] not in _MODELS or
        type(spec["reserved_units"]) is not int or
        not 1 <= spec["reserved_units"] <= 100_000):
        raise CorePreviewError("untrusted or malformed task manifest")
    return _expected_target(spec["target"])

def inspect_core_preview(task_manifest, provider_packet):
    """Compare all pinned task fields with CORE preview; never issue authority.

    The SHA256 digest over an unsigned manifest detects accidental mismatch,
    NOT a forged manifest. A genuinely trusted CORE host must separately
    authenticate task admission, immutable Git preimage and claimed lease.
    """
    expected_provider_path = _valid_spec(task_manifest)
    try:
        _validate_packet(provider_packet)
    except (WireError, TypeError, KeyError, ValueError) as exc:
        raise CorePreviewError("provider packet rejected by coordinator wire") from exc
    p = task_manifest
    r, b = provider_packet["request"], provider_packet["binding"]
    raw = json.dumps(p, sort_keys=True, ensure_ascii=False, separators=(",",":"),
                     allow_nan=False).encode("utf-8")
    expected_input_sha256 = hashlib.sha256(raw).hexdigest()
    expected_binding = {
        "task_id":p["task_id"],"project_id":p["project_id"],
        "source_sha":p["source_sha"],"source_sha256":p["source_sha256"],
        "core_target":p["target"],"provider_target":expected_provider_path,
        "model":p["model"],"input_sha256":expected_input_sha256,
    }
    expected_request = {
        "schema":"neurofactory.providers.request.v1","task_id":p["task_id"],
        "project_id":p["project_id"],"input_sha256":expected_input_sha256,
        "target_path":expected_provider_path,"instruction":p["objective"],
    }
    if b != expected_binding or r != expected_request:
        raise CorePreviewError("CORE preview drift: task digest/path/identity not pinned")
    if provider_packet["permissions"] != {
        "execution":False,"retry":False,"publication":False,"paid_api":False
    }:
        raise CorePreviewError("unexpected executor permission")
    return {
        "schema":"neurofactory.coordination.core_preview_inspection.v1",
        "task_id":p["task_id"],
        "source_sha":p["source_sha"],
        "source_sha256":p["source_sha256"],
        "input_sha256":expected_input_sha256,
        "provider_relative_path":expected_provider_path,
        "format_compatible":True,
        "task_source_authenticated":False,
        "approval_origin_authenticated":False,
        "lease_proven":False,
        "source_verified":False,
        "external_execution_allowed":False,
        "automatic_retry_allowed":False,
        "publication_allowed":False,
        "handoff":"PAUSED_BY_USER",
    }
