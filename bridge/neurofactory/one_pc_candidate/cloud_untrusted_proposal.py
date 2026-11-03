"""Strict, data-only cloud Qwen draft handoff to the existing Windows owner gate.

The channel (GitHub/bridge/file) is UNTRUSTED. Model output never grants
execution, supplies a signature/public trust pin, chooses an effect path or
controls a Windows service. The owner must independently approve the exact
draft/task; witness/physical release gates remain separate.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SCHEMA = "nf.onepc.cloud_untrusted_qwen_draft.ci.v1"
_FIELDS = frozenset((
    "schema", "model", "model_file_sha256", "model_runtime",
    "prompt_sha256", "output_text", "output_sha256", "source",
    "actual_inference_exit_code", "model_text_is_untrusted",
    "execution_allowed", "owner_signed",
    "independent_provenance_attested",
))

class CloudProposalDenied(ValueError):
    pass

def _unique(pairs):
    out={}
    for key,value in pairs:
        if key in out:
            raise CloudProposalDenied("Duplicate cloud proposal field")
        out[key]=value
    return out

def verify_cloud_untrusted_proposal(obj, *, pinned_model_sha256):
    """Pure validation; returns immutable SHA evidence, NEVER permission."""
    if (type(obj) is not dict or set(obj)!=_FIELDS or
            type(pinned_model_sha256) is not str or
            not _SHA.fullmatch(pinned_model_sha256) or
            obj.get("schema")!=_SCHEMA or
            obj.get("model")!="qwen2.5-coder:1.5b" or
            obj.get("model_file_sha256")!=pinned_model_sha256 or
            obj.get("model_runtime")!="llama.cpp b12040" or
            type(obj.get("prompt_sha256")) is not str or
            not _SHA.fullmatch(obj["prompt_sha256"]) or
            type(obj.get("output_sha256")) is not str or
            not _SHA.fullmatch(obj["output_sha256"]) or
            type(obj.get("actual_inference_exit_code")) is not int or
            obj["actual_inference_exit_code"] != 0 or
            obj.get("model_text_is_untrusted") is not True or
            obj.get("execution_allowed") is not False or
            obj.get("owner_signed") is not False or
            obj.get("independent_provenance_attested") is not False):
        raise CloudProposalDenied("Untrusted remote model metadata mismatched/claims authority")
    output=obj.get("output_text")
    source=obj.get("source")
    if (type(output) is not str or
            not 1<=len(output.encode("utf-8"))<=1200 or
            any(ord(c)<32 and c not in "\n\t" for c in output) or
            type(source) is not str or not 5<=len(source)<=160 or
            any(ord(c)<32 for c in source) or
            hashlib.sha256(output.encode("utf-8")).hexdigest()!=obj["output_sha256"]):
        raise CloudProposalDenied("Model output invalid or digest mismatched")
    return {
        "schema": "nf.onepc.cloud_data_only_receipt.ci.v1",
        "model": obj["model"],
        "proposal_sha256": obj["output_sha256"],
        "model_file_sha256": pinned_model_sha256,
        "owner_signed": False,
        "core_enqueued": False,
        "scm_file_allowed": False,
        "remote_witness_signed": False,
        "production_release_approved": False,
    }

def read_cloud_untrusted_proposal(path: Path, *, pinned_model_sha256: str):
    if (not isinstance(path,Path) or not path.is_absolute()
            or path.is_symlink() or not path.is_file()
            or path.stat().st_size>4096):
        raise CloudProposalDenied("Trusted code may only read a bounded existing data file")
    try:
        obj=json.loads(path.read_text("utf-8"),object_pairs_hook=_unique)
    except (OSError,UnicodeError,ValueError,TypeError) as exc:
        raise CloudProposalDenied("Bad cloud proposal JSON") from exc
    return obj,verify_cloud_untrusted_proposal(
        obj,pinned_model_sha256=pinned_model_sha256)
