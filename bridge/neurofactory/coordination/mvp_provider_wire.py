"""Pure coordinator mapping to PROVIDERS v1: no provider calls or filesystem writes.

Context is validated on both sides; authenticating CORE source/identity is
an EXTERNAL obligation, not a claim this adapter may issue.
"""
import hashlib
import re

class WireError(ValueError):
    pass

TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
LOCAL_MODELS = {"qwen3:0.6b", "qwen3:4b", "qwen2.5-coder:7b", "qwen2.5-coder:1.5b"}
PROVIDER_REQ_FIELDS = {"schema", "task_id", "project_id", "input_sha256", "target_path", "instruction"}
PROVIDER_REPLY_REQUIRED = {"schema", "status", "task_id", "project_id", "input_sha256", "model",
                           "provider", "offline_mock", "api_cost_usd", "review_approved",
                           "published", "proposed_files", "response_sha256",
                           "prompt_sha256", "error_code", "attempt_consumed"}
PACKET_FIELDS = {"schema", "request", "binding", "permissions"}
CONTEXT_FIELDS = {"task_id", "project_id", "source_sha", "source_sha256",
                  "core_target", "provider_target", "model", "input_sha256"}
REQ_SCHEMA = "neurofactory.providers.request.v1"
RESULT_SCHEMA = "neurofactory.providers.result.v1"
BRIDGE_SCHEMA = "neurofactory.coordination.provider_bridge.v1"

def _hex(x, regex):
    return type(x) is str and regex.fullmatch(x) is not None

def _safe_path(path):
    return (type(path) is str and 1 <= len(path) <= 160
            and path.startswith(("src/", "docs/"))
            and re.fullmatch(r"[A-Za-z0-9_./-]+", path) is not None
            and all(part and part not in (".", "..") and not part.startswith(".")
                    for part in path.split("/"))
            and any(path.endswith(ext) for ext in (".py", ".md", ".txt", ".json")))

def _validate_packet(packet):
    if type(packet) is not dict or set(packet) != PACKET_FIELDS:
        raise WireError("invalid bridge packet")
    if (packet["schema"] != BRIDGE_SCHEMA or type(packet["request"]) is not dict or
        set(packet["request"]) != PROVIDER_REQ_FIELDS or
        type(packet["binding"]) is not dict or set(packet["binding"]) != CONTEXT_FIELDS or
        packet["permissions"] != {"execution": False, "retry": False,
                                  "publication": False, "paid_api": False}):
        raise WireError("unsafe bridge packet")
    r = packet["request"]
    b = packet["binding"]
    if (r["schema"] != REQ_SCHEMA or
        not _hex(b["task_id"], TASK) or not _hex(b["source_sha"], SHA40) or
        not _hex(b["source_sha256"], SHA64) or not _hex(b["input_sha256"], SHA64) or
        not _safe_path(b["provider_target"]) or type(b["model"]) is not str or b["model"] not in LOCAL_MODELS or
        not isinstance(b["project_id"], str) or
        re.fullmatch(r"[a-z][a-z0-9-]{2,39}", b["project_id"]) is None or
        not isinstance(b["core_target"], str) or
        not b["core_target"].startswith("bridge/neurofactory/development/core_owned/") or
        ".." in b["core_target"] or "//" in b["core_target"] or
        r["task_id"] != b["task_id"] or r["project_id"] != b["project_id"] or
        r["input_sha256"] != b["input_sha256"] or r["target_path"] != b["provider_target"] or
        type(r["instruction"]) is not str or not 1 <= len(r["instruction"].strip()) <= 320):
        raise WireError("source and request binding mismatch")

def make_request(candidate, *, provider_path, trusted_input_digest,
                 trusted_mapping_verifier=None):
    """Authorized data preparation; callback checks CORE mapping externally.

    A True callback is necessary but not sufficient for live execution;
    permission flags NEVER change in this function.
    """
    if type(candidate) is not dict or set(candidate) != {
        "task_id", "project_id", "target", "objective",
        "source_sha", "source_sha256", "model", "reserved_units"
    }:
        raise WireError("unexpected coordinator task proposal")
    b = {"task_id":candidate["task_id"],"project_id":candidate["project_id"],
         "core_target":candidate["target"],"provider_target":provider_path,
         "source_sha":candidate["source_sha"],"source_sha256":candidate["source_sha256"],
         "model":candidate["model"],"input_sha256":trusted_input_digest}
    r = {"schema":REQ_SCHEMA,"task_id":b["task_id"],"project_id":b["project_id"],
         "input_sha256":trusted_input_digest,"target_path":provider_path,
         "instruction":candidate["objective"]}
    p = {"schema":BRIDGE_SCHEMA,"request":r,"binding":b,
         "permissions":{"execution":False,"retry":False,"publication":False,"paid_api":False}}
    _validate_packet(p)
    if (type(candidate["reserved_units"]) is not int or
        not 1 <= candidate["reserved_units"] <= 100000 or
        not callable(trusted_mapping_verifier) or
        trusted_mapping_verifier(dict(b), dict(r)) is not True):
        raise WireError("trusted CORE path and snapshot mapping not available")
    return p

def summarize_reply(packet, result):
    """Accept only a model file *proposal*, never treat it as source commit."""
    _validate_packet(packet)
    if type(result) is not dict or not PROVIDER_REPLY_REQUIRED.issubset(result):
        raise WireError("missing provider result fields")
    if set(result) - PROVIDER_REPLY_REQUIRED - {"observed_local_reply","resources"}:
        raise WireError("unexpected provider result fields")
    r,b = packet["request"],packet["binding"]
    if (result["schema"] != RESULT_SCHEMA or
        result["task_id"] != r["task_id"] or
        result["project_id"] != r["project_id"] or
        result["input_sha256"] != r["input_sha256"] or
        result["model"] != b["model"] or result["provider"] != "ollama-loopback" or
        result["offline_mock"] is not False or type(result["api_cost_usd"]) is not int or result["api_cost_usd"] != 0 or
        result["review_approved"] is not False or result["published"] is not False or
        type(result["attempt_consumed"]) is not bool or
        type(result["proposed_files"]) is not list):
        raise WireError("unsafe or unbound result")
    status = result["status"]
    if status not in ("PROPOSED_UNVERIFIED","BLOCKED","INVALID_MODEL_OUTPUT"):
        raise WireError("unknown provider outcome")
    proposed = result["proposed_files"]
    if status != "PROPOSED_UNVERIFIED":
        if proposed or type(result["error_code"]) is not str or not result["error_code"]:
            raise WireError("blocked result must contain only an error")
        return {"schema":1,"status":"BLOCKED","task_id":b["task_id"],
                "source_sha":b["source_sha"],"provider_status":status,
                "automatic_retry_allowed":False,"publication_allowed":False,
                "source_verified":False,"model_output_digest":None}
    if (result["error_code"] is not None or len(proposed)!=1 or
        result.get("observed_local_reply") is not True or
        result["attempt_consumed"] is not True or
        not _hex(result["prompt_sha256"],SHA64) or
        not _hex(result["response_sha256"],SHA64)):
        raise WireError("invalid successful proposal proof")
    file = proposed[0]
    if (type(file) is not dict or set(file) != {
        "relative_path","content","content_sha256","applied","verified_by_core"
    } or file["relative_path"] != r["target_path"] or
        file["applied"] is not False or file["verified_by_core"] is not False or
        type(file["content"]) is not str or
        not 1 <= len(file["content"]) <= 12000 or
        hashlib.sha256(file["content"].encode("utf-8")).hexdigest() != file["content_sha256"]):
        raise WireError("unsafe proposal content")
    return {"schema":1,"status":"RESPONSE_UNVERIFIED","task_id":b["task_id"],
            "source_sha":b["source_sha"],"provider_status":status,
            "proposed_path":file["relative_path"],
            "proposed_content_sha256":file["content_sha256"],
            "model_output_digest":result["response_sha256"],
            "source_verified":False,"automatic_retry_allowed":False,
            "publication_allowed":False}
