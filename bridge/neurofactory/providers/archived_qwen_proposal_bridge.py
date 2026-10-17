"""Strict offline repackaging of PREVIOUSLY observed genuine Qwen output.

This does not call the model again. The exact response hash and model revision
are pinned to a previously successful hosted Actions run, but a hash is NOT
an owner authorization or independent model provenance proof. Converts text
to one untrusted bounded .txt PROPOSAL for the existing result.v1 shape.
No file writes, no CORE queue, no live worker or file application.
"""
from __future__ import annotations
import hashlib
import re

_MODEL="Qwen/Qwen2.5-0.5B-Instruct"
_REVISION="7ae557604adf67be50417f59c2c2f167def9a775"
_OBSERVED="0a4215b15a5f936050147a658ee4468b2a00e94f2a65ccf20b48513c89ded305"
_SHA64=re.compile(r"[0-9a-f]{64}\Z")
_ID=re.compile(r"[A-Za-z0-9_-]{3,64}\Z")
_TARGET=re.compile(r"docs/[A-Za-z0-9_-]{1,64}\.txt\Z")
_PROMPT="Ответь одним коротким предложением на русском: зачем программисту автоматические тесты?"

class ArchivedQwenBlocked(ValueError):pass

def convert_observed_qwen_to_unverified_result(*,request,observed):
    """Caller must pass an explicitly preselected, synthetic, safe task."""
    if (type(request) is not dict or set(request)!={"schema","task_id","project_id",
             "input_sha256","target_path","instruction"} or
        request["schema"]!="neurofactory.providers.request.v1" or
        type(request["task_id"]) is not str or not _ID.fullmatch(request["task_id"]) or
        type(request["project_id"]) is not str or not _ID.fullmatch(request["project_id"]) or
        request["project_id"]!="nf-sandbox" or
        type(request["input_sha256"]) is not str or not _SHA64.fullmatch(request["input_sha256"]) or
        type(request["target_path"]) is not str or not _TARGET.fullmatch(request["target_path"]) or
        type(request["instruction"]) is not str or request["instruction"]!=_PROMPT or
        type(observed) is not dict or
        set(observed)!={"model","revision","text","text_sha256","generated_tokens","offline_mock",
                        "source_actions_run"}):
        raise ArchivedQwenBlocked("unknown request/observed schema or non-sandbox project")
    text=observed["text"]
    if (observed["model"]!=_MODEL or observed["revision"]!=_REVISION or
        observed["source_actions_run"]!=39057951286 or
        observed["offline_mock"] is not False or
        type(observed["generated_tokens"]) is not int or
        observed["generated_tokens"]!=19 or
        type(text) is not str or not 1<=len(text.encode("utf8"))<=500 or
        any(ord(x)<32 or ord(x)==127 for x in text) or
        observed["text_sha256"]!=_OBSERVED or
        hashlib.sha256(text.encode("utf8")).hexdigest()!=_OBSERVED):
        raise ArchivedQwenBlocked("not pinned previous genuine model text")
    return {
      "schema":"neurofactory.providers.result.v1",
      "status":"PROPOSED_UNVERIFIED",
      "task_id":request["task_id"],"project_id":request["project_id"],
      "input_sha256":request["input_sha256"],
      "provider":"transformers-cpu-archived-proof",
      "model":_MODEL,"model_revision":_REVISION,
      "offline_mock":False,"api_cost_usd":0,
      "review_approved":False,"published":False,
      "proposed_files":[{
        "relative_path":request["target_path"],
        "content":text,
        "content_sha256":_OBSERVED,
        "applied":False,"verified_by_core":False}],
      "response_sha256":_OBSERVED,
      "prompt_sha256":hashlib.sha256(_PROMPT.encode("utf8")).hexdigest(),
      "error_code":None,"attempt_consumed":False,
      "resources":{"model_generation_cpu":"GITHUB_HOSTED_PREVIOUSLY_VERIFIED",
          "run_id":39057951286,"execution_happened_in_this_call":False},
      "provenance":"ARCHIVED_TEST_LOG_NO_NEW_MODEL_CALL",
      "trusted_core_binding":False,
      "compatible_with_current_ollama_only_runner":False,
      "effect_authorization":False,
    }
