"""Actual pinned local PROVIDERS proposal for a single UI draft, never a CORE authorization.

The verified installed worker performs the one local Ollama request and its own
durable reservation. The model can only propose an inert fixed docs text file.
No HOST service, queue admission, approvals, publication or file application.
"""
from __future__ import annotations
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys

class DraftProviderDenied(ValueError):
    pass

SUPPORTED=("qwen3:0.6b","qwen2.5-coder:1.5b")

def _module(components: Path):
    local_verify=Path(__file__).resolve().with_name("installed_integrity.py")
    if local_verify.is_symlink() or not local_verify.is_file():
        raise DraftProviderDenied("Pinned verifier missing")
    spec=importlib.util.spec_from_file_location("_nf_draft_verify",local_verify)
    if spec is None or spec.loader is None:
        raise DraftProviderDenied("Pinned verifier cannot load")
    imported=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(imported)
    stamp=imported.verify(components)
    if stamp["files_verified"]!=16 or stamp["live_execution_allowed"] is not False:
        raise DraftProviderDenied("Invalid installed pinned code")
    location=components/"providers"
    if location.is_symlink() or not location.is_dir():
        raise DraftProviderDenied("Provider module unavailable")
    if str(location) not in sys.path:
        sys.path.insert(0,str(location))
    import ollama_worker
    return ollama_worker

def preflight(components: Path, model_preference: str):
    if type(model_preference) is not str or model_preference not in ("auto",)+SUPPORTED:
        raise DraftProviderDenied("Unsupported local Qwen")
    worker=_module(components)
    choices=SUPPORTED if model_preference=="auto" else (model_preference,)
    errors=[]
    for model in choices:
        try:
            worker.check_resources(model)
            return (worker,model)
        except worker.PreflightBlocked as exc:
            errors.append(exc.code)
    # Never reserve a task attempt when no real installed model and adequate RAM.
    raise DraftProviderDenied("LOCAL_QWEN_PREFLIGHT_BLOCKED:"+
                              (errors[-1] if errors else "UNKNOWN"))

def generate(components: Path, workspace_dir: Path, task: dict, *, model: str):
    worker=_module(components)
    if type(task) is not dict or not {"id","project_id","objective"}.issubset(task):
        raise DraftProviderDenied("Invalid trusted draft task")
    task_id=task["id"]
    # DB issues fixed lowercase hexadecimal UUIDs; validate even when called directly.
    import re
    if type(task_id) is not str or re.fullmatch(r"[0-9a-f]{32}",task_id) is None:
        raise DraftProviderDenied("Invalid draft identifier")
    project=task["project_id"]
    if type(project) is not str or re.fullmatch(r"[0-9a-f]{32}",project) is None:
        raise DraftProviderDenied("Invalid project identity")
    instruction=task["objective"]
    if type(instruction) is not str or not 15<=len(instruction)<=1200:
        raise DraftProviderDenied("Invalid draft content")
    target="docs/neurofactory_draft_"+task_id+".txt"
    source=json.dumps({"task_id":task_id,"project_id":project,"objective":instruction},
                      ensure_ascii=False,sort_keys=True,separators=(",",":")).encode("utf-8")
    request=worker.ProviderTask(task_id=task_id,project_id=project,
           input_sha256=sha256(source).hexdigest(),target_path=target,instruction=instruction)
    ledger=workspace_dir/"provider_attempt_ledger"
    ledger.mkdir(mode=0o700,exist_ok=True)
    if ledger.is_symlink():
        raise DraftProviderDenied("Linked provider attempt ledger")
    result=worker.execute_one(request,model=model,ledger_dir=ledger,
                              max_output_tokens=256,evidence_dir=None)
    if (type(result) is not dict or
        result.get("task_id")!=task_id or result.get("project_id")!=project or
        result.get("model")!=model or result.get("review_approved") is not False or
        result.get("published") is not False or
        result.get("offline_mock") is not False):
        raise DraftProviderDenied("Untrusted provider identity or authority")
    state=result.get("status")
    if state=="PROPOSED_UNVERIFIED":
        proposed=result.get("proposed_files")
        if type(proposed) is not list or len(proposed)!=1:
            raise DraftProviderDenied("Expected exactly one untrusted proposal")
        item=proposed[0]
        if (type(item) is not dict or item.get("relative_path")!=target or
            item.get("applied") is not False or
            item.get("verified_by_core") is not False or
            type(item.get("content")) is not str or
            not 1<=len(item["content"].encode("utf-8"))<=12000 or
            sha256(item["content"].encode("utf-8")).hexdigest()!=item.get("content_sha256")):
            raise DraftProviderDenied("Provider proposed unauthorized content")
        response_hash=result.get("response_sha256")
        if type(response_hash) is not str or re.fullmatch(r"[a-f0-9]{64}",response_hash) is None:
            raise DraftProviderDenied("Missing source response fingerprint")
        return {"status":"PROPOSED_UNVERIFIED","model":model,
                "text":item["content"],"content_sha256":item["content_sha256"],
                "response_sha256":response_hash}
    if state in ("INVALID_MODEL_OUTPUT","BLOCKED"):
        return {"status":state,"model":model,"error_code":str(result.get("error_code","UNKNOWN"))[:80]}
    raise DraftProviderDenied("Unknown provider state; manual review required")
