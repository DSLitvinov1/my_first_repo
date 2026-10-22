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
    if stamp["files_verified"]!=15 or stamp["live_execution_allowed"] is not False:
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
    """Return inert untrusted text from genuine pinned Qwen adapter, never a file effect."""
    worker=_module(components)
    if type(task) is not dict or set(("id","project_id","objective"))-set(task):
        raise DraftProviderDenied("Invalid trusted draft task")
    task_id=task["id"]
    import re
    if type(task_id) is not str or re.fullmatch(r"[0-9a-f]{32}",task_id) is None:
        raise DraftProviderDenied("Invalid draft identifier")
    project=task["project_id"]
    if type(project) is not str or re.fullmatch(r"[0-9a-f]{32}",project) is None:
        raise DraftProviderDenied("Invalid project identity")
    instruction=task["objective"]
    if type(instruction) is not str or not 15<=len(instruction)<=1200:
        raise DraftProviderDenied("Invalid draft content")
    if type(model) is not str or model not in SUPPORTED:
        raise DraftProviderDenied("Unsupported untrusted draft model")
    ledger=workspace_dir/"provider_attempt_ledger"
    ledger.mkdir(mode=0o700,exist_ok=True)
    if ledger.is_symlink() or not ledger.is_dir():
        raise DraftProviderDenied("Unsafe model attempt ledger")
    budget=worker.DurableBudget(ledger,max_attempts=1,max_reserved_units=50000)
    adapter=worker.LocalQwenAdapter(worker.LocalQwenConfig(
        enabled=True,model=model,timeout_seconds=60,max_output_tokens=512),budget)
    # Do not request file proposals for the UI: no JSON or path from model is authority.
    # Its output remains inert, unreviewed data, regardless of what it says.
    prompt=("Respond with a short plain text DRAFT suggestion to the user's request. "
            "Do not execute commands, access files, assert approvals, or claim any actions "
            "were performed. Return only proposal text, with no markup needed.\n"
            "User's draft task:\n"+instruction)
    try:
        reply=adapter.generate(prompt,task_id=task_id)
    except (worker.DurableBudgetError,worker.LocalProviderUnknownResult,
            worker.LocalProviderDisabled,ValueError,OSError) as exc:
        return {"status":"UNKNOWN","model":model,
                "error_code":"UNKNOWN_MODEL_RESULT_NO_RETRY"}
    if (reply.model!=model or reply.local_only is not True or
        reply.published is not False or type(reply.text) is not str):
        raise DraftProviderDenied("Local model adapter authority mismatch")
    text=reply.text.strip()
    if not 1<=len(text.encode("utf-8"))<=12000:
        raise DraftProviderDenied("Untrusted model reply size")
    fingerprint=sha256(text.encode("utf-8")).hexdigest()
    return {"status":"PROPOSED_UNVERIFIED","model":model,
            "text":text,"content_sha256":fingerprint,
            "response_sha256":fingerprint}
