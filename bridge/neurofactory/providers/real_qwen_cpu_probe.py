"""One genuine CPU-only free Qwen inference on an ephemeral hosted Linux runner.

Provider-owned experimental proof; does NOT run CORE, queue, writer, HF tools
or a service. Never record or act on a model-generated instruction. Skip
when runner RAM/disk budgets are inadequate. No paid endpoints or tokens.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time


MODEL="Qwen/Qwen2.5-0.5B-Instruct"
PROMPT="Ответь одним коротким предложением на русском: зачем программисту автоматические тесты?"

def linux_mem_available_bytes():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1])*1024
    raise RuntimeError("RAM_MISSING_STOP")

def main():
    if (sys.platform!="linux" or os.environ.get("NF_QWEN_REAL_INFERENCE_EXPLICIT_TEST_ONLY")!="1"
            or any(os.environ.get(k) for k in ("OPENAI_API_KEY","ANTHROPIC_API_KEY","HF_TOKEN"))):
        raise RuntimeError("OFFLINE_INFERENCE_TEST_GATE_OR_EXTERNAL_SECRET_PRESENT")
    available=linux_mem_available_bytes()
    disk=shutil.disk_usage("/tmp").free
    print(json.dumps({"status":"RESOURCE_PRECHECK",
       "available_ram_mib":available//1048576,
       "free_temp_disk_mib":disk//1048576,
       "model":MODEL,"paid_api_allowed":False,"project_writes_allowed":False}),flush=True)
    if available<5*1024**3 or disk<4*1024**3:
        print("BLOCKED_RESOURCE_NO_MODEL_STARTED",flush=True)
        return 0
    import torch
    from transformers import AutoModelForCausalLM,AutoTokenizer
    from huggingface_hub import snapshot_download
    start=time.monotonic()
    torch.set_num_threads(2)
    cache="/tmp/nf-qwen-weight-sandbox"
    # Fetch an official public free model only into an ephemeral runner.
    snapshot=snapshot_download(repo_id=MODEL,revision="main",
        local_files_only=False,cache_dir=cache,allow_patterns=[
            "*.safetensors","*.json","tokenizer*","vocab*","merges.txt"])
    if not Path(snapshot).name or len(Path(snapshot).name)!=40:
        raise RuntimeError("MODEL_REVISION_SHA_NOT_OBSERVED")
    tokenizer=AutoTokenizer.from_pretrained(snapshot,trust_remote_code=False,
                                           local_files_only=True)
    model=AutoModelForCausalLM.from_pretrained(snapshot,trust_remote_code=False,
         local_files_only=True,torch_dtype=torch.float32)
    model.eval()
    if not any(p.numel()>0 for p in model.parameters()):
        raise RuntimeError("EMPTY_MODEL_WEIGHTS")
    encoded=tokenizer.apply_chat_template(
        [{"role":"system","content":"Ты кратко отвечаешь на русском языке."},
         {"role":"user","content":PROMPT}],
        add_generation_prompt=True,return_tensors="pt")
    with torch.inference_mode():
        result=model.generate(encoded,max_new_tokens=48,do_sample=False,
                              pad_token_id=tokenizer.eos_token_id)
    generated_ids=result[0,encoded.shape[-1]:]
    actual_text=tokenizer.decode(generated_ids,skip_special_tokens=True).strip()
    if not actual_text or len(actual_text)>700:
        raise RuntimeError("MODEL_FAILED_TO_GENERATE_BOUNDED_TEXT")
    print(json.dumps({
       "status":"REAL_QWEN_GENERATION_OBSERVED_NO_SIDE_EFFECTS",
       "model":MODEL,
       "model_revision_sha40":Path(snapshot).name,
       "parameter_count":sum(p.numel() for p in model.parameters()),
       "model_device":str(next(model.parameters()).device),
       "generated_tokens":len(generated_ids),
       "actual_text":actual_text,
       "response_sha256":hashlib.sha256(actual_text.encode()).hexdigest(),
       "elapsed_seconds":round(time.monotonic()-start,1),
       "offline_mock":False,"project_files_modified":False,
       "paid_api_allowed":False,"publication_allowed":False,
       "core_execution_allowed":False},ensure_ascii=False),flush=True)
    return 0

if __name__=="__main__":
    try:sys.exit(main())
    except Exception as exc:
        print(json.dumps({"status":"QWEN_REAL_INFERENCE_NOT_VERIFIED",
            "error_type":type(exc).__name__,
            "paid_api_allowed":False,"core_execution_allowed":False}),flush=True)
        sys.exit(2)
