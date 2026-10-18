"""One actual pinned public Qwen CPU generation on disposable Windows Actions.

No Ollama simulation, no project output/CORE/HOST write, no secrets or APIs.
This is not independent hardware/weights attestation or integrated release.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

REPO="Qwen/Qwen2.5-0.5B-Instruct"
REVISION="7ae557604adf67be50417f59c2c2f167def9a775"
PROMPT="Answer in English with one short sentence: what is the purpose of unit tests?"

def main():
    if (os.name!="nt" or os.getenv("GITHUB_ACTIONS")!="true" or
        os.getenv("RUNNER_ENVIRONMENT")!="github-hosted" or
        os.getenv("NF_REAL_QWEN_WINDOWS_TEST_ONLY")!="1" or
        any(os.getenv(k) for k in ("OPENAI_API_KEY","ANTHROPIC_API_KEY","HF_TOKEN","HUGGING_FACE_HUB_TOKEN"))):
        raise RuntimeError("HOSTED_WINDOWS_FREE_LOCAL_INFERENCE_REQUIRED")
    import ctypes
    class Memory(ctypes.Structure):
        _fields_=[("dwLength",ctypes.c_ulong),("dwMemoryLoad",ctypes.c_ulong),
                  ("ullTotalPhys",ctypes.c_ulonglong),("ullAvailPhys",ctypes.c_ulonglong),
                  ("ullTotalPageFile",ctypes.c_ulonglong),("ullAvailPageFile",ctypes.c_ulonglong),
                  ("ullTotalVirtual",ctypes.c_ulonglong),("ullAvailVirtual",ctypes.c_ulonglong),
                  ("ullAvailExtendedVirtual",ctypes.c_ulonglong)]
    info=Memory()
    info.dwLength=ctypes.sizeof(Memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(info)):
        raise RuntimeError("WINDOWS_RAM_PRECHECK_FAILED")
    cache=Path(os.environ["RUNNER_TEMP"])/"neurofactory-real-qwen-weights"
    free_disk=shutil.disk_usage(cache.parent).free
    print(json.dumps({"status":"NF_QWEN_WINDOWS_RESOURCE_PRECHECK",
          "free_ram_mib":info.ullAvailPhys//1048576,
          "free_disk_mib":free_disk//1048576,
          "model":REPO,"required_min_ram_mib":5000,
          "mock_used":False,"production_queue_allowed":False}),flush=True)
    if info.ullAvailPhys<5*1024**3 or free_disk<6*1024**3:
        raise RuntimeError("HOSTED_WINDOWS_INSUFFICIENT_RESOURCE_NO_DOWNLOAD")
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from huggingface_hub import snapshot_download
    torch.set_num_threads(2)
    started=time.monotonic()
    downloaded=Path(snapshot_download(
        repo_id=REPO, revision=REVISION, cache_dir=str(cache),
        local_files_only=False,
        allow_patterns=["*.safetensors","*.json","tokenizer*","vocab*","merges.txt"]))
    if downloaded.name!=REVISION:
        raise RuntimeError("WEIGHTS_REVISION_NOT_PINNED")
    tokenizer=AutoTokenizer.from_pretrained(str(downloaded),
            local_files_only=True,trust_remote_code=False)
    model=AutoModelForCausalLM.from_pretrained(str(downloaded),
            local_files_only=True,trust_remote_code=False,
            torch_dtype=torch.float32)
    model.eval()
    params=sum(int(p.numel()) for p in model.parameters())
    if params<490_000_000 or params>500_000_000 or str(next(model.parameters()).device)!="cpu":
        raise RuntimeError("ACTUAL_WEIGHTS_OR_DEVICE_UNEXPECTED")
    tokens=tokenizer.apply_chat_template([
        {"role":"system","content":"You write concise English answers."},
        {"role":"user","content":PROMPT}],add_generation_prompt=True,return_tensors="pt")
    with torch.inference_mode():
        generated=model.generate(tokens,max_new_tokens=32,
                                 do_sample=False,pad_token_id=tokenizer.eos_token_id)
    answer_ids=generated[0,tokens.shape[-1]:]
    answer=tokenizer.decode(answer_ids,skip_special_tokens=True).strip()
    if not answer or len(answer.encode("utf-8"))>800:
        raise RuntimeError("REAL_MODEL_RETURNED_NO_BOUNDED_TEXT")
    report={
        "status":"NF_REAL_QWEN_WEIGHTS_CPU_GENERATED_WINDOWS_UNATTESTED",
        "schema":"neurofactory.onepc.real_qwen_windows_test.v1",
        "model":REPO,"model_revision":REVISION,"parameters":params,
        "device":"cpu","generated_tokens":int(len(answer_ids)),
        "prompt_sha256":hashlib.sha256(PROMPT.encode()).hexdigest(),
        "response_sha256":hashlib.sha256(answer.encode()).hexdigest(),
        "answer_text_not_persisted":True,
        "elapsed_seconds":round(time.monotonic()-started,1),
        "real_weights_loaded":True,"http_stub":False,
        "core_dispatch_enabled":False,"host_effect_enabled":False,
        "independent_review_complete":False,"owner_pc_tested":False,
    }
    dest=Path(os.environ["RUNNER_TEMP"])/"nf-real-qwen-windows-result.json"
    dest.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(report,sort_keys=True),flush=True)


if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(json.dumps({"status":"NF_REAL_QWEN_WINDOWS_NOT_VERIFIED",
             "reason":type(exc).__name__,"owner_pc_modified":False,
             "host_effect_enabled":False,"core_dispatch_enabled":False}),flush=True)
        sys.exit(2)
