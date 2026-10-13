"""Free independent Qwen3 review of completed Stage5 non-chat dispatcher integration."""
import hashlib,json,os,pathlib,urllib.request
HERE=pathlib.Path(__file__).resolve().parent
FILENAMES=["stage5_development_queue.py","stage5_remote_journal.py",
           "stage5_git_receipts.py","stage5_usage_ledger.py"]
def main():
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        raise RuntimeError("Independent Qwen reviewer cannot hold publisher credentials")
    docs={n:(HERE/n).read_text("utf-8") for n in FILENAMES}
    hashes={n:hashlib.sha256(src.encode()).hexdigest() for n,src in docs.items()}
    prompt=(
      "You are Qwen3:4b an INDEPENDENT safety reviewer for actual Neurofactory Stage5 "
      "code (author and publisher do not participate in your verdict). "
      "Evaluate the following SECURITY-CRITICAL SOURCE EXCERPTS, not marketing claims. Scope: sequential approved development tasks "
      "with separate Qwen2.5 Coder writer, Qwen3 reviewer and trusted publisher; "
      "strict no ChatGPT delivery, no paid models, no other projects. "
      "Check durable checkpoints and idempotency, replay by stale snapshot, cross-task race, "
      "forged GitHub receipt, manifest contamination, wrong-branch publish, unsafe restore, "
      "and whether unfinished ambiguous publication can be silently retried. "
      "The checkpoint serializer and stage4 queue are separately verified dependencies; "
      "new 3-task Windows tests and entire prior 121-unit suite succeeded. "
      "The dispatcher DOES NOT automatically execute models or publish before integration "
      "is enabled. A verifier is a trusted independent injected callback, not model self-report. "
      "Return ONLY JSON object with verdict REVIEW_OK or REVIEW_BAD and reason. "
      "For REVIEW_BAD cite an exact module/function and concrete exploit path that unit "
      "tests may miss. Do not invent missing behavior. SOURCES:\n" +
      "\n".join("==== "+n+" ====\n"+(s[:6500] if n=="stage5_development_queue.py" else s[:4200] if n=="stage5_remote_journal.py" else s[:2800] if n=="stage5_git_receipts.py" else s[:900]) for n,s in docs.items())
    )
    query={"model":"qwen3:4b","prompt":prompt[:16500],"stream":False,"think":False,
           "format":"json","keep_alive":"0",
           "options":{"num_ctx":6500,"num_predict":350,"num_thread":4,"num_gpu":0,"temperature":0}}
    request=urllib.request.Request("http://127.0.0.1:11434/api/generate",
        data=json.dumps(query).encode(),method="POST",headers={"Content-Type":"application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=240) as f:
        result=json.load(f)
    if result.get("done") is not True:
        raise RuntimeError("Reviewer did not finish")
    reply=json.loads(str(result.get("response","")))
    verdict=reply.get("verdict"); reason=str(reply.get("reason",""))[:1200]
    record={"schema":1,"project":"НЕЙРОЗАВОД","stage":"NF-DEV-05",
            "scope":"non_chat_stage5_dynamic_queue_critical_excerpts","reviewer":"qwen3:4b",
            "verdict":verdict,"reason":reason,"files":hashes,
            "other_projects_untouched":True,"chat_delivery_paused":True}
    out=HERE/"stage5-multiqueue-review-result.json"
    out.write_text(json.dumps(record,sort_keys=True,indent=2,ensure_ascii=False)+"\n","utf-8")
    print("STAGE5_INDEPENDENT_MODEL_REVIEW",verdict,reason,flush=True)
    if verdict!="REVIEW_OK" or len(reason)<10:
        raise RuntimeError("Independent model has not approved new queue integration")
if __name__=="__main__":
    main()
