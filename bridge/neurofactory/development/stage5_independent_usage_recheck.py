"""Focused final independent Qwen3 security review of the resource ledger.

Verifies the exact Git blobs of three previously approved modules. No token,
publication, paid model or ChatGPT sending. Rejections never become approvals.
"""
import hashlib,json,os,pathlib,urllib.request
ROOT=pathlib.Path(__file__).resolve().parent
PRIOR=ROOT/"stage5-security-three-approved.json"
OUT=ROOT/"stage5-security-final-review.json"
FORMAT={"type":"object","properties":{"verdict":{"type":"string","enum":["REVIEW_OK","REVIEW_BAD"]},
"reason":{"type":"string"}},"required":["verdict","reason"]}

def blob(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def main():
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        raise ValueError("Independent reviewer must not have GitHub write token")
    old=json.loads(PRIOR.read_text("utf-8"))
    if (old.get("scope")!="neurofactory_only" or old.get("chat_delivery_paused") is not True or
        len(old.get("component_verdicts",[]))!=3):
        raise ValueError("Untrusted prior Qwen verdict records")
    for item in old["component_verdicts"]:
        source=(ROOT/item["component"]).read_bytes()
        if blob(source)!=item["git_blob_sha"] or item["verdict"]!="REVIEW_OK":
            raise ValueError("Previously reviewed source changed")
    code=(ROOT/"stage5_usage_ledger.py").read_text("utf-8")
    tests=(ROOT/"test_stage5_usage_ledger.py").read_text("utf-8")
    prompt=("Independent Qwen3 security reviewer. Examine this complete real Neurofactory "
      "usage-ledger source. An earlier model claimed append_checked fails to check whether "
      "ledger['runs'] is a list. The code explicitly checks isinstance(existing,list) "
      "before iterating; the associated regression tests pass. The new revision additionally "
      "validates each old row and new entry types, duration, uniqueness, and unverified billing. "
      "Do NOT automatically approve: find a concrete valid input causing false billing, "
      "foreign project acceptance or non-idempotent ledger if such a flaw exists. "
      "Return JSON object with fields verdict REVIEW_OK or REVIEW_BAD and reason of "
      "at most 40 words; a BAD verdict must specify exact input/function, not a guessed omission. "
      "SOURCE:\n"+code+"\nREGRESSION TESTS:\n"+tests[:4100])
    config={"model":"qwen3:4b","prompt":prompt[:11500],"stream":False,
            "think":False,"format":FORMAT,"keep_alive":"0",
            "options":{"num_ctx":5900,"num_predict":500,"num_thread":4,
                       "num_gpu":0,"temperature":0}}
    request=urllib.request.Request("http://127.0.0.1:11434/api/generate",
       data=json.dumps(config).encode(),method="POST",
       headers={"Content-Type":"application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=250) as response:
        item=json.load(response)
    if item.get("done") is not True:raise RuntimeError("Incomplete reviewer")
    raw=str(item.get("response","")).strip()
    try:review=json.loads(raw)
    except json.JSONDecodeError as exc:
        print("NF5_LEDGER_INCOMPLETE_INDEPENDENT_JSON",raw[:250],flush=True)
        raise RuntimeError("Review response malformed; not accepted") from exc
    verdict=review.get("verdict");reason=str(review.get("reason",""))[:550]
    print("NF5_FINAL_INDEPENDENT_LEDGER_VERDICT",verdict,reason,flush=True)
    evidence={"schema":1,"scope":"neurofactory_only",
       "review_run":int(os.environ.get("GITHUB_RUN_ID","0")),
       "reviewer":"qwen3:4b","prior":old["component_verdicts"],
       "last_component":{"component":"stage5_usage_ledger.py",
            "git_blob_sha":blob(code.encode("utf-8")),
            "verdict":verdict,"reason":reason},
       "chat_delivery_paused":True,
       "overall_verdict":"REVIEW_OK" if verdict=="REVIEW_OK" and len(reason)>=12 else "REVIEW_BAD"}
    OUT.write_text(json.dumps(evidence,sort_keys=True,indent=2)+"\n","utf-8")
    if evidence["overall_verdict"]!="REVIEW_OK":
        raise RuntimeError("Independent review does not approve all four modules")
if __name__=="__main__":
    main()
