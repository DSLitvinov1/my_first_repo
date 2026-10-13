"""Complete independent Stage5 security review without repeating an attested first module.

A specific prior Qwen3 result is pinned to its immutable Git blob. Other modules
are reviewed independently on this free read-only runner. Never infer approval.
"""
import hashlib,json,os,pathlib,urllib.request

ROOT=pathlib.Path(__file__).resolve().parent
PAST=ROOT/"stage5-security-partial-review.json"
OUT=ROOT/"stage5-security-tail-verdict.json"
TAIL=[
 ("serial_queue_core","stage5_development_queue.py","Inspect serial issuance, task manifests, local restore and duplicate protection."),
 ("verified_remote_receipts","stage5_git_receipts.py","Inspect GitHub exact path, commit ancestry, source hash and Qwen reviewer identity."),
 ("usage_without_billing","stage5_usage_ledger.py","Inspect append-only run identity, foreign project rejection and no invented costs.")
]
FORMAT={"type":"object","properties":{
   "verdict":{"type":"string","enum":["REVIEW_OK","REVIEW_BAD"]},
   "reason":{"type":"string"}},"required":["verdict","reason"]}

def git_blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def ask(prompt):
    config={"model":"qwen3:4b","prompt":prompt[:12000],"stream":False,"think":False,
       "format":FORMAT,"keep_alive":"0",
       "options":{"num_ctx":5700,"num_predict":560,"num_thread":4,
                  "num_gpu":0,"temperature":0}}
    req=urllib.request.Request("http://127.0.0.1:11434/api/generate",
       data=json.dumps(config).encode(),method="POST",
       headers={"Content-Type":"application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=260) as f:
        response=json.load(f)
    if response.get("done") is not True:raise ValueError("Unfinished independent Qwen model")
    raw=str(response.get("response","")).strip()
    try:result=json.loads(raw)
    except json.JSONDecodeError as err:
        print("NF5_QWEN_REVIEW_INCOMPLETE_JSON",len(raw),raw[:220],flush=True)
        raise ValueError("Reviewer output not valid JSON") from err
    if result.get("verdict") not in ("REVIEW_OK","REVIEW_BAD"):
        raise ValueError("Missing actionable independent verdict")
    reason=str(result.get("reason",""))[:850]
    if len(reason)<12:raise ValueError("Reviewer did not explain verdict")
    return result["verdict"],reason

def save(report):
    OUT.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n","utf-8")

def main():
    if os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        raise ValueError("No publication credentials for Qwen reviewer")
    earlier=json.loads(PAST.read_text("utf-8"))
    raw=(ROOT/"stage5_remote_journal.py").read_bytes()
    if (earlier.get("review_run")!=38461101666 or
        earlier.get("component_verdict")!="REVIEW_OK" or
        earlier.get("git_blob_sha")!=git_blob(raw) or
        earlier.get("chat_delivery_paused") is not True):
        raise ValueError("Prior positive Qwen3 result not tied to exact code")
    results=[{"component":"stage5_remote_journal.py",
              "source_blob":git_blob(raw),"verdict":"REVIEW_OK",
              "review_run":earlier["review_run"],"reason":earlier["reason"]}]
    report={"schema":1,"project":"НЕЙРОЗАВОД","scope":"neurofactory_only",
            "chat_delivery_paused":True,"reviewer":"qwen3:4b",
            "components":results,"status":"incomplete"}
    save(report)
    for group,name,focus in TAIL:
        code=(ROOT/name).read_text("utf-8")
        prompt=("You are independent Qwen3:4b security reviewer. Examine ALL of this "
          "actual source code written by a different agent. "
          "Return JSON verdict REVIEW_OK or REVIEW_BAD and reason in one or two sentences. "
          "Reject only with a specific executable counterexample in the exact source. "
          "Check this area: "+focus+
          " No ChatGPT messages, no paid API, only bridge/neurofactory/development. "
          "Source file "+name+":\n"+code)
        verdict,reason=ask(prompt)
        results.append({"component":name,"source_blob":git_blob(code.encode("utf-8")),
            "verdict":verdict,"reason":reason,"group":group})
        report["status"]="incomplete"
        save(report)
        print("NF5_QWEN_SECURITY_CONTINUATION",name,verdict,reason,flush=True)
        if verdict!="REVIEW_OK":raise RuntimeError("Independent reviewer rejected "+name)
    report["status"]="REVIEW_OK"
    save(report)
    print("NF5_ALL_FOUR_SECURITY_MODULES_INDEPENDENTLY_APPROVED",flush=True)

if __name__=="__main__":
    main()
