"""Independent limited Qwen3 safety audit of exact Neurofactory Stage5 queue sources.

Read-only, CPU-local, no GitHub write token, no publication. A missing verdict is not approval.
"""
import hashlib,json,os,pathlib,urllib.request
ROOT=pathlib.Path(__file__).resolve().parent
GROUPS=[
 {"name":"durability_and_queue","files":["stage5_development_queue.py","stage5_remote_journal.py"],
  "question":"Find concrete unsafe replay after a crash, stale-runner overwrite, forged queue identity, foreign file write, task skip, or lost remote checkpoint."},
 {"name":"receipt_and_usage","files":["stage5_git_receipts.py","stage5_usage_ledger.py"],
  "question":"Find concrete forged GitHub receipt, authorization bypass, unsafe re-publication, external project scope, or fabricated expense."}
]
FORM={"type":"object","properties":{"verdict":{"type":"string","enum":["REVIEW_OK","REVIEW_BAD"]},
  "reason":{"type":"string"}},"required":["verdict","reason"]}
def ask(prompt):
    data={"model":"qwen3:4b","prompt":prompt[:14500],"stream":False,"think":False,
          "keep_alive":"0","format":FORM,
          "options":{"num_ctx":6000,"num_predict":250,"num_thread":4,"num_gpu":0,"temperature":0}}
    request=urllib.request.Request("http://127.0.0.1:11434/api/generate",
        data=json.dumps(data).encode(),method="POST",headers={"Content-Type":"application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=220) as resp:
        answer=json.load(resp)
    if answer.get("done") is not True:raise ValueError("Unfinished independent model")
    result=json.loads(str(answer.get("response","")))
    if result.get("verdict") not in ("REVIEW_OK","REVIEW_BAD") or len(str(result.get("reason","")))<15:
        raise ValueError("Qwen did not provide actionable independent verdict")
    return result
def main():
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        raise ValueError("Reviewer cannot access any publication credential")
    proofs=[]
    for group in GROUPS:
        sources={n:(ROOT/n).read_text("utf-8") for n in group["files"]}
        hashes={n:hashlib.sha256(s.encode()).hexdigest() for n,s in sources.items()}
        prompt=("You are independent Qwen3:4b security reviewer, NOT developer. "
            "Evaluate ACTUAL enclosed Neurofactory code. Different AI author wrote code, "
            "no API secrets. Scope strictly bridge/neurofactory/development only. "
            "Do NOT infer unspecified surrounding function behavior. "
            "Answer JSON verdict REVIEW_OK or REVIEW_BAD, reason 30-80 words. "
            "If REVIEW_BAD identify exact function and an executable sequence causing "
            "a security, replay or data integrity flaw. "
            "Focus specifically: "+group["question"]+
            "\\nCODE:\\n"+"\\n".join("FILE "+n+"\\n"+s for n,s in sources.items()))
        verdict=ask(prompt)
        proof={"group":group["name"],"files_sha256":hashes,"verdict":verdict["verdict"],
               "reason":str(verdict["reason"])[:1000],"reviewer":"qwen3:4b"}
        proofs.append(proof)
        print("NF5_QWEN_INDEPENDENT_SECURITY",group["name"],proof["verdict"],
              proof["reason"],flush=True)
        if proof["verdict"]!="REVIEW_OK":
            break
    record={"schema":1,"scope":"neurofactory_only","chat_delivery_paused":True,
       "reviewer":"qwen3:4b","proofs":proofs,
       "overall_verdict":"REVIEW_OK" if len(proofs)==len(GROUPS) and all(x["verdict"]=="REVIEW_OK" for x in proofs) else "REVIEW_BAD"}
    (ROOT/"stage5-independent-security-outcome.json").write_text(json.dumps(record,indent=2)+"\n","utf-8")
    if record["overall_verdict"]!="REVIEW_OK":
        raise RuntimeError("Independent review did not approve all queue components")
if __name__=="__main__":main()
