"""Independent limited Qwen3 safety audit of exact Neurofactory Stage5 queue sources.

Read-only, CPU-local, no GitHub write token, no publication. A missing verdict is not approval.
"""
import hashlib,json,os,pathlib,urllib.request
ROOT=pathlib.Path(__file__).resolve().parent
GROUPS=[
 {"name":"remote_checkpoint_and_recovery","files":["stage5_remote_journal.py"],
  "question":"Check the trusted DurableCoordinator.recover() method that reads and compares exact GitHub state before local recovery, then commits it via checkpoint_to_github. Examine stale-runner CAS conflict handling and give exact exploit only if still present."},
 {"name":"serial_queue_core","files":["stage5_development_queue.py"],
  "question":"Examine sequential task issuance, local file identity, portable snapshot validation and the strictly local recover() method. This local queue is used via DurableCoordinator for real remote effects. Identify concrete exploit or unsafe local handling."},
 {"name":"verified_remote_receipts","files":["stage5_git_receipts.py"],
  "question":"Check independent GitHub proof of commit identity, allowed target, ancestry, source hash and Qwen reviewer verification."},
 {"name":"usage_and_paid_guard","files":["stage5_usage_ledger.py"],
  "question":"Check duplicate run ID prevention, foreign project rejection, read-only usage retrieval and risk of treating wall clock as paid costs."}
]
FORM={"type":"object","properties":{"verdict":{"type":"string","enum":["REVIEW_OK","REVIEW_BAD"]},
  "reason":{"type":"string"}},"required":["verdict","reason"]}
def ask(prompt):
    data={"model":"qwen3:4b","prompt":prompt[:13500],"stream":False,"think":False,
          "keep_alive":"0","format":FORM,
          "options":{"num_ctx":5800,"num_predict":280,"num_thread":4,"num_gpu":0,"temperature":0}}
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
        prompt=("Independent Qwen3:4b security review; do not approve flawed code. "
            "Evaluate each exact file below fully, and distinguish local queue methods "
            "from trusted GitHub coordinator that performs remote checkpointing. "
            "Scope is Neurofactory only; no API secrets or ChatGPT sender. "
            "Return JSON verdict REVIEW_OK or REVIEW_BAD with reason 30-80 words. "
            "If REVIEW_BAD identify the exact function and a precise runnable "
            "counterexample in the provided code, not a hypothetical omitted caller. "
            "Examine: "+group["question"]+
            "\\nEXACT SOURCE:\\n"+"\\n".join("FILE "+n+"\\n"+code for n,code in sources.items()))
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
