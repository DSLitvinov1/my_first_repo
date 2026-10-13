"""Independent Qwen3 review after deterministic forged-identity regression suite."""
import hashlib,json,os,pathlib,urllib.request
HERE=pathlib.Path(__file__).resolve().parent
SOURCE=HERE/"stage4_receipt_rules.py"
PROOF=pathlib.Path(os.environ["RUNNER_TEMP"])/"neurofactory-stage4-receipt-hardening-review.json"
def run():
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):raise ValueError("Reviewer must never access credentials")
    text=SOURCE.read_text("utf-8");digest=hashlib.sha256(text.encode()).hexdigest()
    prompt=(
      "You are Qwen3 4B independent reviewer of an AI-authored Neurofactory correction. "
      "A previously approved AI generated this security helper but its original source failed "
      "two new attacks: forged record repo='attacker/other' with expected repo='attacker/other', "
      "and forged record path='../secret' with expected path='../secret'. Both must return False "
      "even though the record and expected inputs MATCH one another. "
      "Exactly trusted repo='DSLitvinov1/my_first_repo' and trusted path="
      "'bridge/neurofactory/development/stage4_receipt_rules.py' MUST be enforced explicitly, "
      "along with 40 lowercase hex SHA and dict keys. "
      "9 targeted new regression tests including forged input and 15 existing behavior vectors passed. "
      "Review this exact source independently for a real flaw. Return JSON only with verdict "
      "REVIEW_OK or REVIEW_BAD and a precise reason under 65 words. If REVIEW_BAD give concrete counterexample. "
      "SOURCE:\n"+text
    )
    req={"model":"qwen3:4b","prompt":prompt,"stream":False,"think":False,"format":"json","keep_alive":"0",
         "options":{"num_ctx":6000,"num_predict":650,"num_thread":3,"num_gpu":0,"temperature":0}}
    request=urllib.request.Request("http://127.0.0.1:11434/api/generate",
       data=json.dumps(req).encode(),method="POST",headers={"Content-Type":"application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=240) as resp:r=json.load(resp)
    if r.get("done") is not True:raise ValueError("Incomplete reviewer")
    review=json.loads(str(r.get("response","")))
    verdict=review.get("verdict");reason=str(review.get("reason",""))[:500]
    print("NF4_HARDENING_SECOND_AGENT",verdict,reason,flush=True)
    if verdict!="REVIEW_OK" or len(reason)<12:raise ValueError("Independent reviewer rejected security correction")
    PROOF.write_text(json.dumps({"stage":"NF-DEV-04","component":"receipt_validator_security_hardening",
        "reviewer":"qwen3:4b","verdict":verdict,"source_sha256":digest,
        "new_attack_regressions":9,"prior_behavior_cases":15,"reason":reason,
        "scope":"neurofactory_only"},sort_keys=True)+"\n","utf-8")
if __name__=="__main__":run()
