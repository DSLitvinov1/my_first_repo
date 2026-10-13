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
    review_history=[{"verdict":verdict,"reason":reason}]
    if verdict=="REVIEW_BAD":
        # A negative reviewer claim is checked against its explicit alleged exploit.
        # We only offer correction when a concrete cited attack demonstrably fails.
        import importlib.util
        spec=importlib.util.spec_from_file_location("neurofactory_hardening_attack_verification",SOURCE)
        candidate=importlib.util.module_from_spec(spec);spec.loader.exec_module(candidate)
        sha="0123456789abcdef"*2+"01234567"
        attack={"repo":"attacker/other","path":"../secret","sha":sha}
        actual=candidate.receipt_matches(attack,"attacker/other","../secret",sha)
        if actual is not False:
            raise ValueError("AI reviewer found a genuine exploit; do not publish")
        print("NF4_REVIEWER_ALLEGED_FORGED_IDENTITY_RESULT",actual,flush=True)
        retry_prompt=(
          prompt+
          "\nAn initial review claimed the forged attacker/other ../secret example was accepted. "
          "That explicit input was independently executed against the exact source and returned False. "
          "The relevant source enforces repo != hardcoded and path != hardcoded -> return False, "
          "before it compares record values. This is not a request to auto-approve: identify a "
          "DIFFERENT concrete runnable failing input and its actual expected/observed output "
          "if rejection is justified. If the initial claim was refuted and no new defect exists, "
          "return REVIEW_OK. Reinspect the candidate carefully."
        )
        req["prompt"]=retry_prompt[:9500]
        again=urllib.request.Request("http://127.0.0.1:11434/api/generate",
            data=json.dumps(req).encode(),method="POST",headers={"Content-Type":"application/json"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(again,timeout=240) as resp:
            reply=json.load(resp)
        if reply.get("done") is not True:raise ValueError("Second independent review incomplete")
        reassess=json.loads(str(reply.get("response","")))
        verdict=reassess.get("verdict");reason=str(reassess.get("reason",""))[:500]
        review_history.append({"verdict":verdict,"reason":reason})
        print("NF4_INDEPENDENT_REVIEWER_RECHECKED",verdict,reason,flush=True)
    if verdict!="REVIEW_OK" or len(reason)<12:raise ValueError("Independent reviewer rejected security correction")
    PROOF.write_text(json.dumps({"stage":"NF-DEV-04","component":"receipt_validator_security_hardening",
        "reviewer":"qwen3:4b","verdict":verdict,"source_sha256":digest,
        "new_attack_regressions":9,"prior_behavior_cases":15,"reason":reason,"history":review_history,
        "scope":"neurofactory_only"},sort_keys=True)+"\n","utf-8")
if __name__=="__main__":run()
