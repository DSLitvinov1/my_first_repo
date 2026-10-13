"""Trusted single-commit correction, never import or run untrusted generated code."""
import base64,hashlib,json,os,pathlib,sys,urllib.error,urllib.request
import stage4_live_worker as baseline
REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-public-lab-20261012"
SOURCE="bridge/neurofactory/development/stage4_receipt_rules.py"
PROOF="bridge/neurofactory/development/stage4-receipt-hardening-verification.json"
EXPECTED_OLD="745d04659a60589ae808bffcd386a9eb6ae71da8f2222141c854294a5a08ed8c"
ROOT=pathlib.Path(__file__).resolve().parent
BASE="https://api.github.com/repos/"+REPO+"/"
def api(method,url,payload=None):
    if not url.startswith(BASE):raise ValueError("Cross-project GitHub write forbidden")
    secret=os.environ.get("GITHUB_TOKEN")
    if not secret:raise ValueError("Publisher-only GitHub token absent")
    req=urllib.request.Request(url,method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization":"Bearer "+secret,"Accept":"application/vnd.github+json",
                 "Content-Type":"application/json","User-Agent":"NeurofactoryStage4Hardening"})
    with urllib.request.urlopen(req,timeout=35) as resp:
        raw=resp.read()
    return json.loads(raw) if raw else {}
def remote(path):
    try:res=api("GET",BASE+"contents/"+path+"?ref="+BRANCH)
    except urllib.error.HTTPError as e:
        if e.code==404:return None
        raise
    return base64.b64decode(res["content"].replace("\n",""))
def publish():
    if (os.environ.get("GITHUB_REPOSITORY")!=REPO
        or os.environ.get("GITHUB_REF_NAME")!="neurofactory-stage4-receipt-hardening-20261013"
        or os.environ.get("NF_FREE_PUBLIC_CONFIRMED")!="yes"):
        raise ValueError("Only free approved isolated security correction")
    source=(ROOT/"stage4_receipt_rules.py").read_bytes()
    digest,checked=baseline.check(source.decode("utf-8"))
    if checked!=15:raise ValueError("Original acceptance vectors lost")
    review_path=pathlib.Path(os.environ["RUNNER_TEMP"])/"neurofactory-stage4-receipt-hardening-review.json"
    reviewer=json.loads(review_path.read_text("utf-8"))
    if reviewer.get("verdict")!="REVIEW_OK" or reviewer.get("source_sha256")!=digest or reviewer.get("new_attack_regressions")!=9:
        raise ValueError("Independent Qwen3 approval of exact source missing")
    receipt={"stage":"NF-DEV-04","component":"stage4_receipt_rules_security_correction",
       "source_sha256":digest,"previous_source_sha256":EXPECTED_OLD,
       "reviewer":reviewer,"tests_passed":{"old_behavior":15,"forged_attack_regressions":9},
       "mode":"security_correction_not_duplicate_result","scope":"neurofactory_only",
       "chat_delivery":"paused_by_user","original_real_ai_cycle_commit":"4156913b3572bc17b7579ca4cbcc0059c53928cf"}
    rbytes=(json.dumps(receipt,indent=2,sort_keys=True)+"\n").encode("utf-8")
    old=remote(SOURCE);saved=remote(PROOF)
    if saved is not None:
        loaded=json.loads(saved)
        if old==source and loaded.get("source_sha256")==digest:
            print("NF4_HARDENING_ALREADY_PUBLISHED_NO_REPLAY",flush=True)
            return
        raise ValueError("Existing correction mismatches; stop without duplicate")
    if old is None or hashlib.sha256(old).hexdigest()!=EXPECTED_OLD:
        raise ValueError("Source has changed since approved original; manual review needed")
    base_ref=api("GET",BASE+"git/ref/heads/"+BRANCH)["object"]["sha"]
    previous=api("GET",BASE+"git/commits/"+base_ref)
    tree=api("POST",BASE+"git/trees",{"base_tree":previous["tree"]["sha"],
       "tree":[{"path":SOURCE,"mode":"100644","type":"blob","content":source.decode("utf-8")},
               {"path":PROOF,"mode":"100644","type":"blob","content":rbytes.decode("utf-8")}]})
    commit=api("POST",BASE+"git/commits",{"parents":[base_ref],"tree":tree["sha"],
       "message":"neurofactory: Qwen3-reviewed correction for forged Stage4 receipt identity"})
    api("PATCH",BASE+"git/refs/heads/"+BRANCH,{"sha":commit["sha"],"force":False})
    if remote(SOURCE)!=source or remote(PROOF)!=rbytes:
        raise ValueError("Hardened source and review proof did not survive GitHub publication")
    print("NF4_HARDENED_SOURCE_PUBLISHED",commit["sha"],digest,flush=True)
if __name__=="__main__":
    try:publish()
    except Exception as exc:
        print("NF4_HARDENING_SAFE_STOP",type(exc).__name__,str(exc)[:280],flush=True)
        sys.exit(1)
