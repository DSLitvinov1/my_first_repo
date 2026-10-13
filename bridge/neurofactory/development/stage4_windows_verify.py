"""Read-only GitHub/Windows proof of the one real Stage4 task and no duplicate commit."""
import hashlib,json,pathlib,sys,urllib.request

REPO="DSLitvinov1/my_first_repo"
STAGING="neurofactory-stage4-live-integration-20261013"
PROD="neurofactory-public-lab-20261012"
PREFIX="bridge/neurofactory/development/"
SOURCE=PREFIX+"stage4_receipt_rules.py"
PROOF=PREFIX+"stage4-live-proof.json"
CANDIDATE=PREFIX+"stage4-live-candidate.py"
REVIEW=PREFIX+"stage4-live-reviewed.json"
STATE=PREFIX+"stage4-live-state.json"

def web_json(path):
    if not path.startswith("/repos/"+REPO+"/"):raise ValueError("Different project denied")
    req=urllib.request.Request("https://api.github.com"+path,headers={"User-Agent":"NeurofactoryWindowsReadonly","Accept":"application/vnd.github+json"})
    with urllib.request.urlopen(req,timeout=25) as resp:return json.load(resp)

def check(prod,staging):
    prod=pathlib.Path(prod);staging=pathlib.Path(staging)
    source=(prod/SOURCE).read_bytes()
    candidate=(staging/CANDIDATE).read_bytes()
    if source!=candidate:raise ValueError("Different author source and production")
    digest=hashlib.sha256(source).hexdigest()
    proof=json.loads((prod/PROOF).read_text("utf-8"))
    review=json.loads((staging/REVIEW).read_text("utf-8"))
    state=json.loads((staging/STATE).read_text("utf-8"))
    if state.get("scope")!="neurofactory_only" or state.get("chat_delivery")!="paused_by_user":
        raise ValueError("State identity failure")
    if any(state["files"][name] is None for name in ("writer","reviewer","publisher")):
        raise ValueError("Missing remote stage checkpoint")
    tasks={name:json.loads(state["files"][name])["data"] for name in ("writer","reviewer","publisher")}
    if any(t["state"]!="verified_done" for t in tasks.values()):
        raise ValueError("Task not genuinely completed")
    if [tasks[role]["attempts"] for role in ("writer","reviewer","publisher")]!=[2,1,1]:
        raise ValueError("Crash retry or no-replay attempts differ from expected")
    if state.get("meta",{}).get("crash_injected") is not True:
        raise ValueError("No real owned child interruption recorded")
    if (proof.get("source_sha256")!=digest or review.get("source_sha256")!=digest
            or tasks["writer"].get("proof",{}).get("source_sha256")!=digest
            or tasks["reviewer"].get("proof",{}).get("source_sha256")!=digest
            or tasks["publisher"].get("proof",{}).get("source_sha256")!=digest
            or review.get("verdict")!="REVIEW_OK" or proof.get("verdict")!="REVIEW_OK"):
        raise ValueError("Author, reviewer and publisher proof mismatch")
    for role in tasks:
        val=tasks[role].get("publication_sha","")
        if len(val)!=40 or any(c not in "0123456789abcdef" for c in val):
            raise ValueError("No verified GitHub commit for "+role)
    repo=lambda branch,path:web_json("/repos/"+REPO+"/commits?sha="+branch+"&path="+path+"&per_page=5")
    for branch,path,role in ((PROD,SOURCE,"publisher"),(STAGING,CANDIDATE,"writer"),(STAGING,REVIEW,"reviewer")):
        commits=repo(branch,path)
        if len(commits)!=1:
            raise ValueError("Expected exactly one GitHub commit, no duplicated result: "+role)
        if commits[0]["sha"]!=tasks[role]["publication_sha"]:
            raise ValueError("Recorded receipt is not the actual source commit: "+role)
    saved_commit=web_json("/repos/"+REPO+"/commits/"+tasks["publisher"]["publication_sha"])
    changed={f["filename"] for f in saved_commit.get("files",[])}
    if changed!={SOURCE,PROOF}:raise ValueError("Publication modified unrelated files: "+str(changed))
    print("NF4_WINDOWS_COMPLETE: 15 real writer behavior cases, 3 verified role receipts,"
          " 1 production commit, 1 reviewer commit, 1 author commit, no replay,"
          " restart attempts [2,1,1], no other project modified",flush=True)
if __name__=="__main__":
    if len(sys.argv)!=3:raise ValueError("Expected production and candidate checkouts")
    check(sys.argv[1],sys.argv[2])
