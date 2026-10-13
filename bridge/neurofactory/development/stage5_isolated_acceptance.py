"""Isolated REAL GitHub durability acceptance; no model call or production write."""
import base64,hashlib,json,os,pathlib,urllib.error,urllib.request
from stage5_development_queue import DevelopmentQueue
from stage5_remote_journal import _validate

REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-stage5-isolated-journal-20261013"
PATH="bridge/neurofactory/development/stage5-isolated-state-proof.json"
ROOT=pathlib.Path(__file__).resolve().parent
OBJECTIVE={"id":"NF-DEV-05-Q091","target":"bridge/neurofactory/development/stage5_isolated_acceptance.py",
"objective":"Prove real GitHub checkpoint state remains unchanged between separate free runners"}
OBJECTIVE2={"id":"NF-DEV-05-Q092","target":"bridge/neurofactory/development/stage5_isolated_recovery.py",
"objective":"Verify second approved job remains queued after first job checkpoint persisted"}
API="https://api.github.com/repos/"+REPO+"/contents/"+PATH
def remote(method,body=None):
    token=os.getenv("GITHUB_TOKEN")
    hdr={"Accept":"application/vnd.github+json","User-Agent":"NeurofactoryStage5IsolatedReceipt"}
    if token:hdr["Authorization"]="Bearer "+token
    req=urllib.request.Request(API+("?ref="+BRANCH if method=="GET" else ""),
       method=method,headers=hdr,data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req,timeout=30) as response:return json.load(response)
    except urllib.error.HTTPError as e:
        if e.code==404 and method=="GET":return None
        raise
def canonical(x):return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()
def read():
    result=remote("GET")
    if result is None:return None
    if result.get("path")!=PATH:raise ValueError("Unsafe response")
    obj=json.loads(base64.b64decode(result["content"]))
    _validate(obj)
    return obj,result["sha"]
def main():
    import sys,tempfile
    phase=sys.argv[1]
    hosted = os.getenv("GITHUB_REPOSITORY")==REPO and os.getenv("GITHUB_REF_NAME")==BRANCH
    windows_audit = (phase=="recover" and os.getenv("NF_STAGE5_WINDOWS_READONLY")=="yes"
                     and os.getenv("GITHUB_REPOSITORY")=="DSLitvinov1/lesson3.1")
    if not (hosted or windows_audit):
        raise ValueError("Wrong project or branch, abort")
    plan=json.loads((ROOT/"roadmap.json").read_text("utf-8"))
    if plan.get("chat_delivery_paused") is not True or plan.get("free_only") is not True:
        raise ValueError("User safety settings changed")
    jobs=[OBJECTIVE,OBJECTIVE2]
    with tempfile.TemporaryDirectory(prefix="neurofactory-stage5-real-github-") as t:
        q=DevelopmentQueue(t,plan,jobs)
        if phase=="write":
            if read() is not None:raise ValueError("Cannot overwrite earlier checkpoint")
            q.prepare()
            q.claim(OBJECTIVE["id"],"writer",100,10)
            saved=q.sealed_snapshot()
            data={"branch":BRANCH,"message":"neurofactory test-only stage5 one-time remote checkpoint",
              "content":base64.b64encode(canonical(saved)+b"\n").decode()}
            if not os.getenv("GITHUB_TOKEN"):raise ValueError("Only authorized publisher may write")
            receipt=remote("PUT",data)
            actual=read()
            if actual is None or actual[0]!=saved:raise ValueError("Remote bytes mismatch after actual commit")
            print("STAGE5_REAL_GITHUB_INITIAL_WRITE_VERIFIED",receipt["commit"]["sha"],saved["sha256"],flush=True)
        elif phase=="recover":
            original=read()
            if original is None:raise ValueError("No checkpoint from prior workflow")
            q.restore_snapshot(original[0])
            state=q.snapshot()
            if state[OBJECTIVE["id"]]["writer"]["attempts"]!=1 or state[OBJECTIVE["id"]]["writer"]["state"]!="running":
                raise ValueError("Lost durable first task")
            if state[OBJECTIVE2["id"]]["writer"]["state"]!="queued":raise ValueError("Second task not waiting")
            if q.sealed_snapshot()!=original[0]:raise ValueError("Restored snapshot differs")
            if read()!=original:raise ValueError("Duplicate or changed remote write")
            try:q.claim(OBJECTIVE["id"],"writer",101,10)
            except Exception:pass
            else:raise ValueError("Duplicate claim accepted")
            print("STAGE5_REAL_GITHUB_RESTORED_NO_REPLAY",original[0]["sha256"],original[1],flush=True)
        else:raise ValueError("Unknown phase")
if __name__=="__main__":main()
