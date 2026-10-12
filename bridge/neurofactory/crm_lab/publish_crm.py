"""Restricted publisher for separately reviewed synthetic Qwen CRM.
Never imports or executes generated CRM source with publishing credentials.
"""
import base64,hashlib,json,os,pathlib,urllib.error,urllib.request
OUTPUT=pathlib.Path("/tmp")/("crm_generated_"+os.environ.get("GITHUB_RUN_ID","local"))
DEST="bridge/neurofactory/pilots/third_crm_qwen_cloud/"
ALLOWED=("storage.py","crm.py","main.py","architecture-plan.json","verification-manifest.json")
REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-crm-autonomous-20261012"
def put(token,name,payload):
    if name not in ALLOWED:raise ValueError("Unknown output file")
    path=DEST+name
    h={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
       "Content-Type":"application/json","User-Agent":"NeurofactoryCRMVerifiedPublisher"}
    url="https://api.github.com/repos/"+REPO+"/contents/"+path
    try:
        req=urllib.request.Request(url+"?ref="+BRANCH,headers=h)
        with urllib.request.urlopen(req,timeout=22) as r:old=json.load(r)
        existing=base64.b64decode(old["content"].replace("\n",""))
        if existing==payload:return
        raise ValueError("Existing published file differs; overwrite denied")
    except urllib.error.HTTPError as e:
        if e.code!=404:raise
    data={"branch":BRANCH,"message":"neurofactory: independently verified autonomous CRM "+name,
          "content":base64.b64encode(payload).decode("ascii")}
    req=urllib.request.Request(url,method="PUT",data=json.dumps(data).encode(),headers=h)
    with urllib.request.urlopen(req,timeout=25) as r:
        if r.status not in (200,201):raise ValueError("Publishing failed")
def main():
    token=os.environ.get("GITHUB_TOKEN")
    if not token or os.environ.get("GITHUB_REPOSITORY")!=REPO or os.environ.get("GITHUB_REF_NAME")!=BRANCH:
        raise ValueError("Publisher not authorized")
    manifest=json.loads((OUTPUT/"verification-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("status")!="two_models_reviewed" or manifest.get("review_verdict")!="REVIEW_OK":
        raise ValueError("Independent review not approved")
    if manifest.get("tests_passed")!=20 or set(manifest.get("source_modules",[]))!={"storage.py","crm.py","main.py"}:
        raise ValueError("Independent acceptance evidence missing")
    if manifest.get("architecture_model")!="qwen3:4b" or manifest.get("writer")!="qwen2.5-coder:3b" or manifest.get("reviewer")!="qwen3:4b":
        raise ValueError("Unproven model provenance")
    if set(manifest.get("sha256",{}))!={"storage.py","crm.py","main.py"}:raise ValueError("Incomplete hashes")
    for name in ("storage.py","crm.py","main.py"):
        if hashlib.sha256((OUTPUT/name).read_bytes()).hexdigest()!=manifest["sha256"][name]:
            raise ValueError("Model-generated file modified after tests")
    plan=json.loads((OUTPUT/"architecture-plan.json").read_text(encoding="utf-8"))
    if sorted(z["file"] for z in plan["modules"])!=sorted(["storage.py","crm.py","main.py"]):
        raise ValueError("Unapproved architecture")
    for name in ALLOWED:
        put(token,name,(OUTPUT/name).read_bytes())
    print("CRM generated, 20 objective tests passed, second Qwen approved, five files published.")
if __name__=="__main__":
    try:main()
    except Exception as e:
        print("SAFE_PUBLICATION_BLOCKED:",type(e).__name__,str(e)[:240])
        raise SystemExit(1)
