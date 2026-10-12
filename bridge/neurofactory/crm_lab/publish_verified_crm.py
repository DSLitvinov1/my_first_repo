"""Publish only independently reviewed synthetic Russian CRM modules in the lab branch."""
import base64,hashlib,json,os,urllib.error,urllib.request
from pathlib import Path
import generate_crm as generator

REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-public-lab-20261012"
DEST="bridge/neurofactory/pilots/crm_autonomous_ru/"
API="https://api.github.com/repos/"+REPO+"/contents/"
GENERATED=("storage.py","crm.py","main.py")
SUPPORT=("architecture-plan.json","verification-manifest.json")
NAMES=GENERATED+SUPPORT+("requirements_ru.txt","acceptance_check.py")

def request(token,path,method,payload=None):
    if not path.startswith(DEST) or path[len(DEST):].count("/") or ".." in path:
        raise ValueError("Denied GitHub publication destination")
    headers={"Authorization":"Bearer "+token,
             "Accept":"application/vnd.github+json",
             "Content-Type":"application/json",
             "User-Agent":"NeurofactorySyntheticCRMPublisher"}
    url=API+path+("?ref="+BRANCH if method=="GET" else "")
    content=json.dumps(payload).encode() if payload is not None else None
    req=urllib.request.Request(url,method=method,headers=headers,data=content)
    with urllib.request.urlopen(req,timeout=25) as resp:return json.load(resp)

def integrity_check(manifest):
    if manifest.get("status")!="two_models_reviewed":
        raise ValueError("Missing full two-agent success")
    if manifest.get("writer")!=generator.WRITER or manifest.get("reviewer")!=generator.REVIEWER:
        raise ValueError("Unexpected creator or reviewer provenance")
    if manifest.get("review_verdict")!="REVIEW_OK" or manifest.get("tests_passed")!=20:
        raise ValueError("Independent verification not complete")
    if set(manifest.get("source_modules",[]))!=set(GENERATED):
        raise ValueError("Invalid generated module list")
    if set(manifest.get("sha256",{}))!=set(GENERATED):
        raise ValueError("Missing source file hash")
    for file in GENERATED:
        p=generator.DIR/file
        if p.is_symlink() or p.resolve().parent!=generator.DIR.resolve():
            raise ValueError("Unsafe local source path")
        b=p.read_bytes()
        if hashlib.sha256(b).hexdigest()!=manifest["sha256"][file]:
            raise ValueError("Generated code changed since model verification")
        generator.guard(b.decode("utf-8"))
    plan=json.loads((generator.DIR/"architecture-plan.json").read_text(encoding="utf-8"))
    if sorted(x["file"] for x in plan["modules"])!=sorted(GENERATED):
        raise ValueError("Model planning proof missing")
    success,detail=generator.tests()
    if not success:raise ValueError("Independent tests failed again: "+detail[-350:])
    return True

def put_idempotent(token,path,raw):
    try:
        existing=request(token,path,"GET")
        if base64.b64decode(existing.get("content","").replace("\n",""))==raw:
            return "unchanged"
        raise ValueError("An existing published file has different content; no overwrite")
    except urllib.error.HTTPError as error:
        if error.code!=404:raise
    request(token,path,"PUT",{"branch":BRANCH,
        "message":"neurofactory: verified synthetic CRM "+path[len(DEST):],
        "content":base64.b64encode(raw).decode()})
    return "created"

def publish():
    token=os.environ.get("GITHUB_TOKEN")
    if not token or os.getenv("GITHUB_REPOSITORY")!=REPO or os.getenv("GITHUB_REF_NAME")!=BRANCH:
        raise ValueError("Unauthorized publishing identity")
    file=generator.DIR/"verification-manifest.json"
    manifest=json.loads(file.read_text(encoding="utf-8"))
    integrity_check(manifest)
    for name in GENERATED:
        put_idempotent(token,DEST+name,(generator.DIR/name).read_bytes())
    put_idempotent(token,DEST+"architecture-plan.json",
                   (generator.DIR/"architecture-plan.json").read_bytes())
    put_idempotent(token,DEST+"requirements_ru.txt",
                   (generator.TRUSTED/"requirements_ru.txt").read_bytes())
    put_idempotent(token,DEST+"acceptance_check.py",
                   (generator.TRUSTED/"acceptance_check.py").read_bytes())
    # Manifest is last: its existence is the proof of completed publication.
    put_idempotent(token,DEST+"verification-manifest.json",file.read_bytes())
    print("PUBLISHED VERIFIED SYNTHETIC CRM (all modules and 20 independent tests)")
if __name__=="__main__":
    try:publish()
    except Exception as error:
        print("CRM PUBLISH DENIED:",type(error).__name__,str(error)[:260])
        raise SystemExit(1)
