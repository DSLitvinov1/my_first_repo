"""Publisher for ephemeral Qwen cloud pilot with full revalidation and write guard."""
import base64,json,os,pathlib,urllib.error,urllib.request
import ru_crm_factory as engine
ROOT=engine.ROOT
PUBLISH="bridge/neurofactory/pilots/crm_ru_qwen_cloud/"
FILES=tuple(engine.FILES)+("verification-manifest.json",)
API="https://api.github.com/repos/DSLitvinov1/my_first_repo/contents/"
BRANCH="neurofactory-public-lab-20261012"
def request(token,path,method,payload=None):
    if not path.startswith(PUBLISH) or path[len(PUBLISH):].count("/") or ".." in path:
        raise ValueError("Write destination outside approved pilot")
    headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
             "Content-Type":"application/json","User-Agent":"NeurofactoryCloudPublisher"}
    u=API+path+("?ref="+BRANCH if method=="GET" else "")
    data=json.dumps(payload).encode() if payload is not None else None
    with urllib.request.urlopen(urllib.request.Request(u,method=method,data=data,headers=headers),timeout=25) as r:
        return json.load(r)
def verify_crm(manifest):
    if manifest.get("status")!="two_models_reviewed":
        raise ValueError("Model not verified")
    if manifest.get("reviewer",{}).get("model")!=engine.REVIEWER or manifest["reviewer"].get("verdict")!="REVIEW_OK":
        raise ValueError("Independent reviewer missing")
    if manifest.get("tests",{}).get("passed")!=16:
        raise ValueError("Independent CRM tests not passed")
    if set(manifest.get("hashes",{}))!=set(engine.FILES):
        raise ValueError("Unexpected files")
    if set(manifest.get("app_modules",[]))!=set(engine.MODULES):
        raise ValueError("Not all three modules authored")
    for name in engine.FILES:
        data=engine.safe(name).read_bytes()
        if __import__("hashlib").sha256(data).hexdigest()!=manifest["hashes"][name]:
            raise ValueError("Tampered source")
    for name in engine.MODULES:
        engine.validate_source(engine.safe(name).read_text(encoding="utf-8"),name)
    engine.test()
    return True

def publish():
    token=os.environ.get("GITHUB_TOKEN")
    if not token or os.environ.get("GITHUB_REPOSITORY")!="DSLitvinov1/my_first_repo":
        raise ValueError("Missing isolated publisher identity")
    manifest=json.loads(engine.safe("verification-manifest.json").read_text(encoding="utf-8"))
    if not verify_crm(manifest):raise ValueError("Unverified results")
    for name in FILES:
        raw=engine.safe(name).read_bytes()
        path=PUBLISH+name
        try:
            old=request(token,path,"GET")
            encoded=old.get("content","").replace("\n","")
            if base64.b64decode(encoded)==raw:continue
            raise ValueError("Existing published file differs; no overwrite permitted")
        except urllib.error.HTTPError as exc:
            if exc.code!=404:raise
        payload={"branch":BRANCH,"message":"neurofactory: independently verified cloud Qwen "+name,
                  "content":base64.b64encode(raw).decode()}
        request(token,path,"PUT",payload)
    print("All",len(FILES),"files published to isolated verified cloud folder")
if __name__=="__main__":
    try:publish()
    except Exception as exc:
        print("Cloud publisher safely denied:",type(exc).__name__,str(exc)[:220])
        raise SystemExit(1)
