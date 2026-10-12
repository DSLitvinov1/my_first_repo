"""Publish a real AI-reviewed Neurofactory source improvement in a single atomic Git commit."""
import base64,hashlib,json,os,pathlib,sys,urllib.error,urllib.parse,urllib.request
import real_self_improve as model
from stage3_guard import approved_stage3,read
REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-public-lab-20261012"
BASE="https://api.github.com/repos/"+REPO+"/"
TARGET="bridge/neurofactory/development/path_policy.py"
RECEIPT="bridge/neurofactory/development/path-policy-verification.json"
def api(method,endpoint,payload=None):
    if not endpoint.startswith(BASE):
        raise ValueError("Cross-repository modification denied")
    headers={"Authorization":"Bearer "+os.environ["GITHUB_TOKEN"],
        "Accept":"application/vnd.github+json","Content-Type":"application/json",
        "User-Agent":"NeurofactoryVerifiedSelfImprovement"}
    data=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(endpoint,method=method,data=data,headers=headers)
    with urllib.request.urlopen(req,timeout=30) as response:return json.load(response)
def content(path):
    if path not in (TARGET,RECEIPT):
        raise ValueError("Modification outside approved Neurofactory scope")
    try:
        obj=api("GET",BASE+"contents/"+path+"?ref="+BRANCH)
    except urllib.error.HTTPError as e:
        if e.code==404:return None
        raise
    return base64.b64decode(obj["content"])
def enforce_generated_policy(source):
    # The independently reviewed AI function actually gates the real publication paths.
    tree=model.validate_source(source.decode("utf-8") if isinstance(source,bytes) else source)
    safe={"isinstance":isinstance,"len":len,"all":all,"any":any,"str":str}
    isolated={"__builtins__":safe}
    exec(compile(tree,"<verified-path-gate>","exec"),isolated)
    check=isolated["approved_change_path"]
    for path in (TARGET,RECEIPT):
        if check(path) is not True:
            raise ValueError("Independent AI path gate rejects real Neurofactory publication")
    return True
def verify_candidate():
    source=(model.OUT/"path_policy.py").read_bytes()
    proof=json.loads((model.OUT/"verification.json").read_text("utf-8"))
    if (proof.get("stage")!="NF-DEV-03" or proof.get("scope")!="neurofactory_only"
        or proof.get("writer")!=model.WRITER or proof.get("reviewer")!=model.REVIEWER
        or proof.get("review_verdict")!="REVIEW_OK"):
        raise ValueError("Missing two distinct agent approvals")
    if proof.get("sha256")!=hashlib.sha256(source).hexdigest():
        raise ValueError("Candidate changed since model review")
    n=model.acceptance(source.decode("utf-8"))
    enforce_generated_policy(source)
    if proof.get("tests_passed")!=n:
        raise ValueError("Independent test-count mismatch")
    return source,proof
def publish():
    if (os.environ.get("GITHUB_REPOSITORY")!=REPO
        or os.environ.get("GITHUB_REF_NAME")!=BRANCH
        or os.environ.get("NF_FREE_PUBLIC_CONFIRMED")!="yes"):
        raise ValueError("Not a permitted free public Neurofactory branch")
    if not os.environ.get("GITHUB_TOKEN"):
        raise ValueError("Publisher-only token absent")
    if not approved_stage3(read()):
        raise ValueError("Exact-chat delivery stage 02 not independently completed")
    source,proof=verify_candidate()
    if content(TARGET) is not None or content(RECEIPT) is not None:
        raise ValueError("Refuse to modify or replay existing approved policy files")
    proof["publication_status"]="verified_candidate"
    proof["github_branch"]=BRANCH
    proof["file"]=TARGET
    raw=(json.dumps(proof,ensure_ascii=False,indent=2)+"\n").encode("utf-8")
    head=api("GET",BASE+"git/ref/heads/"+BRANCH)
    old_sha=head["object"]["sha"]
    commit=api("GET",BASE+"git/commits/"+old_sha)
    objects=[
        {"path":TARGET,"mode":"100644","type":"blob","content":source.decode("utf-8")},
        {"path":RECEIPT,"mode":"100644","type":"blob","content":raw.decode("utf-8")}
    ]
    tree=api("POST",BASE+"git/trees",{"base_tree":commit["tree"]["sha"],"tree":objects})
    new=api("POST",BASE+"git/commits",{
        "message":"neurofactory: independently verified real self-improvement of repository path policy",
        "parents":[old_sha],"tree":tree["sha"]})
    api("PATCH",BASE+"git/refs/heads/"+BRANCH,{"sha":new["sha"],"force":False})
    if content(TARGET)!=source or content(RECEIPT)!=raw:
        raise ValueError("Committed source or audit receipt failed post-publication verification")
    print("REAL_NF_SELF_IMPROVEMENT_PUBLISHED",new["sha"],proof["tests_passed"],flush=True)
if __name__=="__main__":
    try:publish()
    except Exception as e:
        print("REAL_NF_PUBLICATION_DENIED",type(e).__name__,str(e)[:230],flush=True)
        sys.exit(1)
