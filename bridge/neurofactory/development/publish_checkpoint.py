"""Only after independent Qwen3 approval, atomically publish real checkpoint source and proof."""
import hashlib
import json
import os
import pathlib
import urllib.error
import base64

import publish_real_improvement as api_support
from stage3_guard import read
from real_self_improve import validate_source

HERE=pathlib.Path(__file__).resolve().parent
SOURCE=HERE/"durable_checkpoint.py"
REVIEW=pathlib.Path(os.environ.get("RUNNER_TEMP","/tmp"))/"neurofactory-checkpoint-review.json"
TARGET="bridge/neurofactory/development/durable_checkpoint.py"
PROOF="bridge/neurofactory/development/durable-checkpoint-verification.json"
BRANCH="neurofactory-public-lab-20261012"

def remote(path):
    if path not in (TARGET,PROOF):
        raise ValueError("Refuse other remote files")
    try:
        result=api_support.api("GET",api_support.BASE+"contents/"+path+"?ref="+BRANCH)
        return base64.b64decode(result["content"].replace("\n",""))
    except urllib.error.HTTPError as exc:
        if exc.code==404:
            return None
        raise

def publish():
    if os.environ.get("GITHUB_REPOSITORY")!="DSLitvinov1/my_first_repo":
        raise ValueError("Wrong repository")
    if os.environ.get("NF_FREE_PUBLIC_CONFIRMED")!="yes" or not os.environ.get("GITHUB_TOKEN"):
        raise ValueError("Trusted free publisher identity missing")
    p=read()
    states={x["id"]:x["state"] for x in p["milestones"]}
    if states["NF-DEV-01"]!="verified" or states["NF-DEV-02"]!="deferred" or states["NF-DEV-03"]!="verified" or states["NF-DEV-04"]!="active":
        raise ValueError("Roadmap does not approve checkpoint publication")
    if p.get("chat_delivery_paused") is not True or p.get("free_only") is not True:
        raise ValueError("Unsafe runtime or resumed browser delivery")
    data=SOURCE.read_bytes().replace(b"\r\n",b"\n")
    report=json.loads(REVIEW.read_text("utf-8"))
    if any((
        report.get("review_verdict")!="REVIEW_OK",
        report.get("reviewer")!="qwen3:4b",
        report.get("scope")!="neurofactory_only",
        report.get("component")!="durable_checkpoint",
        report.get("actual_interruption_checked") is not True,
        report.get("checks_passed")!=6,
        report.get("source_sha256")!=hashlib.sha256(data).hexdigest()
    )):
        raise ValueError("Missing independent approval of exact source bytes")
    audited=(HERE/"path_policy.py").read_text("utf-8")
    tree=validate_source(audited)
    allowed={"__builtins__":{"isinstance":isinstance,"len":len,"all":all,"any":any,"str":str}}
    exec(compile(tree,"<verified-path-allowlist>","exec"),allowed)
    for path in (TARGET,PROOF):
        if allowed["approved_change_path"](path) is not True:
            raise ValueError("Previously reviewed path gate refuses file")
        if remote(path) is not None:
            raise ValueError("Already published: never replay checkpoint source")
    report["publication_status"]="approved_production"
    report["source_path"]=TARGET
    report["destination_branch"]=BRANCH
    proof=(json.dumps(report,ensure_ascii=False,indent=2)+"\n").encode("utf-8")
    current=api_support.api("GET",api_support.BASE+"git/ref/heads/"+BRANCH)["object"]["sha"]
    original=api_support.api("GET",api_support.BASE+"git/commits/"+current)
    tree=api_support.api("POST",api_support.BASE+"git/trees",{"base_tree":original["tree"]["sha"],"tree":[
        {"path":TARGET,"mode":"100644","type":"blob","content":data.decode("utf-8")},
        {"path":PROOF,"mode":"100644","type":"blob","content":proof.decode("utf-8")}
    ]})
    commit=api_support.api("POST",api_support.BASE+"git/commits",{
        "message":"neurofactory: Qwen3-reviewed durable atomic production checkpoints and real crash-restart proof",
        "parents":[current],"tree":tree["sha"]})
    api_support.api("PATCH",api_support.BASE+"git/refs/heads/"+BRANCH,{"sha":commit["sha"],"force":False})
    if remote(TARGET)!=data or remote(PROOF)!=proof:
        raise ValueError("Published checkpoint content or evidence changed after review")
    print("NEUROFACTORY_DURABLE_CHECKPOINT_PUBLISHED",commit["sha"],hashlib.sha256(data).hexdigest(),flush=True)

if __name__=="__main__":
    publish()
