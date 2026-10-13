"""Atomic publication of a truly new, independently verified Neurofactory crash recovery module."""
import hashlib
import json
import os
import pathlib
import sys
import urllib.error

import publish_real_improvement as pub
import real_self_improve as safety
import recovery_proposal as model
from stage3_guard import read

TARGET="bridge/neurofactory/development/recovery_decision.py"
RECEIPT="bridge/neurofactory/development/recovery-verification.json"
SAFE_POLICY=pathlib.Path(__file__).resolve().parent/"path_policy.py"

def remote_bytes(path):
    if path not in (TARGET, RECEIPT):
        raise ValueError("Cross-component publication denied")
    import base64
    try:
        obj=pub.api("GET",pub.BASE+"contents/"+path+"?ref="+pub.BRANCH)
        return base64.b64decode(obj["content"].replace("\n",""))
    except urllib.error.HTTPError as exc:
        if exc.code==404:
            return None
        raise

def verify():
    plan=read()
    if next(x for x in plan["milestones"] if x["id"]=="NF-DEV-04")["state"]!="active":
        raise ValueError("Crash recovery not active in user-approved roadmap")
    data=(model.OUT/model.FILENAME).read_bytes()
    proof=json.loads((model.OUT/model.REVIEW_FILE).read_text("utf-8"))
    if any([proof.get("stage")!="NF-DEV-04",
            proof.get("writer")!=model.WRITER,
            proof.get("reviewer")!=model.REVIEWER,
            proof.get("review_verdict")!="REVIEW_OK",
            proof.get("scope")!="neurofactory_only",
            proof.get("sha256")!=hashlib.sha256(data).hexdigest()]):
        raise ValueError("No independent AI acceptance for exact code")
    tested=model.acceptance(data.decode("utf-8"))
    if proof.get("tests_passed")!=tested:
        raise ValueError("Real recovery behavior checks do not match evidence")
    if not SAFE_POLICY.is_file():
        raise ValueError("Previously verified Neurofactory security gate missing")
    tree=safety.validate_source(SAFE_POLICY.read_text("utf-8"))
    isolated={"__builtins__":{"isinstance":isinstance,"len":len,"all":all,"any":any,"str":str}}
    exec(compile(tree,"<reviewed-repository-path-gate>","exec"),isolated)
    gate=isolated["approved_change_path"]
    if gate(TARGET) is not True or gate(RECEIPT) is not True:
        raise ValueError("First published two-agent policy rejects recovery files")
    return data,proof,tested

def publish():
    if (os.environ.get("GITHUB_REPOSITORY")!=pub.REPO or
        os.environ.get("GITHUB_REF_NAME")!=pub.BRANCH or
        os.environ.get("NF_FREE_PUBLIC_CONFIRMED")!="yes" or
        not os.environ.get("GITHUB_TOKEN")):
        raise ValueError("Publisher not running in authorized free Neurofactory branch")
    data,proof,tested=verify()
    if remote_bytes(TARGET) is not None or remote_bytes(RECEIPT) is not None:
        raise ValueError("Previously published recovery module cannot be repeated")
    proof["publication_status"]="verified_candidate"
    proof["github_branch"]=pub.BRANCH
    proof["file"]=TARGET
    receipt=(json.dumps(proof,ensure_ascii=False,indent=2)+"\n").encode("utf-8")
    head=pub.api("GET",pub.BASE+"git/ref/heads/"+pub.BRANCH)
    previous=head["object"]["sha"]
    commit=pub.api("GET",pub.BASE+"git/commits/"+previous)
    entries=[
        {"path":TARGET,"mode":"100644","type":"blob","content":data.decode("utf-8")},
        {"path":RECEIPT,"mode":"100644","type":"blob","content":receipt.decode("utf-8")}
    ]
    generated=pub.api("POST",pub.BASE+"git/trees",{"base_tree":commit["tree"]["sha"],"tree":entries})
    new=pub.api("POST",pub.BASE+"git/commits",{
        "message":"neurofactory: independently reviewed production crash recovery decision",
        "parents":[previous],"tree":generated["sha"]})
    pub.api("PATCH",pub.BASE+"git/refs/heads/"+pub.BRANCH,
            {"sha":new["sha"],"force":False})
    if remote_bytes(TARGET)!=data or remote_bytes(RECEIPT)!=receipt:
        raise ValueError("Newly committed recovery code or review receipt differs")
    print("NEUROFACTORY_RECOVERY_CORE_PUBLISHED",new["sha"],tested,flush=True)

if __name__=="__main__":
    try:
        publish()
    except Exception as exc:
        print("NEUROFACTORY_RECOVERY_SAFE_STOP",type(exc).__name__,str(exc)[:230],flush=True)
        sys.exit(1)
