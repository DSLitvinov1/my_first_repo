"""Trusted one-time isolated GitHub publisher and reconciliation journal.

Only dedicated branch, two pre-approved paths, no other repositories.
Writer/reviewer run without credentials in a separate job. Publication occurs
only after exact tests, two model proofs and a durable prepublication checkpoint.
"""
import base64
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-stage5-live-e2e-20261013"
PREFIX="bridge/neurofactory/development/"
JOURNAL=PREFIX+"stage5-live-e2e-journal.json"
JOBS=[
 ("NF-DEV-05-Q001","stage5_task_registry.py","valid_task_ids"),
 ("NF-DEV-05-Q002","stage5_receipt_reconciliation.py","reconcile_receipt"),
]
BASE="https://api.github.com/repos/"+REPO+"/"
SHA40=re.compile(r"[a-f0-9]{40}\Z")
SHA64=re.compile(r"[a-f0-9]{64}\Z")

def guard():
    if (os.getenv("GITHUB_REPOSITORY")!=REPO
        or os.getenv("GITHUB_REF_NAME")!=BRANCH):
        raise ValueError("Unauthorized repository or branch")
    if not os.getenv("GITHUB_TOKEN"):
        raise ValueError("Only a trusted publisher with scoped token may write")

def api(method,resource,body=None):
    if resource.startswith("/") or ".." in resource or "://" in resource:
        raise ValueError("Invalid API endpoint")
    headers={"Accept":"application/vnd.github+json","User-Agent":"NF5IsolatedTrustedPublisher",
        "Content-Type":"application/json","Authorization":"Bearer "+os.environ["GITHUB_TOKEN"]}
    request=urllib.request.Request(BASE+resource,method=method,
        headers=headers,data=None if body is None else json.dumps(body).encode("utf-8"))
    try:
        with urllib.request.urlopen(request,timeout=30) as response:
            raw=response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as err:
        if method=="GET" and err.code==404:return None
        raise

def content(path,reference=BRANCH):
    if not path.startswith(PREFIX) or ".." in path.split("/"):
        raise ValueError("Other project access denied")
    entry=api("GET","contents/"+path+"?ref="+reference)
    if entry is None:return None,None
    if entry.get("path")!=path:raise ValueError("GitHub path mismatch")
    return base64.b64decode(entry["content"].replace("\n","")),entry["sha"]

def expected_journal():
    return {"schema":1,"scope":"neurofactory_only","chat_delivery":"paused_by_user",
      "branch":BRANCH,"tasks":{id:{"target":PREFIX+filename,
          "state":"queued","source_sha256":None,"commit_sha":None}
          for id,filename,_ in JOBS}}

def verified_journal():
    raw,sha=content(JOURNAL)
    if raw is None:return None,None
    entry=json.loads(raw)
    original=expected_journal()
    if (entry.get("schema")!=1 or entry.get("scope")!=original["scope"]
        or entry.get("chat_delivery")!="paused_by_user"
        or entry.get("branch")!=BRANCH
        or set(entry.get("tasks",{}))!=set(original["tasks"])):
        raise ValueError("Journal has unsafe identity")
    for task_id,row in entry["tasks"].items():
        if row.get("target")!=original["tasks"][task_id]["target"]:
            raise ValueError("Task destination changed")
        if row.get("state") not in ("queued","publishing","verified_done"):
            raise ValueError("Task phase unsupported")
        if row.get("source_sha256") is not None and not SHA64.fullmatch(str(row["source_sha256"])):
            raise ValueError("Source digest corrupted")
        if row.get("commit_sha") is not None and not SHA40.fullmatch(str(row["commit_sha"])):
            raise ValueError("Commit digest corrupted")
    return entry,sha

def save(doc,sha):
    encoded=(json.dumps(doc,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
    post={"branch":BRANCH,"message":"neurofactory isolated stage5: durable publication checkpoint",
          "content":base64.b64encode(encoded).decode()}
    if sha is not None:post["sha"]=sha
    result=api("PUT","contents/"+JOURNAL,post)
    reread,new_sha=content(JOURNAL)
    if reread!=encoded or new_sha!=result.get("content",{}).get("sha"):
        raise ValueError("Remote checkpoint not confirmed; stop before effects")
    return new_sha

def initialize():
    guard()
    item,sha=verified_journal()
    if item is None:
        doc=expected_journal()
        save(doc,None)
        print("NF5_ACTUAL_GITHUB_JOURNAL_INITIALIZED",flush=True)
    else:
        print("NF5_EXISTING_REMOTE_JOURNAL_REUSED",flush=True)

def files_for(task_id,filename,scratch):
    code=(scratch/filename).read_bytes()
    proof=(scratch/(filename+".proof.json")).read_bytes()
    checked=json.loads(proof)
    expected_path=PREFIX+filename
    if (checked.get("task_id")!=task_id or checked.get("target")!=expected_path
        or checked.get("writer")!="qwen2.5-coder:7b"
        or checked.get("reviewer")!="qwen3:4b"
        or checked.get("independent_verdict",{}).get("verdict")!="REVIEW_OK"
        or checked.get("independent_verdict",{}).get("source_sha256")!=checked.get("source_sha256")
        or checked.get("chat_delivery")!="paused_by_user"
        or checked.get("scope")!="neurofactory_only"
        or hashlib.sha256(code).hexdigest()!=checked.get("source_sha256")
        or checked.get("tests",0)<10):
        raise ValueError("No matching two-agent tested source approval")
    return code,proof,checked["source_sha256"]

def verify_stored(task_id,filename,code,proof):
    target=PREFIX+filename
    proof_target=PREFIX+"stage5-e2e-evidence/"+task_id+".json"
    actual_code,_=content(target)
    actual_proof,_=content(proof_target)
    if actual_code!=code or actual_proof!=proof:
        raise ValueError("GitHub publication missing/mismatched: no retransmission allowed")
    history=api("GET","commits?sha="+BRANCH+"&path="+target+"&per_page=5")
    if len(history)!=1:
        raise ValueError("Duplicate or missing source commits")
    commit=history[0]["sha"]
    changed=api("GET","commits/"+commit)
    change_paths={entry["filename"] for entry in changed.get("files",[])}
    if change_paths!={target,proof_target}:
        raise ValueError("Source publication modified unauthorized files")
    return commit

def commit_once(task_id,filename,code,proof):
    target=PREFIX+filename
    proof_target=PREFIX+"stage5-e2e-evidence/"+task_id+".json"
    if content(target)[0] is not None or content(proof_target)[0] is not None:
        raise ValueError("Uncertain prior publication; do not repeat")
    old=api("GET","git/ref/heads/"+BRANCH)["object"]["sha"]
    old_commit=api("GET","git/commits/"+old)
    tree=api("POST","git/trees",{"base_tree":old_commit["tree"]["sha"],
      "tree":[{"path":target,"mode":"100644","type":"blob","content":code.decode("utf-8")},
              {"path":proof_target,"mode":"100644","type":"blob","content":proof.decode("utf-8")}]})
    commit=api("POST","git/commits",{"parents":[old],"tree":tree["sha"],
        "message":"neurofactory Stage5 independently verified "+task_id})
    api("PATCH","git/refs/heads/"+BRANCH,{"sha":commit["sha"],"force":False})
    return verify_stored(task_id,filename,code,proof)

def publish(scratch,selected_id):
    if selected_id not in {x[0] for x in JOBS}:
        raise ValueError("Single approved task required for publication")
    guard()
    scratch=pathlib.Path(scratch)
    if not scratch.is_dir():raise ValueError("Missing model artifacts")
    for index,(task_id,filename,function) in enumerate(JOBS):
        if task_id!=selected_id:continue
        doc,sha=verified_journal()
        if doc is None:raise ValueError("Must initialize remote journal first")
        previous=JOBS[:index]
        if any(doc["tasks"][t[0]]["state"]!="verified_done" for t in previous):
            raise ValueError("Cannot skip earlier task")
        code,proof,hash_value=files_for(task_id,filename,scratch)
        row=doc["tasks"][task_id]
        if row["state"]=="verified_done":
            if row["source_sha256"]!=hash_value:
                raise ValueError("Already finished different source; no replay")
            actual=verify_stored(task_id,filename,code,proof)
            if actual!=row["commit_sha"]:
                raise ValueError("Previously confirmed result changed")
            print("NF5_ALREADY_VERIFIED_NO_NEW_COMMIT",task_id,actual,flush=True)
            continue
        if row["state"]=="publishing":
            # A previous crash after an intent may have left remote effects ambiguous:
            # never send the same publication again; reconcile only.
            published=verify_stored(task_id,filename,code,proof)
            if row["source_sha256"]!=hash_value:
                raise ValueError("Recovered intent has different source")
            row["state"]="verified_done"
            row["commit_sha"]=published
            save(doc,sha)
            print("NF5_RECOVERED_PRIOR_REMOTE_PUBLICATION",task_id,published,flush=True)
            continue
        row["source_sha256"]=hash_value
        row["state"]="publishing"
        sha=save(doc,sha)
        published=commit_once(task_id,filename,code,proof)
        row["state"]="verified_done"
        row["commit_sha"]=published
        save(doc,sha)
        print("NF5_ONE_REAL_APPROVED_PUBLICATION",task_id,published,flush=True)
    doc,_=verified_journal()
    if doc["tasks"][selected_id]["state"]!="verified_done":
        raise ValueError("Selected task not acknowledged")
    print("NF5_ONE_APPROVED_TASK_DURABLY_PUBLISHED",selected_id,flush=True)

def audit(scratch):
    guard()
    doc,_=verified_journal()
    if doc is None:raise ValueError("Remote durable state missing")
    if any(t["state"]!="verified_done" for t in doc["tasks"].values()):
        raise ValueError("Not all tasks finished")
    for task_id,filename,function in JOBS:
        code,proof,hash_value=files_for(task_id,filename,pathlib.Path(scratch))
        row=doc["tasks"][task_id]
        if row["source_sha256"]!=hash_value or row["commit_sha"]!=verify_stored(task_id,filename,code,proof):
            raise ValueError("Verified source/receipt changed")
    print("NF5_CROSS_PROCESS_REMOTE_JOURNAL_AND_NO_DUPLICATES_VERIFIED",flush=True)

if __name__=="__main__":
    try:
        if len(sys.argv)<2:raise ValueError("Missing command")
        if sys.argv[1]=="init":initialize()
        elif sys.argv[1]=="publish":publish(sys.argv[2],sys.argv[3])
        elif sys.argv[1]=="audit":audit(sys.argv[2])
        else:raise ValueError("Unknown trusted publishing action")
    except Exception as error:
        print("NF5_FAIL_CLOSED",type(error).__name__,str(error)[:500],flush=True)
        sys.exit(1)
