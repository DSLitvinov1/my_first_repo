"""Read-only cross-run reconstruction of already Qwen-reviewed Stage5 task outputs.

Never regenerate or republish a finished task. No token and no GitHub writes.
"""
import base64
import hashlib
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

from stage5_live_pair_lab import JOBS,check_source

REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-stage5-live-e2e-20261013"
PREFIX="bridge/neurofactory/development/"
STATE=PREFIX+"stage5-live-e2e-journal.json"

def fetch(path):
    if not path.startswith(PREFIX) or ".." in path.split("/"):
        raise ValueError("Foreign source path denied")
    req=urllib.request.Request(
        "https://api.github.com/repos/"+REPO+"/contents/"+path+"?ref="+BRANCH,
        headers={"User-Agent":"NeurofactoryIsolatedStage5Restore",
                 "Accept":"application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req,timeout=25) as response:
            doc=json.load(response)
    except urllib.error.HTTPError as err:
        if err.code==404:return None
        raise
    if doc.get("path")!=path:
        raise ValueError("Remote path differs from verified scope")
    return base64.b64decode(doc["content"].replace("\n",""))

def restore(job_id,directory):
    candidates=[item for item in JOBS if item[0]==job_id]
    if len(candidates)!=1:raise ValueError("Unknown approved task")
    _,filename,function,_=candidates[0]
    out=pathlib.Path(directory)
    if not out.is_dir() or out.is_symlink():raise ValueError("Unsafe output directory")
    data=fetch(STATE)
    if data is None:raise ValueError("Durable state must exist before any AI call")
    state=json.loads(data)
    if (state.get("scope")!="neurofactory_only" or
        state.get("chat_delivery")!="paused_by_user" or
        state.get("branch")!=BRANCH):
        raise ValueError("Foreign or unpaused state rejected")
    tasks=state.get("tasks",{})
    if set(tasks)!={item[0] for item in JOBS}:
        raise ValueError("Incomplete task identity")
    row=tasks[job_id]
    if row.get("target")!=PREFIX+filename:
        raise ValueError("Task target modified after approval")
    status=row.get("state")
    if status=="queued":
        if fetch(PREFIX+filename) is not None:
            raise ValueError("Unacknowledged prior publication found; do not regenerate")
        print("NF5_NEW_APPROVED_TASK_NOT_YET_PUBLISHED",job_id,flush=True)
        return False
    if status not in ("verified_done","publishing"):
        raise ValueError("Unsafe unresolved task status")
    source=fetch(PREFIX+filename)
    proof_data=fetch(PREFIX+"stage5-e2e-evidence/"+job_id+".json")
    if source is None or proof_data is None:
        raise ValueError("Remote publication uncertain: halt instead of new model output")
    proof=json.loads(proof_data)
    outcome=check_source(source.decode("utf-8"),function)
    if (row.get("source_sha256")!=outcome["source_sha256"] or
        proof.get("source_sha256")!=outcome["source_sha256"] or
        proof.get("task_id")!=job_id or proof.get("target")!=PREFIX+filename or
        proof.get("writer")!="qwen2.5-coder:7b" or
        proof.get("reviewer")!="qwen3:4b" or
        proof.get("independent_verdict",{}).get("verdict")!="REVIEW_OK" or
        proof["independent_verdict"].get("source_sha256")!=outcome["source_sha256"]):
        raise ValueError("Source or independent review no longer matches checkpoint")
    if status=="verified_done" and not row.get("commit_sha"):
        raise ValueError("Completed task lacks exact GitHub commit receipt")
    (out/filename).write_bytes(source)
    (out/(filename+".proof.json")).write_bytes(proof_data)
    print("NF5_RESTORED_PREVIOUSLY_VERIFIED_MODEL_RESULT",job_id,
          outcome["source_sha256"],flush=True)
    return True

if __name__=="__main__":
    if len(sys.argv)!=3:raise ValueError("Provide safe task ID and scratch path")
    status=restore(sys.argv[1],sys.argv[2])
    output=os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output,"a",encoding="utf-8") as stream:
            stream.write("restored="+("true" if status else "false")+"\n")
