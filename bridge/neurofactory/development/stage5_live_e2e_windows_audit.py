"""Read-only Windows audit of two real Qwen-approved sources and GitHub journal.

Never publishes, writes, sends ChatGPT messages or calls any paid AI service.
"""
import base64
import hashlib
import json
import os
import pathlib
import sys
import urllib.request

import stage5_live_pair_lab as lab

REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-stage5-live-e2e-20261013"
PREFIX="bridge/neurofactory/development/"
JOURNAL=PREFIX+"stage5-live-e2e-journal.json"
BASE="https://api.github.com/repos/"+REPO+"/"

def api(path):
    headers={"Accept":"application/vnd.github+json",
             "User-Agent":"NeurofactoryStage5WindowsReadOnly"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"]="Bearer "+os.environ["GITHUB_TOKEN"]
    request=urllib.request.Request(BASE+path,headers=headers,method="GET")
    with urllib.request.urlopen(request,timeout=35) as answer:
        return json.load(answer)

def content(path,ref=BRANCH):
    if not path.startswith(PREFIX):raise ValueError("Foreign source path")
    obj=api("contents/"+path+"?ref="+ref)
    if obj.get("path")!=path:raise ValueError("Repository contents path changed")
    return base64.b64decode(obj["content"].replace("\n",""))

def audit():
    journal_bytes=content(JOURNAL)
    state=json.loads(journal_bytes)
    if (state.get("schema")!=1 or state.get("scope")!="neurofactory_only"
        or state.get("branch")!=BRANCH
        or state.get("chat_delivery")!="paused_by_user"):
        raise ValueError("Wrong scope or ChatGPT sender unpaused")
    records=state.get("tasks",{})
    if set(records)!={x[0] for x in lab.JOBS}:
        raise ValueError("Journal missing or duplicated a task")
    commits=[]
    checks=0
    for task_id,filename,function,_ in lab.JOBS:
        row=records[task_id]
        if row.get("state")!="verified_done" or not row.get("commit_sha"):
            raise ValueError("Unfinished live task")
        source_path=PREFIX+filename
        evidence_path=PREFIX+"stage5-e2e-evidence/"+task_id+".json"
        source=content(source_path)
        proof=content(evidence_path)
        record=json.loads(proof)
        validated=lab.check_source(source.decode("utf-8"),function)
        checks+=validated["behavior_cases"]
        if (row.get("target")!=source_path or
            row["source_sha256"]!=validated["source_sha256"] or
            record.get("source_sha256")!=validated["source_sha256"] or
            record.get("task_id")!=task_id or
            record.get("writer")!="qwen2.5-coder:7b" or
            record.get("reviewer")!="qwen3:4b" or
            record.get("independent_verdict",{}).get("verdict")!="REVIEW_OK" or
            record["independent_verdict"].get("source_sha256")!=validated["source_sha256"]):
            raise ValueError("Agent review does not match verified exact source")
        history=api("commits?sha="+BRANCH+"&path="+source_path+"&per_page=5")
        if len(history)!=1 or history[0]["sha"]!=row["commit_sha"]:
            raise ValueError("Missing or duplicated GitHub source publication")
        changed=api("commits/"+row["commit_sha"])
        if {file["filename"] for file in changed.get("files",[])}!={source_path,evidence_path}:
            raise ValueError("Publication changed unauthorized files")
        commits.append(row["commit_sha"])
    if len(set(commits))!=len(lab.JOBS):
        raise ValueError("Tasks did not produce independent commits")
    summary={"result":"verified","two_real_model_tasks":len(lab.JOBS),
       "deterministic_checks":checks,
       "state_sha256":hashlib.sha256(journal_bytes).hexdigest(),
       "first_commit":commits[0],"second_commit":commits[1],
       "chat_delivery_paused":True,"no_duplicate_publication":True}
    print("NF5_REAL_TWO_AGENT_WINDOWS_AUDIT "+json.dumps(summary,sort_keys=True),flush=True)
    return summary

if __name__=="__main__":
    audit()
