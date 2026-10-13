"""Read-only trusted GitHub receipts for queue completion; no worker credentials.

The candidate and independent reviewer use distinct receipt paths. Publisher checks
the actual approved production target and exact source digest. Never trust model text
or a Boolean from an AI as a remote publication receipt.
"""
import base64
import hashlib
import json
import re
import urllib.request

from stage5_development_queue import REPO,BRANCH,SAFE

HEX40=re.compile(r"[0-9a-f]{40}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
ROLE_PATH="bridge/neurofactory/development/stage5-job-evidence/"

class ReceiptError(ValueError):
    pass

def _get(relative):
    request=urllib.request.Request("https://api.github.com/repos/"+REPO+"/"+relative,
       headers={"Accept":"application/vnd.github+json",
                "User-Agent":"NeurofactoryStage5TrustedReadOnlyVerifier"})
    with urllib.request.urlopen(request,timeout=30) as response:return json.load(response)

def receipt_path(task_id,role,target):
    if not isinstance(task_id,str) or not re.fullmatch(r"NF-DEV-05-Q[0-9]{3}",task_id):
        raise ReceiptError("Unapproved task")
    if not isinstance(target,str) or not target.startswith(SAFE) or ".." in target.split("/"):
        raise ReceiptError("Foreign development path")
    if role=="writer":
        return ROLE_PATH+task_id+"-candidate.py"
    if role=="reviewer":
        return ROLE_PATH+task_id+"-review.json"
    if role=="publisher":
        return target
    raise ReceiptError("Unknown role")

def verify(repo,branch,target,sha,source_sha256,*,task_id,role):
    if (repo!=REPO or branch!=BRANCH or
        not isinstance(sha,str) or not HEX40.fullmatch(sha) or
        not isinstance(source_sha256,str) or not HEX64.fullmatch(source_sha256)):
        raise ReceiptError("Forbidden repository or receipt hash")
    path=receipt_path(task_id,role,target)
    commit=_get("commits/"+sha)
    changed={file["filename"] for file in commit.get("files",[])}
    if path not in changed or any(not x.startswith("bridge/neurofactory/") for x in changed):
        raise ReceiptError("Receipt never changed approved file or modified unrelated project")
    lineage=_get("compare/"+sha+"..."+BRANCH)
    if lineage.get("status") not in ("identical","ahead"):
        raise ReceiptError("Receipt is not reachable from approved production branch")
    record=_get("contents/"+path+"?ref="+sha)
    if record.get("path")!=path:
        raise ReceiptError("GitHub returned different receipt path")
    payload=base64.b64decode(record.get("content","").replace("\n",""))
    if role=="reviewer":
        try:proof=json.loads(payload)
        except ValueError as exc:raise ReceiptError("Reviewer receipt is not JSON") from exc
        if (proof.get("source_sha256")!=source_sha256
            or proof.get("verdict")!="REVIEW_OK"
            or proof.get("reviewer")!="qwen3:4b"
            or proof.get("task_id")!=task_id):
            raise ReceiptError("Independent reviewed source digest not confirmed")
    elif hashlib.sha256(payload).hexdigest()!=source_sha256:
        raise ReceiptError("Published source differs from writer fingerprint")
    return True
