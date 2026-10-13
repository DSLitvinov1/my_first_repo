"""GitHub CAS journal for the approved Neurofactory development queue.

Only a trusted coordinator with GITHUB_TOKEN may write this fixed file. Independent
AI workers get no token. A failed checkpoint write stops work before external effects.
"""
import base64
import hashlib
import json
import os
import urllib.error
import urllib.request

from stage5_development_queue import REPO, BRANCH, DevelopmentQueueError, _canonical

FILE = "bridge/neurofactory/development/stage5-active-queue-state.json"
BASE = "https://api.github.com/repos/" + REPO + "/contents/" + FILE

class RemoteJournalError(ValueError):
    pass


def _request(method, data=None):
    headers = {"Accept":"application/vnd.github+json",
               "Content-Type":"application/json",
               "User-Agent":"NeurofactoryStage5TrustedQueue"}
    if method != "GET":
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise RemoteJournalError("Only trusted publisher may persist remote state")
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + ("?ref=" + BRANCH if method=="GET" else ""),
        data=json.dumps(data).encode("utf-8") if data is not None else None,
        method=method, headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=30) as stream:
            return json.load(stream)
    except urllib.error.HTTPError as exc:
        if method=="GET" and exc.code==404:
            return None
        raise


def read():
    response = _request("GET")
    if response is None:
        return None, None
    if response.get("path") != FILE or not isinstance(response.get("sha"),str):
        raise RemoteJournalError("Untrusted journal path")
    try:
        payload=base64.b64decode(response["content"].replace("\n",""))
        entry=json.loads(payload)
    except (KeyError,ValueError,TypeError) as error:
        raise RemoteJournalError("Invalid remote journal") from error
    _validate(entry)
    return entry,response["sha"]


def _validate(entry):
    if not isinstance(entry,dict) or set(entry)!={"body","sha256"}:
        raise RemoteJournalError("Unexpected snapshot envelope")
    body=entry["body"]
    if (not isinstance(body,dict) or
            body.get("scope")!="neurofactory_only" or
            body.get("chat_delivery")!="paused_by_user" or
            body.get("schema")!=1 or
            not isinstance(body.get("files"),dict) or
            hashlib.sha256(_canonical(body)).hexdigest()!=entry["sha256"]):
        raise RemoteJournalError("Unsigned, altered, or wrong-project queue state")
    return entry


def _no_rewind(old, fresh):
    """A restarted older worker must never overwrite a newer confirmed checkpoint."""
    previous=old["body"]["files"]
    current=fresh["body"]["files"]
    if set(previous)!=set(current):
        raise RemoteJournalError("Checkpoint inventory changed")
    moves={
        "queued":{"queued","running"},
        "running":{"running","queued","publishing","retry_exhausted","needs_manual_review"},
        "publishing":{"publishing","needs_receipt_check","verified_done"},
        "needs_receipt_check":{"needs_receipt_check","verified_done"},
        "verified_done":{"verified_done"},
        "retry_exhausted":{"retry_exhausted"},
        "needs_manual_review":{"needs_manual_review"},
        "failed":{"failed"}
    }
    for filename in previous:
        former=json.loads(previous[filename])["data"]
        latest=json.loads(current[filename])["data"]
        if former["id"]!=latest["id"] or former.get("identity_sha256")!=latest.get("identity_sha256"):
            raise RemoteJournalError("Checkpoint identity regressed")
        if latest.get("attempts",0)<former.get("attempts",0):
            raise RemoteJournalError("Attempt count rewind denied")
        if latest.get("state") not in moves.get(former.get("state"),set()):
            raise RemoteJournalError("Already-verified or unresolved task rewind denied")
        for field in ("publication_sha",):
            if field in former and former[field]!=latest.get(field):
                raise RemoteJournalError("Persisted GitHub receipt cannot be replaced")
        for field in ("proof",):
            if field in former and former[field]!=latest.get(field):
                raise RemoteJournalError("Author or reviewer proof cannot be rewritten")
    return True


def checkpoint_to_github(queue):
    """Persist before each writer/reviewer/publisher external effect; reread receipt."""
    fresh=_validate(queue.sealed_snapshot())
    old,blob_sha=read()
    if old is not None:
        if old["body"]["identity_sha256"]!=fresh["body"]["identity_sha256"]:
            raise RemoteJournalError("Another approved queue owns this journal")
        if old==fresh:
            return {"changed":False,"verified":True}
        _no_rewind(old,fresh)
    payload={
        "branch":BRANCH,
        "message":"neurofactory-state: durable stage5 per-task agent checkpoints",
        "content":base64.b64encode((_canonical(fresh)+b"\n")).decode("ascii"),
    }
    if blob_sha:
        payload["sha"]=blob_sha
    response=_request("PUT",payload)
    recorded= response.get("content",{}).get("sha","")
    if not recorded:
        raise RemoteJournalError("GitHub did not return checkpoint receipt")
    actual,_=read()
    if actual!=fresh:
        raise RemoteJournalError("Checkpoint changed or was lost after commit; stop before model call")
    return {"changed":True,"verified":True,"commit":response.get("commit",{}).get("sha")}


class DurableCoordinator:
    def __init__(self,queue):
        self.queue=queue

    def restore_if_exists(self):
        remote,_=read()
        if remote is None:
            self.queue.prepare()
            return checkpoint_to_github(self.queue)
        self.queue.restore_snapshot(remote)
        return {"changed":False,"restored":True}

    def recover(self, now):
        """Reconcile the exact GitHub checkpoint before local recovery, then persist it.

        Recovery from a stale runner is rejected instead of overwriting a newer
        writer/reviewer/publisher receipt. No agent runs if the CAS save fails.
        """
        previous,_=read()
        if previous is None or previous!=self.queue.sealed_snapshot():
            raise RemoteJournalError("Cannot recover stale or unpersisted task state")
        result=self.queue.recover(now)
        checkpoint_to_github(self.queue)
        return result

    def claim(self, job_id, role, now, lease_seconds=120):
        result=self.queue.claim(job_id,role,now,lease_seconds)
        checkpoint_to_github(self.queue)
        return result

    def before_effect(self,job_id,role,**proof):
        result=self.queue.before_effect(job_id,role,**proof)
        checkpoint_to_github(self.queue)
        return result

    def acknowledge(self,job_id,role,sha,*,verify_remote):
        result=self.queue.acknowledge(job_id,role,sha,verify_remote=verify_remote)
        checkpoint_to_github(self.queue)
        return result
