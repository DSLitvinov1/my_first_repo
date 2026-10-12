"""Generic task intake, state machine and recovery for APPROVED synthetic tasks.
No model, OS shell or network actions are executed by this module.
"""
import datetime as dt,hashlib,json,pathlib,re
STAGES=("queued","planning","coding","testing","review","publishing","completed","failed","waiting_memory")
NEXT={"queued":"planning","planning":"coding","coding":"testing",
      "testing":"review","review":"publishing","publishing":"completed"}
SAFE_NAME=re.compile(r"^[a-z][a-z0-9_]{2,48}$")
MAX_RETRIES=2
MAX_TASKS=6
STALE_MINUTES=45
def validate_task(t):
    if not isinstance(t,dict):raise ValueError("Task data must be an object")
    if not SAFE_NAME.fullmatch(str(t.get("id",""))):raise ValueError("Unsafe task ID")
    if t.get("scope")!="public_synthetic_only":raise ValueError("Only public fabricated examples")
    if t.get("branch")!="neurofactory-crm-autonomous-20261012":raise ValueError("Wrong branch")
    brief=t.get("brief")
    if not isinstance(brief,str) or not 60<=len(brief)<=3500:raise ValueError("Invalid Russian brief")
    if t.get("stage") not in STAGES:raise ValueError("Invalid stage")
    if type(t.get("attempts")) is not int or not 0<=t["attempts"]<=MAX_RETRIES:raise ValueError("Attempt limit")
    if t.get("published") is True and t["stage"]!="completed":raise ValueError("Unverified publication")
    paths=t.get("files",[])
    if not isinstance(paths,list) or len(paths)<2 or len(paths)>8:raise ValueError("Unexpected file count")
    if len(set(paths))!=len(paths) or any(not re.fullmatch(r"[a-z][a-z0-9_]*\.py",p) for p in paths):
        raise ValueError("Unsafe output files")
    return True
def audit(t,event,now,detail=""):
    events=t.setdefault("audit",[])
    events.append({"time":now.isoformat(),"event":event,"stage":t["stage"],
                   "attempt":t["attempts"],"detail":detail[:130]})
    del events[:-80]
def transition(t,event,now=None,proof=None):
    validate_task(t)
    now=now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:raise ValueError("Timezone-aware clock mandatory")
    stage=t["stage"]
    if event=="begin":
        if stage!="queued":raise ValueError("Task not queued")
        t["attempts"]+=1
        if t["attempts"]>MAX_RETRIES:raise ValueError("Retry cap reached")
        t["stage"]="planning"
    elif event=="advance":
        if stage not in NEXT:raise ValueError("Cannot advance terminal or waiting stage")
        if stage in ("testing","review","publishing"):
            if not isinstance(proof,dict) or proof.get("ok") is not True:
                raise ValueError("Independent proof required")
        t["stage"]=NEXT[stage]
        if t["stage"]=="completed":
            t["published"]=True
            t["proof_digest"]=hashlib.sha256(json.dumps(proof,sort_keys=True).encode()).hexdigest()
    elif event=="memory_wait":
        if stage in ("completed","failed"):raise ValueError("Terminal task cannot wait")
        t["resume_stage"]=stage
        t["stage"]="waiting_memory"
    elif event=="resume":
        if stage!="waiting_memory":raise ValueError("Task was not waiting")
        t["stage"]=t.pop("resume_stage","queued")
    elif event=="fail":
        if stage in ("completed","failed"):raise ValueError("Terminal task cannot fail again")
        t["stage"]="failed" if t["attempts"]>=MAX_RETRIES else "queued"
    else:raise ValueError("Unknown transition")
    t["updated_at"]=now.isoformat()
    audit(t,event,now)
    return t
def restore_stale(queue,now=None):
    now=now or dt.datetime.now(dt.timezone.utc)
    count=0
    for t in queue.get("tasks",[]):
        validate_task(t)
        if t["stage"] in ("queued","completed","failed","waiting_memory"):continue
        try:updated=dt.datetime.fromisoformat(t["updated_at"].replace("Z","+00:00"))
        except (KeyError,TypeError,ValueError):updated=now-dt.timedelta(days=1)
        if updated.tzinfo is None:updated=updated.replace(tzinfo=dt.timezone.utc)
        if (now-updated).total_seconds()<STALE_MINUTES*60:continue
        if t["attempts"]>=MAX_RETRIES:t["stage"]="failed"
        else:t["stage"]="queued"
        t["updated_at"]=now.isoformat()
        audit(t,"stale_recovered",now)
        count+=1
    return count
def validate_queue(q):
    if not isinstance(q,dict) or q.get("paid_services") is not False or q.get("working_projects") is not False:
        raise ValueError("Unsafe factory policy")
    tasks=q.get("tasks")
    if not isinstance(tasks,list) or len(tasks)>MAX_TASKS:raise ValueError("Queue too large")
    for t in tasks:validate_task(t)
    if len({t["id"] for t in tasks})!=len(tasks):raise ValueError("Duplicate task IDs")
    return True
def next_task(q):
    validate_queue(q)
    if any(x["stage"] in ("planning","coding","testing","review","publishing") for x in q["tasks"]):
        return None
    return next((t for t in q["tasks"] if t["stage"]=="queued"),None)
