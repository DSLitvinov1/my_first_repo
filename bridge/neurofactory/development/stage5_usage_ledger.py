"""Append-only audited Neurofactory Actions usage, not an invoice.

Only verified run IDs and observed wall time; monetary charges require billing evidence.
The caller is responsible for persisting the returned ledger in the approved repo.
"""
import copy
import datetime as dt
import urllib.request
import json

ALLOWED_REPOS={"DSLitvinov1/my_first_repo","DSLitvinov1/lesson3.1"}

class UsageError(ValueError):
    pass

def verified_run(repo,run_id,fetch=None):
    if repo not in ALLOWED_REPOS or type(run_id) is not int or run_id<1000000:
        raise UsageError("Forbidden project or run")
    def official():
        url="https://api.github.com/repos/"+repo+"/actions/runs/"+str(run_id)
        request=urllib.request.Request(url,headers={
            "User-Agent":"NeurofactoryStage5ReadOnlyUsage",
            "Accept":"application/vnd.github+json"})
        with urllib.request.urlopen(request,timeout=25) as resp:return json.load(resp)
    data=official() if fetch is None else fetch(repo,run_id)
    if (data.get("id")!=run_id or data.get("status")!="completed"
        or data.get("conclusion") not in {"success","failure","cancelled","timed_out"}):
        raise UsageError("Run not independently completed")
    try:
        started=dt.datetime.fromisoformat(data["run_started_at"].replace("Z","+00:00"))
        finished=dt.datetime.fromisoformat(data["updated_at"].replace("Z","+00:00"))
        delta=int((finished-started).total_seconds())
    except (KeyError,ValueError,TypeError) as err:
        raise UsageError("Invalid measured usage timestamps") from err
    if not 0<=delta<=86400:raise UsageError("Unsafe or reversed duration")
    return {"run_id":run_id,"repo":repo,"conclusion":data["conclusion"],
            "elapsed_wall_seconds":delta,"kind":"verified_actions_run",
            "platform":"unverified_runner_type"}

def append_checked(ledger,entry):
    if not isinstance(ledger,dict) or ledger.get("schema")!=1 or ledger.get("project")!="НЕЙРОЗАВОД":
        raise UsageError("Untrusted cost ledger")
    existing=ledger.get("runs")
    if not isinstance(existing,list) or not isinstance(entry,dict):
        raise UsageError("Unsupported usage")
    if (entry.get("repo") not in ALLOWED_REPOS or
            entry.get("kind")!="verified_actions_run" or
            type(entry.get("run_id")) is not int or entry["run_id"] < 1000000 or
            type(entry.get("elapsed_wall_seconds")) is not int or
            not 0 <= entry["elapsed_wall_seconds"] <= 86400 or
            entry.get("conclusion") not in ("success","failure","cancelled","timed_out")):
        raise UsageError("Unverified run evidence")
    for historic in existing:
        if (not isinstance(historic,dict) or
                type(historic.get("run_id")) is not int or
                type(historic.get("elapsed_wall_seconds")) is not int or
                historic["elapsed_wall_seconds"] < 0):
            raise UsageError("Corrupt prior resource evidence")
    billing=ledger.get("monetary_charges")
    if not isinstance(billing,dict) or billing.get("verified_amount") is not None:
        raise UsageError("Billing must remain independently unverified")
    for item in existing:
        if item.get("run_id")==entry.get("run_id"):
            if all(item.get(k)==entry.get(k) for k in ("repo","conclusion","elapsed_wall_seconds")):
                return copy.deepcopy(ledger),False
            raise UsageError("A historical run cannot be overwritten")
    changed=copy.deepcopy(ledger)
    changed["runs"].append(copy.deepcopy(entry))
    if len({item["run_id"] for item in changed["runs"]})!=len(changed["runs"]):
        raise UsageError("Duplicate run identity")
    changed["observed_total_elapsed_wall_seconds"]=sum(
        item["elapsed_wall_seconds"] for item in changed["runs"])
    changed["observed_total_elapsed_wall_minutes"]=round(
        changed["observed_total_elapsed_wall_seconds"]/60,2)
    changed["unique_run_ids_verified"]=True
    return changed,True
