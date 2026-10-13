"""Read-only Stage5 non-chat acceptance of REAL GitHub-backed Neurofactory history.

No models, shell commands, mutation, paid endpoints, ChatGPT delivery, or live task replay.
This audits immutable Stage4 writer/reviewer/publisher receipts over *separate* runs.
"""
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import urllib.request

REPO = "DSLitvinov1/my_first_repo"
BRANCH = "neurofactory-public-lab-20261012"
STAGING = "neurofactory-stage4-live-integration-20261013"
ROOT = pathlib.Path(__file__).resolve().parent
PREFIX = "bridge/neurofactory/development/"
STATE_PATH = PREFIX + "stage4-live-state.json"
WRITER_PATH = PREFIX + "stage4-live-candidate.py"
REVIEW_PATH = PREFIX + "stage4-live-reviewed.json"
SOURCE_PATH = PREFIX + "stage4_receipt_rules.py"
ORIGINAL_PROOF_PATH = PREFIX + "stage4-live-proof.json"
HARDEN_PROOF_PATH = PREFIX + "stage4-receipt-hardening-verification.json"
INITIAL_COMMIT = "4156913b3572bc17b7579ca4cbcc0059c53928cf"
CORRECTION_COMMIT = "b11b9fdba325976018b8a0547f53c8660a10726c"
KNOWN_WINDOWS_RUN = 38447399597
KNOWN_AGENT_RUN = 38444910309
KNOWN_HARDEN_RUN = 38446284364
AUTHORITY = "https://api.github.com/repos/"

def remote(repo, subpath):
    if repo not in {REPO, "DSLitvinov1/lesson3.1"}:
        raise ValueError("Non-Neurofactory repository access denied")
    if not subpath.startswith(("contents/", "commits", "actions/runs/")):
        raise ValueError("Unexpected audit endpoint")
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept":"application/vnd.github+json",
               "User-Agent":"NeurofactoryStage5ReadOnlyAcceptance"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(AUTHORITY + repo + "/" + subpath,
                                 headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=35) as stream:
        return json.load(stream)

def content(path, branch):
    if not path.startswith("bridge/neurofactory/") or "/../" in path:
        raise ValueError("Forbidden source path")
    item = remote(REPO, "contents/" + path + "?ref=" + branch)
    if item.get("path") != path:
        raise ValueError("Unexpected GitHub content path")
    return base64.b64decode(item["content"].replace("\n", ""))

def digest(blob):
    return hashlib.sha256(blob).hexdigest()

def ensure(value, why):
    if not value:
        raise ValueError("STAGE5_AUDIT_REJECTED: " + why)

def commit_history(branch, path, expected):
    found = remote(REPO, "commits?sha=" + branch + "&path=" + path + "&per_page=5")
    shas = [x["sha"] for x in found]
    ensure(shas == expected,
           "Repeat or missing publication for " + path + ": " + str(shas))
    return shas

def checkpoint(task):
    obj = json.loads(task)
    ensure(obj.get("schema") == 1 and isinstance(obj.get("data"), dict),
           "Checkpoint format invalid")
    data = obj["data"]
    canonical = json.dumps(data, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")
    ensure(obj.get("sha256") == digest(canonical),
           "Checkpoint integrity check failed")
    return data

def audit():
    plan = json.loads((ROOT/"roadmap.json").read_text("utf-8"))
    queue = json.loads((ROOT.parent/"universal_queue"/"inbox.json").read_text("utf-8"))
    roles = json.loads((ROOT/"agent_roles.json").read_text("utf-8"))
    states = {x["id"]:x["state"] for x in plan["milestones"]}
    ensure(plan.get("free_only") is True and plan.get("forbid_other_projects") is True,
           "Free-only / project scope protection disabled")
    ensure(plan.get("chat_delivery_paused") is True
       and states.get("NF-DEV-02") == "deferred"
       and states.get("NF-DEV-05") == "pending", "User-deferred stage was resumed or stage5 falsely completed")
    ensure(all(states.get(s) == "verified" for s in ("NF-DEV-01","NF-DEV-03","NF-DEV-04")),
           "Prerequisite acceptance missing")
    ensure(roles.get("roles",{}).get("writer",{}).get("model") == "qwen2.5-coder:7b"
       and roles.get("roles",{}).get("reviewer",{}).get("model") == "qwen3:4b"
       and roles.get("roles",{}).get("chat_sender",{}).get("activation") == "paused_by_user_until_explicit_resumption",
           "Agent separation or paused delivery lost")
    ensure(queue.get("scope") == "synthetic_only" and queue.get("paid_services") is False
       and queue.get("network_effects") is False, "Synthetic-only universal queue policy changed")
    ensure(len(queue.get("tasks", [])) == 2
       and all(task.get("state") == "verified_done"
           and task.get("proof",{}).get("reviewer") == "qwen3:4b"
           for task in queue["tasks"]), "Historic universal queue has unfinished/changed tasks")

    raw_state = content(STATE_PATH, STAGING)
    stored = json.loads(raw_state)
    ensure(stored.get("schema") == 1
       and stored.get("task_id") == "NF-DEV-04-LIVE-RECEIPT-20261013"
       and stored.get("chat_delivery") == "paused_by_user"
       and stored.get("scope") == "neurofactory_only",
           "Stage4 state identity changed")
    lanes = {k:checkpoint(v) for k,v in stored["files"].items()}
    ensure(set(lanes) == {"writer","reviewer","publisher"}
       and all(x.get("state") == "verified_done" for x in lanes.values()),
           "Incomplete real two-agent task")
    ensure([lanes[name]["attempts"] for name in ("writer","reviewer","publisher")] == [2,1,1]
       and stored.get("meta",{}).get("crash_injected") is True,
           "Real crash recovery evidence lost or task retried")
    ensure(lanes["writer"].get("actor") == "qwen2.5-coder:7b"
       and lanes["reviewer"].get("actor") == "qwen3:4b",
           "Original independent actors changed")

    candidate = content(WRITER_PATH,STAGING)
    review = json.loads(content(REVIEW_PATH,STAGING))
    initial_proof = json.loads(content(ORIGINAL_PROOF_PATH,BRANCH))
    hardened_proof = json.loads(content(HARDEN_PROOF_PATH,BRANCH))
    production = content(SOURCE_PATH,BRANCH)
    old = digest(candidate)
    new = digest(production)
    ensure(old != new, "Corrected source not distinguishable from original")
    ensure(initial_proof.get("source_sha256") == old
       and initial_proof.get("verdict") == "REVIEW_OK"
       and review.get("verdict") == "REVIEW_OK"
       and review.get("source_sha256") == old
       and hardened_proof.get("previous_source_sha256") == old
       and hardened_proof.get("source_sha256") == new
       and hardened_proof.get("reviewer",{}).get("verdict") == "REVIEW_OK",
           "Unverified source, reviewer or security correction")
    for name in ("writer","reviewer","publisher"):
        ensure(lanes[name].get("proof",{}).get("source_sha256") == old,
               "Task source fingerprint mismatch: " + name)

    commit_history(STAGING,WRITER_PATH,[lanes["writer"]["publication_sha"]])
    commit_history(STAGING,REVIEW_PATH,[lanes["reviewer"]["publication_sha"]])
    commit_history(BRANCH,SOURCE_PATH,[CORRECTION_COMMIT,INITIAL_COMMIT])
    ensure(lanes["publisher"]["publication_sha"] == INITIAL_COMMIT,
           "Repeated or incorrect trusted production receipt")

    for sha,allowed in ((INITIAL_COMMIT,{SOURCE_PATH,ORIGINAL_PROOF_PATH}),
                        (CORRECTION_COMMIT,{SOURCE_PATH,HARDEN_PROOF_PATH})):
        change = remote(REPO, "commits/"+sha)
        ensure({f["filename"] for f in change.get("files",[])} == allowed,
               "Unrelated projects affected by published change")

    usage = {}
    for repo,runid,label in ((REPO,KNOWN_AGENT_RUN,"real_agents"),
                             (REPO,KNOWN_HARDEN_RUN,"independent_security_recheck"),
                             ("DSLitvinov1/lesson3.1",KNOWN_WINDOWS_RUN,"reserve_windows")):
        run = remote(repo,"actions/runs/"+str(runid))
        ensure(run.get("conclusion") == "success" and run.get("status") == "completed",
               "Historical Github Actions run missing: " + label)
        started = dt.datetime.fromisoformat(run["run_started_at"].replace("Z","+00:00"))
        finished = dt.datetime.fromisoformat(run["updated_at"].replace("Z","+00:00"))
        usage[label] = {"run_id":runid,
                        "elapsed_wall_seconds":max(0,int((finished-started).total_seconds()))}
    ensure(sum(x["elapsed_wall_seconds"] for x in usage.values())>0,
           "Historical compute time unavailable")

    # This is a scoped audit of prior real work, not general-purpose new task dispatch.
    result={
        "audit_schema":1,
        "status":"non_chat_read_only_verified",
        "project":"Нейрозавод",
        "stage":"NF-DEV-05",
        "formal_stage_state":"pending_due_to_deferred_stage_02",
        "no_chat_delivery":True,
        "no_model_or_publisher_invocation":True,
        "new_paid_api_calls":0,
        "monetary_spend":"unverified_no_billing_connector",
        "validated_agents":["qwen2.5-coder:7b","qwen3:4b"],
        "archived_universal_queue_count":len(queue["tasks"]),
        "universal_queue_scope":"synthetic_only_not_production_development",
        "real_cycle_state_sha256":digest(raw_state),
        "real_cycle_attempts":{"writer":2,"reviewer":1,"publisher":1},
        "real_cycle_all_verified":True,
        "actual_publication_count":1,
        "distinct_security_correction_count":1,
        "writer_review_source_sha256":old,
        "current_hardened_source_sha256":new,
        "historical_resource_time":usage,
        "next_blocker":"unified_dynamic_self_development_queue_and_deferred_chat_dependency",
    }
    print("STAGE5_NONCHAT_ACCEPTANCE " + json.dumps(result,sort_keys=True,ensure_ascii=True),flush=True)
    return result

if __name__ == "__main__":
    audit()
