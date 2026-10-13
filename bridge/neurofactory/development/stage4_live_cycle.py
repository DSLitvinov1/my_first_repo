"""One authorized real Stage-4 self-development cycle with GitHub-persisted task state.

Deliberately does not send ChatGPT messages, change other projects or retry a
remote publication when an uncertain receipt needs reconciliation.
"""
import base64,hashlib,json,os,pathlib,subprocess,sys,tempfile,time,urllib.error,urllib.request
import stage4_queue as queue
import stage4_live_worker as worker

REPO="DSLitvinov1/my_first_repo"
STAGING="neurofactory-stage4-live-integration-20261013"
PROD="neurofactory-public-lab-20261012"
BASE="https://api.github.com/repos/"+REPO+"/"
ROOT=pathlib.Path(__file__).resolve().parent
SOURCE_PATH="bridge/neurofactory/development/stage4_receipt_rules.py"
REVIEW_PATH="bridge/neurofactory/development/stage4-live-reviewed.json"
STATE_PATH="bridge/neurofactory/development/stage4-live-state.json"
PROOF_PATH="bridge/neurofactory/development/stage4-live-proof.json"
CANDIDATE_PATH="bridge/neurofactory/development/stage4-live-candidate.py"
FIXED_TASK="NF-DEV-04-LIVE-RECEIPT-20261013"

def api(method,path,data=None):
    if not path.startswith(BASE):raise ValueError("Refuse cross-repository endpoint")
    token=os.environ.get("GITHUB_TOKEN")
    if not token:raise ValueError("Missing trusted GitHub publisher token")
    headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
             "Content-Type":"application/json","User-Agent":"NeurofactoryStage4Live"}
    req=urllib.request.Request(path,data=None if data is None else json.dumps(data).encode(),
                               method=method,headers=headers)
    with urllib.request.urlopen(req,timeout=35) as response:
        raw=response.read()
    return json.loads(raw) if raw else {}

def read_remote(path,branch):
    if not path.startswith("bridge/neurofactory/development/"):raise ValueError("Unsafe target")
    url=BASE+"contents/"+path+"?ref="+branch
    try:
        item=api("GET",url)
    except urllib.error.HTTPError as exc:
        if exc.code==404:return None
        raise
    return {"bytes":base64.b64decode(item["content"].replace("\n","")),
            "blob_sha":item["sha"],"path":item["path"]}

def sha256(data):return hashlib.sha256(data).hexdigest()

def file_commit(path,branch):
    data=api("GET",BASE+"commits?sha="+branch+"&path="+path+"&per_page=1")
    if not data:return None
    result=str(data[0].get("sha",""))
    if len(result)!=40 or any(c not in "0123456789abcdef" for c in result):
        raise ValueError("Invalid exact file commit")
    return result

def put_once(path,content,branch):
    if read_remote(path,branch) is not None:
        raise ValueError("Already published: never write again")
    args={"branch":branch,"message":"neurofactory-stage4-live: "+path.rsplit("/",1)[-1],
          "content":base64.b64encode(content).decode("ascii")}
    result=api("PUT",BASE+"contents/"+path,args)
    commit=result["commit"]["sha"]
    actual=read_remote(path,branch)
    if actual is None or actual["bytes"]!=content:
        raise ValueError("Remote published bytes not independently verified")
    return commit

def confirm(path,branch,expected):
    record=read_remote(path,branch)
    if record is None or record["bytes"]!=expected:
        raise ValueError("Real remote content absent or changed")
    result=file_commit(path,branch)
    if not result:raise ValueError("Real remote commit missing")
    return result

def direct_checkpoint_sync(state,store):
    """CAS save to GitHub after every local transition, before every effect."""
    blob={r:store.paths[r].read_text("utf-8") for r in queue.STAGES}
    document={"schema":1,"task_id":FIXED_TASK,"scope":"neurofactory_only",
              "chat_delivery":"paused_by_user","files":blob,"meta":state["meta"]}
    raw=(json.dumps(document,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
    args={"branch":STAGING,"message":"neurofactory-state: durable stage4 checkpoint",
          "content":base64.b64encode(raw).decode("ascii")}
    if state["sha"]:args["sha"]=state["sha"]
    answer=api("PUT",BASE+"contents/"+STATE_PATH,args)
    state["sha"]=answer["content"]["sha"]
    verified=read_remote(STATE_PATH,STAGING)
    if verified is None or verified["bytes"]!=raw:
        raise ValueError("State lost or modified on GitHub; stop before side effects")

def restore_into(directory,plan):
    store=queue.Stage4Queue(directory,plan)
    previous=read_remote(STATE_PATH,STAGING)
    if previous is None:
        if read_remote(SOURCE_PATH,PROD) is not None:
            raise ValueError("Published source exists without a durable state: manual audit required")
        store.prepare()
        state={"sha":None,"meta":{"crash_injected":False,"review_sha":None,"candidate_sha":None,
                                  "published_commit":None}}
        direct_checkpoint_sync(state,store)
        return store,state
    document=json.loads(previous["bytes"])
    if (document.get("task_id")!=FIXED_TASK or document.get("schema")!=1
          or document.get("scope")!="neurofactory_only"
          or document.get("chat_delivery")!="paused_by_user"
          or set(document.get("files",{}))!=set(queue.STAGES)):
        raise ValueError("Unsafe persisted queue state")
    for role,body in document["files"].items():
        if not isinstance(body,str):raise ValueError("Corrupt stored checkpoint")
        store.paths[role].write_text(body,"utf-8")
    store.prepare()
    return store,{"sha":previous["blob_sha"],"meta":document["meta"]}

def run_child(role,candidate,review,crash=False):
    env={k:v for k,v in os.environ.items() if k not in ("GITHUB_TOKEN","GH_TOKEN","NF_FREE_PUBLIC_CONFIRMED")}
    command=[sys.executable,"-B",str(ROOT/"stage4_live_worker.py"),
             "owned-crash" if crash else role,str(candidate),str(review)]
    p=subprocess.run(command,env=env,capture_output=True,text=True,timeout=360)
    print("NF4_ISOLATED_WORKER",role,p.returncode,p.stdout[-650:],p.stderr[-600:],flush=True)
    return p.returncode

def reconcile(store,state,role,remote_path,branch,expected):
    """A crash in publishing must NEVER publish again; check existing receipt only."""
    task=store._read(role)
    if task["state"] not in ("publishing","needs_receipt_check"):return False
    recovered=store.recover(int(time.time())+1)
    direct_checkpoint_sync(state,store)
    # Absence must remain waiting for manual audit, never resend automatically.
    remote=read_remote(remote_path,branch)
    if remote is None:
        raise ValueError("Ambiguous publication, no remote receipt; manual review, no retry")
    if expected is not None and remote["bytes"]!=expected:
        raise ValueError("Remote receipt mismatch: no replay")
    if role=="writer":
        digest=store._read(role).get("proof",{}).get("source_sha256")
        if sha256(remote["bytes"])!=digest:raise ValueError("Writer remote digest mismatch")
    elif role=="reviewer":
        proof=json.loads(remote["bytes"])
        if proof.get("source_sha256")!=store._read(role)["proof"]["source_sha256"] or proof.get("verdict")!="REVIEW_OK":
            raise ValueError("Reviewer remote evidence mismatch")
    elif role=="publisher":
        proof=read_remote(PROOF_PATH,PROD)
        if proof is None or json.loads(proof["bytes"]).get("source_sha256")!=store._read(role)["proof"]["source_sha256"]:
            raise ValueError("Production multi-file proof missing or mismatched")
    commit=confirm(remote_path,branch,remote["bytes"])
    store.acknowledge(role,commit,remote_verified=True)
    state["meta"][role+"_commit"]=commit
    direct_checkpoint_sync(state,store)
    print("NF4_RECONCILED_EXACT_REMOTE_RECEIPT",role,commit,flush=True)
    return True

def prod_publish(candidate,review_bytes):
    """Single atomic Git commit; stop if target exists. No token goes to models."""
    digest,passed=worker.check(candidate.decode("utf-8"))
    evidence=json.loads(review_bytes)
    if evidence.get("source_sha256")!=digest or evidence.get("verdict")!="REVIEW_OK":
        raise ValueError("Independent model review does not match exact tested source")
    if read_remote(SOURCE_PATH,PROD) is not None or read_remote(PROOF_PATH,PROD) is not None:
        raise ValueError("Source already exists; never duplicate a production publication")
    receipt={"stage":"NF-DEV-04","task":FIXED_TASK,"source_sha256":digest,
             "writer":"qwen2.5-coder:7b","reviewer":"qwen3:4b","verdict":"REVIEW_OK",
             "behavior_tests":passed,"review":evidence,"chat_delivery":"paused_by_user",
             "scope":"neurofactory_only"}
    before=api("GET",BASE+"git/ref/heads/"+PROD)["object"]["sha"]
    original=api("GET",BASE+"git/commits/"+before)
    tree=api("POST",BASE+"git/trees",{"base_tree":original["tree"]["sha"],
       "tree":[{"path":SOURCE_PATH,"mode":"100644","type":"blob","content":candidate.decode()},
               {"path":PROOF_PATH,"mode":"100644","type":"blob","content":json.dumps(receipt,sort_keys=True,indent=2)+"\n"}]})
    commit=api("POST",BASE+"git/commits",{"message":"neurofactory: one real independently reviewed stage4 receipt integrity improvement",
        "parents":[before],"tree":tree["sha"]})
    api("PATCH",BASE+"git/refs/heads/"+PROD,{"sha":commit["sha"],"force":False})
    actual=read_remote(SOURCE_PATH,PROD)
    if actual is None or actual["bytes"]!=candidate:raise ValueError("Published source verification failed")
    print("NF4_SINGLE_PRODUCTION_COMMIT",commit["sha"],flush=True)
    return commit["sha"]

def run():
    if (os.environ.get("GITHUB_REPOSITORY")!=REPO
            or os.environ.get("GITHUB_REF_NAME")!=STAGING
            or os.environ.get("NF_FREE_PUBLIC_CONFIRMED")!="yes"):
        raise ValueError("Not the approved public free Stage4 run")
    plan=json.loads((ROOT/"roadmap.json").read_text("utf-8"))
    with tempfile.TemporaryDirectory(prefix="neurofactory-real-stage4-") as directory:
        root=pathlib.Path(directory)
        candidate=root/"candidate.py"; review=root/"review.json"
        store,state=restore_into(directory,plan)
        print("NF4_RESTORED", {r:store._read(r)["state"] for r in queue.STAGES},flush=True)
        if store._read("writer")["state"]=="verified_done":
            old=read_remote(CANDIDATE_PATH,STAGING)
            if old is None:raise ValueError("Verified writer candidate missing remotely")
            candidate.write_bytes(old["bytes"]);worker.check(candidate.read_text("utf-8"))
        if store._read("writer")["state"] in ("publishing","needs_receipt_check"):
            reconcile(store,state,"writer",CANDIDATE_PATH,STAGING,None)
            candidate.write_bytes(read_remote(CANDIDATE_PATH,STAGING)["bytes"])
        if store._read("writer")["state"] in ("queued","running"):
            current=store._read("writer")
            if current["state"]=="running":
                store.recover(int(current["lease_until"] or 0)+1)
                direct_checkpoint_sync(state,store)
            if not state["meta"].get("crash_injected"):
                store.claim("writer",100,10);direct_checkpoint_sync(state,store)
                state["meta"]["crash_injected"]=True;direct_checkpoint_sync(state,store)
                if run_child("writer",candidate,review,crash=True)!=73:
                    raise ValueError("Actual owned subprocess interruption did not occur")
                store.recover(120);direct_checkpoint_sync(state,store)
            store.claim("writer",int(time.time()),120);direct_checkpoint_sync(state,store)
            if run_child("writer",candidate,review)!=0:raise ValueError("First real AI writer failed")
            src=candidate.read_bytes();digest,passed=worker.check(src.decode())
            store.before_external_effect("writer",source_sha256=digest);direct_checkpoint_sync(state,store)
            if read_remote(CANDIDATE_PATH,STAGING) is None:
                put_once(CANDIDATE_PATH,src,STAGING)
            reconcile(store,state,"writer",CANDIDATE_PATH,STAGING,src)
        if store._read("reviewer")["state"]=="verified_done":
            ref=read_remote(REVIEW_PATH,STAGING)
            if ref is None:raise ValueError("Missing independently reviewed evidence")
            review.write_bytes(ref["bytes"])
        if store._read("reviewer")["state"] in ("publishing","needs_receipt_check"):
            reconcile(store,state,"reviewer",REVIEW_PATH,STAGING,None)
            review.write_bytes(read_remote(REVIEW_PATH,STAGING)["bytes"])
        if store._read("reviewer")["state"] in ("queued","running"):
            t=store._read("reviewer")
            if t["state"]=="running":
                store.recover(int(t["lease_until"] or 0)+1);direct_checkpoint_sync(state,store)
            store.claim("reviewer",int(time.time()),120);direct_checkpoint_sync(state,store)
            if run_child("reviewer",candidate,review)!=0:raise ValueError("Second independent AI rejected")
            evidence=json.loads(review.read_text("utf-8"))
            digest,_=worker.check(candidate.read_text("utf-8"))
            if evidence["source_sha256"]!=digest or evidence["verdict"]!="REVIEW_OK":
                raise ValueError("Reviewer approved a different source")
            store.before_external_effect("reviewer",source_sha256=digest,verdict="REVIEW_OK")
            direct_checkpoint_sync(state,store)
            if read_remote(REVIEW_PATH,STAGING) is None:
                put_once(REVIEW_PATH,review.read_bytes(),STAGING)
            reconcile(store,state,"reviewer",REVIEW_PATH,STAGING,review.read_bytes())
        if store._read("publisher")["state"] in ("publishing","needs_receipt_check"):
            reconcile(store,state,"publisher",SOURCE_PATH,PROD,candidate.read_bytes())
        if store._read("publisher")["state"] in ("queued","running"):
            t=store._read("publisher")
            if t["state"]=="running":
                store.recover(int(t["lease_until"] or 0)+1);direct_checkpoint_sync(state,store)
            store.claim("publisher",int(time.time()),120);direct_checkpoint_sync(state,store)
            store.before_external_effect("publisher");direct_checkpoint_sync(state,store)
            # Actual publication is performed in an owned child, then deliberately terminated
            # *after* the remote Git commit. Parent must reconcile, never republish.
            p=subprocess.run([sys.executable,"-B",str(ROOT/"stage4_live_cycle.py"),
                  "--publish-owned-child",str(candidate),str(review)],env=os.environ.copy(),
                  capture_output=True,text=True,timeout=90)
            print("NF4_PUBLISH_CHILD_EXIT",p.returncode,p.stdout[-500:],p.stderr[-400:],flush=True)
            if p.returncode!=74:
                raise ValueError("Real owned publisher did not stop after publication; receipt audit required")
            reconcile(store,state,"publisher",SOURCE_PATH,PROD,candidate.read_bytes())
        if any(store._read(r)["state"]!="verified_done" for r in queue.STAGES):
            raise ValueError("Not all exact remote receipts verified")
        if store._read("publisher")["publication_sha"]!=confirm(SOURCE_PATH,PROD,candidate.read_bytes()):
            raise ValueError("Final source commit has changed")
        print("NF4_REAL_CYCLE_VERIFIED_NO_REPLAY",store._read("publisher")["publication_sha"],flush=True)

if __name__=="__main__":
    try:
        if len(sys.argv)>1 and sys.argv[1]=="--publish-owned-child":
            prod_publish(pathlib.Path(sys.argv[2]).read_bytes(),pathlib.Path(sys.argv[3]).read_bytes())
            sys.stdout.flush()
            os._exit(74)
        run()
    except Exception as exc:
        print("NF4_LIVE_SAFE_STOP",type(exc).__name__,str(exc)[:350],flush=True)
        sys.exit(1)
