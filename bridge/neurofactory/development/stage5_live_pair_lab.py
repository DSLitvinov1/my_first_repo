"""Two isolated sequential model tasks. No GitHub token, paid API or ChatGPT sender."""
import ast
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.request

JOBS=(
 ("NF-DEV-05-Q001","stage5_task_registry.py","valid_task_ids",
  "Return True only for a nonempty list of unique strings, each exactly 'NF-DEV-05-Q' followed by three decimal digits. Reject every invalid input."),
 ("NF-DEV-05-Q002","stage5_receipt_reconciliation.py","reconcile_receipt",
  "Return exact STRINGS. When state is 'publishing' or 'needs_receipt_check': "
  "if published is True and hash_matches is True return 'verify'; "
  "if published is False return 'wait'; else return 'block'. "
  "For 'verified_done' return 'done' only if both flags are exactly True, else 'block'. "
  "For 'queued' return 'ready' only if published is exactly False, else 'block'. "
  "For any other state return 'block'. Never return other words such as 'verified' or 'ok'.")
)
P="bridge/neurofactory/development/"
BUILTINS={"isinstance":isinstance,"len":len,"all":all,"set":set,"str":str,"list":list,"bool":bool,"any":any}
METHODS={"startswith","isdigit","get"}
BANNED=(ast.Import,ast.ImportFrom,ast.ClassDef,ast.Global,ast.Nonlocal,
        ast.With,ast.AsyncWith,ast.Try,ast.Raise,ast.Delete,ast.Lambda,
        ast.Await,ast.Yield,ast.YieldFrom,ast.AsyncFunctionDef)

def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def check_source(src,name):
    if not isinstance(src,str) or not 70<=len(src)<=2200:
        raise ValueError("Source length")
    tree=ast.parse(src)
    if len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef):
        raise ValueError("Exactly one function")
    f=tree.body[0]
    expected=["items"] if name=="valid_task_ids" else ["state","published","hash_matches"]
    if f.name!=name or [arg.arg for arg in f.args.args]!=expected:
        raise ValueError("Wrong public function contract")
    for node in ast.walk(tree):
        if isinstance(node,BANNED):
            raise ValueError("Unsafe generated source")
        if isinstance(node,ast.FunctionDef) and node is not f:
            raise ValueError("Nested function not permitted")
        if isinstance(node,ast.Name) and node.id.startswith("__"):
            raise ValueError("Dunder access denied")
        if isinstance(node,ast.Attribute) and node.attr not in METHODS:
            raise ValueError("Method denied")
        if isinstance(node,ast.Call):
            callee=node.func
            if isinstance(callee,ast.Name) and callee.id in BUILTINS:continue
            if isinstance(callee,ast.Attribute) and callee.attr in METHODS:continue
            raise ValueError("Call denied")
    namespace={"__builtins__":BUILTINS}
    exec(compile(tree,"<untrusted-isolated-Qwen-source>","exec"),namespace)
    func=namespace[name]
    if name=="valid_task_ids":
        vectors=[
            (["NF-DEV-05-Q001"],True),
            (["NF-DEV-05-Q001","NF-DEV-05-Q002"],True),
            (["NF-DEV-05-Q001","NF-DEV-05-Q001"],False),
            ([],False),(None,False),("NF-DEV-05-Q001",False),
            ([42],False),(["NF-DEV-05-Q001","other"],False),
            (["NF-DEV-05-Q01"],False),(["NF-DEV-05-Q0001"],False),
            (["NF-DEV-04-Q001"],False),(["NF-DEV-05-QABC"],False)]
    else:
        vectors=[
            (("publishing",True,True),"verify"),
            (("needs_receipt_check",True,True),"verify"),
            (("publishing",False,True),"wait"),
            (("needs_receipt_check",False,False),"wait"),
            (("publishing",True,False),"block"),
            (("needs_receipt_check",True,False),"block"),
            (("queued",False,False),"ready"),
            (("queued",True,True),"block"),
            (("verified_done",True,True),"done"),
            (("verified_done",False,True),"block"),
            (("running",True,True),"block"),
            (("publishing",1,True),"block"),((None,False,False),"block")]
    for index,(args,expected_value) in enumerate(vectors):
        actual=func(args) if name=="valid_task_ids" else func(*args)
        if type(actual)!=type(expected_value) or actual!=expected_value:
            raise ValueError("Behavior test "+str(index)+" input="+repr(args)+" expected="+repr(expected_value)+" actual="+repr(actual))
    return {"source_sha256":digest(src),"behavior_cases":len(vectors)}

def ask(model,prompt):
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        raise ValueError("Publisher token must not reach a model")
    request_body={"model":model,"prompt":prompt[:7500],"stream":False,
       "keep_alive":"0","think":False,
       "options":{"num_ctx":3500,"num_predict":400,"num_thread":4,"num_gpu":0,"temperature":0}}
    if model=="qwen3:4b":request_body["format"]="json"
    request=urllib.request.Request("http://127.0.0.1:11434/api/generate",
        data=json.dumps(request_body).encode(),method="POST",
        headers={"Content-Type":"application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=230) as reply:
        answer=json.load(reply)
    if answer.get("done") is not True or not str(answer.get("model","")).startswith(model):
        raise RuntimeError("Unfinished/wrong model output")
    return str(answer.get("response","")).strip()

def write(function,objective):
    prompt=("You are FIRST agent Qwen2.5 Coder. Write a single pure Python "
        "function named "+function+". "+objective+" Use parameter names exactly: "+
        ("items" if function=="valid_task_ids" else "state,published,hash_matches")+
        ". ONLY Python source, no imports or explanation, no I/O, no nested definitions. "
        "Allowed builtins isinstance,len,all,set,str,list,bool,any; string methods startswith,isdigit. "
        "For task IDs, use len(set(items)) to reject duplicates (do NOT call set.add). "
        "The required prefix is exactly NF-DEV-05-Q followed by 3 digits, total length 14. "
        "For receipt flags compare with is True / is False, never trust truthy integers. "
        "For reconcile_receipt implement this exact decision table: "
        "state publishing and flags True,True -> verify; "
        "state needs_receipt_check and True,True -> verify; "
        "publishing or needs_receipt_check and published False -> wait; "
        "publishing or needs_receipt_check with published True and hash_matches False -> block; "
        "verified_done with True,True -> done; "
        "queued with published False -> ready; all other situations -> block. "
        "Use literal string outputs, never Booleans.")
    failure=""
    for attempt in range(3):
        raw=ask("qwen2.5-coder:7b",prompt+failure)
        pattern=re.search(r"(?m)^def "+function+r"\(",raw)
        if not pattern:
            print("NF5_WRITER_RETRY",function,attempt+1,"missing_function_header",flush=True)
            failure="\nReturn a single def only, not Markdown."
            continue
        source=raw[pattern.start():].split(chr(96)*3,1)[0].strip()+"\n"
        try:return source,check_source(source,function)
        except (SyntaxError,ValueError,TypeError,NameError) as exc:
            print("NF5_WRITER_RETRY",function,attempt+1,type(exc).__name__,str(exc)[:160],flush=True)
            failure="\nLast candidate failed: "+str(exc)[:140]+". Correct it. Avoid banned calls/imports."
    raise RuntimeError("Unaccepted writer candidate; safe stop")

def review(function,source,proof):
    prompt=("INDEPENDENT Qwen3 4B security reviewer. You did not author this "
       "production Neurofactory helper. Independently examine the exact Python code "
       "and its behavior. It passed "+str(proof["behavior_cases"])+" deterministic tests. "
       "Return JSON with fields verdict (REVIEW_OK or REVIEW_BAD) and reason. "
       "If REVIEW_BAD give a concrete failing input. Do not trust author assertions. "
       "Function "+function+". SOURCE:\n"+source)
    reply=json.loads(ask("qwen3:4b",prompt))
    verdict=reply.get("verdict");reason=str(reply.get("reason",""))[:600]
    print("NF5_INDEPENDENT_REVIEW",function,verdict,reason,flush=True)
    if verdict!="REVIEW_OK" or len(reason)<10:
        raise RuntimeError("Independent Qwen review missing or rejected")
    return {"verdict":verdict,"reason":reason,"reviewer":"qwen3:4b",
            "source_sha256":proof["source_sha256"]}

def run(directory,selected_id):
    out=pathlib.Path(directory)
    if not out.is_dir() or out.is_symlink():
        raise ValueError("Use precreated isolated scratch")
    if selected_id not in {item[0] for item in JOBS}:
        raise ValueError("Only one approved task may be generated per durable job")
    for job_id,filename,function,objective in JOBS:
        if selected_id != job_id:
            continue
        source,proof=write(function,objective)
        verdict=review(function,source,proof)
        (out/filename).write_text(source,"utf-8")
        evidence={"task_id":job_id,"target":P+filename,
             "writer":"qwen2.5-coder:7b","reviewer":"qwen3:4b",
             "source_sha256":proof["source_sha256"],"tests":proof["behavior_cases"],
             "independent_verdict":verdict,"scope":"neurofactory_only",
             "chat_delivery":"paused_by_user"}
        (out/(filename+".proof.json")).write_text(json.dumps(evidence,indent=2)+"\n","utf-8")
        print("NF5_REAL_BOTH_MODELS_APPROVED",job_id,proof["source_sha256"],flush=True)
    print("NF5_ONE_REVIEWED_TASK_READY",selected_id,flush=True)

if __name__=="__main__":
    if len(sys.argv)!=3:raise ValueError("Need scratch dir and exact task ID")
    run(sys.argv[1],sys.argv[2])
