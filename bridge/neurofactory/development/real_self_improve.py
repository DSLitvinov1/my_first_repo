"""Real Neurofactory self-improvement: Qwen code author, strict tests, independent Qwen reviewer.

Generated code cannot write other files. Publisher receives only independently approved output.
"""
import ast, hashlib, json, os, pathlib, re, sys, urllib.request

ROOT=pathlib.Path(__file__).resolve().parent
OUT=pathlib.Path(os.environ.get("RUNNER_TEMP","/tmp"))/"nf-real-improvement"
OUT.mkdir(parents=True,exist_ok=True)
WRITER="qwen2.5-coder:7b"
REVIEWER="qwen3:4b"
GOOD=[
"bridge/neurofactory/development/control_plane.py",
"bridge/neurofactory/development/path_policy.py",
"bridge/neurofactory/universal_queue/queue_runner.py",
"bridge/neurofactory/sub/deep-module.py",
".github/workflows/neurofactory-real-self-improvement.yml",
".github/workflows/neurofactory-development-plan.yml"]
BAD=[
".github/workflows/other-project.yml","bridge/other_project/file.py",
"other_project/file.py","bridge/neurofactory/../other_project/main.py",
"bridge/neurofactory/sub/../../secret.txt","bridge/neurofactory//bad.py",
"bridge/neurofactory/./bad.py","bridge\\neurofactory\\bad.py",
"/bridge/neurofactory/main.py","C:\\Users\\file.py",
"bridge/neurofactory/",".github/workflows/neurofactory-",
".github/workflows/neurofactory-file.yml/../evil",
"bridge/neurofactory/x.py\nSECRET","bridge/neurofactory/name?.py",
"bridge/neurofactory/emoji💣.py","bridge/neurofactory/"+("x"*250)]
NONSTR=[None,23,[],{},True]
SAFE_FUNCS={"isinstance","len","all","any","str"}
SAFE_METHODS={"startswith","endswith","split","replace","isalnum","isascii"}
BANNED_NODES=(ast.Import,ast.ImportFrom,ast.Global,ast.Nonlocal,ast.With,ast.AsyncWith,
    ast.While,ast.For,ast.AsyncFor,ast.Try,ast.Raise,ast.Lambda,ast.ClassDef,
    ast.Delete,ast.Yield,ast.YieldFrom,ast.Await,ast.NamedExpr)
def ask(model,prompt,structured=False):
    payload={"model":model,"prompt":prompt[:8500],"stream":False,"think":False,
        "keep_alive":"0","options":{"num_ctx":4096,"num_predict":760,
        "num_thread":3,"num_gpu":0,"temperature":0}}
    if structured:payload["format"]="json"
    req=urllib.request.Request("http://127.0.0.1:11434/api/generate",
        data=json.dumps(payload).encode(),method="POST",headers={"Content-Type":"application/json"})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req,timeout=240) as response:data=json.load(response)
    if data.get("done") is not True:raise ValueError("AI answer incomplete")
    return str(data.get("response","")).strip()
def extract(text):
    match=re.search(r"(?m)^def approved_change_path\(path\):",text)
    if not match:raise ValueError("Missing exact required function")
    return text[match.start():].split(chr(96)*3,1)[0].strip()+"\n"
def validate_source(code):
    if not isinstance(code,str) or not 90<=len(code)<=1900:
        raise ValueError("Unacceptable generated code size")
    tree=ast.parse(code)
    if len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef):
        raise ValueError("Exactly one standalone function required")
    fn=tree.body[0]
    if fn.name!="approved_change_path" or [arg.arg for arg in fn.args.args]!=["path"] or fn.decorator_list:
        raise ValueError("Wrong function contract")
    for node in ast.walk(tree):
        if isinstance(node,BANNED_NODES):raise ValueError("Forbidden operation")
        if isinstance(node,ast.FunctionDef) and node is not fn:
            raise ValueError("Nested functions denied")
        if isinstance(node,ast.Call):
            f=node.func
            if isinstance(f,ast.Name) and f.id in SAFE_FUNCS:pass
            elif isinstance(f,ast.Attribute) and f.attr in SAFE_METHODS:pass
            else:raise ValueError("Unapproved function call")
        if isinstance(node,ast.Attribute) and node.attr not in SAFE_METHODS:
            raise ValueError("Unapproved attribute access")
        if isinstance(node,ast.Name) and node.id.startswith("__"):
            raise ValueError("Private identifier denied")
    return tree
def acceptance(code):
    tree=validate_source(code)
    safe={"isinstance":isinstance,"len":len,"all":all,"any":any,"str":str}
    ns={"__builtins__":safe}
    exec(compile(tree,"<checked-path-policy>","exec"),ns)
    fn=ns["approved_change_path"]
    for x in GOOD:
        if fn(x) is not True:raise ValueError("Rejected real Neurofactory path "+repr(x))
    for x in BAD+NONSTR:
        if fn(x) is not False:raise ValueError("Admitted forbidden path "+repr(x))
    return len(GOOD)+len(BAD)+len(NONSTR)
def run():
    if os.environ.get("GITHUB_REPOSITORY")!="DSLitvinov1/my_first_repo" or os.environ.get("NF_FREE_PUBLIC_CONFIRMED")!="yes":
        raise ValueError("Wrong repository, runner or paid context")
    if os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        raise ValueError("No model may have publication secrets")
    instruction=(
       "You are Qwen2.5-Coder, author of a NEW production Neurofactory Python "
       "path access policy. Output exactly one function def approved_change_path(path): "
       "and return only true Python code, no markdown or explanation. "
       "The policy must allow TWO independent prefix families: "
       "1. bridge/neurofactory/ followed by a nonempty relative file path; "
       "2. .github/workflows/neurofactory- followed by a nonempty filename ending in .yml. "
       "Both families MUST return True for real files; DO NOT reject .github simply "
       "because it begins with a dot. Deny everything else. "
       "First deny if not isinstance(path,str), path length above 240, "
       "or path.isascii() is False. "
       "Deny any backslash. Split EVERY input with path.split('/'), then deny "
       "if ANY segment is empty, '.' or '..'. IMPORTANT: do not reject a harmless "
       "segment like '.github'; only reject the exact strings '.' and '..'. "
       "Deny if ANY character in ANY segment is not alphanumeric or one of '._-'. "
       "Only AFTER those global checks test the two allowed prefixes. "
       "An accepted workflow MUST start with '.github/workflows/neurofactory-' "
       "and end with '.yml'. Normal source paths MUST start with 'bridge/neurofactory/'. "
       "Required True: bridge/neurofactory/development/control_plane.py, "
       ".github/workflows/neurofactory-real-self-improvement.yml. "
       "Required False: bridge/neurofactory/../other_project/main.py, "
       ".github/workflows/other-project.yml, bridge/neurofactory//bad.py, "
       "bridge\\\\neurofactory\\\\bad.py. "
       "Use only if statements, return statements, comprehensions and builtins "
       "isinstance,len,all,any,str. String methods allowed: "
       "startswith,endswith,split,replace,isalnum,isascii. "
       "No imports, file IO, classes, exec, eval, while, for loops, try, "
       "exception handling, function nesting or other function calls."
    )
    code=None
    feedback=""
    seen_candidates=set()
    for i in range(3):
        try:
            candidate=extract(ask(WRITER,instruction+feedback))
            fingerprint=hashlib.sha256(candidate.encode()).hexdigest()
            if fingerprint in seen_candidates:
                raise ValueError("Writer repeated an already rejected source; stop without replay")
            seen_candidates.add(fingerprint)
            checked=acceptance(candidate)
            code=candidate
            print("REAL_NF_WRITER_ACCEPTED",i+1,"test_count",checked,flush=True)
            break
        except (ValueError,SyntaxError,TypeError) as e:
            if "repeated an already rejected" in str(e):
                print("REAL_NF_WRITER_REJECTED_DUPLICATE",flush=True)
                break
            feedback="\nYour previous candidate failed: "+str(e)[:240]+(
                "\nRewrite it from the full-file-segment validation rules above. "
                "Ensure BOTH allowed prefix families accept real paths; "
                "do not repeat identical code.")
                
            print("REAL_NF_WRITER_REPAIR",i+1,str(e)[:120],flush=True)
    if code is None:raise ValueError("Unverified model output; no publication")
    prompt=("You are the second independent reviewer Qwen3. Review this REAL new "
      "GitHub file path safety function for an autonomous developer. It passed "
      "the trusted boundary tests. Does it prevent writing outside the Neurofactory "
      "allowlist, traversal, executable IO and unsafe strings? "
      "Return JSON only with verdict REVIEW_OK or REVIEW_BAD and reason. "
      "Reject doubtful code. Candidate:\n"+code)
    review=json.loads(ask(REVIEWER,prompt,True))
    if review.get("verdict")!="REVIEW_OK":raise ValueError("Independent Qwen reviewer rejected candidate")
    info={"stage":"NF-DEV-03","scope":"neurofactory_only",
        "writer":WRITER,"reviewer":REVIEWER,"review_verdict":"REVIEW_OK",
        "tests_passed":checked,"sha256":hashlib.sha256(code.encode()).hexdigest(),
        "reason":str(review.get("reason",""))[:350]}
    (OUT/"path_policy.py").write_text(code,"utf-8")
    (OUT/"verification.json").write_text(json.dumps(info,ensure_ascii=False,indent=2)+"\n","utf-8")
    print("REAL_NF_CODE_APPROVED",info["sha256"],checked,flush=True)
if __name__=="__main__":
    try:run()
    except Exception as e:
        print("REAL_NF_SAFE_STOP",type(e).__name__,str(e)[:260],flush=True)
        sys.exit(1)
