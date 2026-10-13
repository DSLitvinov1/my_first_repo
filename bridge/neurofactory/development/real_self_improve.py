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
"bridge/neurofactory/sub/./safe.py",
"bridge/neurofactory/a/..",
"bridge/neurofactory/a//b.py",
"bridge/neurofactory/a/b.py/",
".github/workflows/neurofactory-ok.yml/",
".github/workflows/neurofactory-x.yml/secret",
".github/workflows/neurofactory-.yml/other",
"bridge/neurofactory/file.py%2f..",
"bridge/neurofactory/file.py#fragment",
"bridge/neurofactory/file.py?mode=unsafe",
"bridge/neurofactory/name\tbad.py",
"bridge/neurofactory/name\rbad.py",
"bridge/neurofactory/name:bad.py",
"bridge/neurofactory/name\\bad.py",
"bridge/neurofactory/name\x00bad.py",
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
        "You are the FIRST AI code author implementing one NEW REAL production Neurofactory file-path allowlist function."
        "Return ONLY the complete Python source: exactly one def approved_change_path(path): with a bool return and no Markdown."
        "Preserve this correct production security reference algorithm exactly in behavior; you may simplify wording but NEVER remove a validation."
        "REFERENCE SOURCE:\n"
        "def approved_change_path(path):\n    if not isinstance(path, str) or len(path) < 5 or len(path) > 240 or not path.isascii():\n        return False\n    if '\\\\\\\\' in path:\n        return False\n    parts = path.split('/')\n    if not all(part != '' and part != '.' and part != '..' and all(c.isalnum() or c in '._-' for c in part) for part in parts):\n        return False\n    if path.startswith('bridge/neurofactory/'):\n        return True\n    if path.startswith('.github/workflows/neurofactory-') and path.endswith('.yml'):\n        return True\n    return False\n"
        "Both independent allowed families MUST accept real files. Dot-prefixed .github segment is legitimate. Reject exact '.' and '..' segments. Reject path traversal and any non-ASCII."
        "Do NOT require Python files to end in .yml. Restrict .yml suffix only to .github/workflows/neurofactory- files."
        "All input checks MUST occur before both allowed prefixes are evaluated. Always deny everything outside Neurofactory."
        "Never invoke IO, imports, syscalls, eval, exec or secrets. Only pure Python if, return, comprehensions and allowed builtins/methods."
        "Pass all published positive and forbidden-path acceptance vectors, including real bridge/neurofactory/development/control_plane.py and .github/workflows/neurofactory-real-self-improvement.yml."
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
            feedback=("\nPrevious candidate rejected: "+str(e)[:240]
                      +"\nFix the exact rejected input. Follow the REFERENCE SOURCE faithfully. "
                      +"The next proposal must not repeat the failed candidate.")
            print("REAL_NF_WRITER_REPAIR",i+1,str(e)[:120],flush=True)
    if code is None:raise ValueError("Unverified model output; no publication")
    prompt=(
      "You are the INDEPENDENT second AI reviewer. The first AI has authored "
      "the code below. Evaluate it against the SPECIFIC approved Neurofactory "
      "source-and-workflow allowlist, NOT an imagined broader security rule. "
      "Family A: safe ASCII relative files under bridge/neurofactory/ are allowed. "
      "Family B: safe .github/workflows/neurofactory-*.yml files are allowed. "
      "Everything else is forbidden; empty, '.', '..' path segments, trailing "
      "slashes, backslashes, absolute and non-ASCII paths must be rejected. "
      "Trusted independent Python structural checks prohibit IO, imports, "
      "exec/eval, process launching and dangerous APIs. "
      "Trustworthy behavior tests have already checked 43 concrete cases. "
      "These exact failure modes were tested and are REJECTED by the candidate: "
      "bridge/neurofactory/a//b.py, bridge/neurofactory/a/b.py/, "
      "bridge/neurofactory/../other_project/main.py, "
      ".github/workflows/neurofactory-ok.yml/. "
      "Positive tested case: bridge/neurofactory/development/control_plane.py. "
      "Find a REAL untested security flaw or wrong permitted behavior, if any. "
      "If verdict is REVIEW_BAD, give a literal counterexample path whose "
      "behavior contradicts the policy, and expected_allow (true or false). "
      "Do not reject without a concrete path. Missing IO checks are not a "
      "valid flaw because AST restrictions already prevent executable IO. "
      "Return only a JSON object with verdict REVIEW_OK or REVIEW_BAD, "
      "reason, counterexample, expected_allow. If you cannot identify "
      "a concrete defect, use REVIEW_OK, empty counterexample and false "
      "expected_allow. Candidate:\n"+code
    )
    review=None
    for review_round in range(2):
        report=json.loads(ask(REVIEWER,prompt,True))
        verdict=report.get("verdict")
        why=str(report.get("reason",""))[:350]
        sample=report.get("counterexample","")
        expect=report.get("expected_allow")
        print("REAL_NF_INDEPENDENT_REVIEW",review_round+1,
              str(verdict)[:35],why[:200],flush=True)
        if verdict=="REVIEW_OK" and not sample:
            review=report
            break
        if verdict!="REVIEW_BAD":
            raise ValueError("Independent reviewer returned invalid or unsupported verdict")
        if isinstance(sample,str) and sample and isinstance(expect,bool):
            tree=validate_source(code)
            safe={"isinstance":isinstance,"len":len,"all":all,"any":any,"str":str}
            isolated={"__builtins__":safe}
            exec(compile(tree,"<checked-independent-review>","exec"),isolated)
            observed=isolated["approved_change_path"](sample)
            if observed is not expect:
                raise ValueError("Independent reviewer found actual failing path; publication denied")
            feedback=("Your reported failing path returns "+str(observed)+
                      ", exactly the expected "+str(expect)+
                      ". This is NOT a counterexample. Re-examine the source "
                      "and the stated allowlist; identify a REAL failure or "
                      "return REVIEW_OK with empty counterexample. ")
        else:
            feedback=("A REVIEW_BAD verdict must include a literal, reproducible "
                      "path AND expected_allow true/false. The candidate passed "
                      "the exact empty-segment and trailing-slash cases. "
                      "Find a verifiable failing input, or return REVIEW_OK. ")
        if review_round==1:
            raise ValueError("Independent reviewer did not positively approve candidate")
        prompt=feedback+"\nOriginal security assessment:\n"+prompt
    if review is None or review.get("verdict")!="REVIEW_OK":
        raise ValueError("Second agent did not approve; publication denied")
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
