"""Second independent synthetic application: package volume and box count.

Only model-proposed pure arithmetic functions can be published. All tests and
the CLI entrypoint are fixed, allowlisted synthetic templates.
"""
import ast,datetime,hashlib,json,os,pathlib,subprocess,sys,time
import isolated_first_app as first
MODEL_WRITER=first.MODEL_WRITER
MODEL_REVIEWER=first.MODEL_REVIEWER
ROOT=pathlib.Path(os.environ.get("RUNNER_TEMP","/tmp"))/"neurofactory_cloud_second_app"
TEMPLATE=pathlib.Path(__file__).resolve().parents[3]/"bridge/neurofactory/pilots/second_app"
FILES=("volume.py","boxes.py","main.py","test_app.py","README.md")
SPEC={
 "volume":{"name":"parcel_volume","params":["length","width","height"],
           "wrong":"def parcel_volume(length, width, height):\n    return length + width + height\n",
           "require":"Multiply length times width times height; do NOT add the three numbers.",
           "cases":[((2,3,4),24),((1,1,1),1),((3,5,7),105),((0,3,4),0)]},
 "boxes":{"name":"boxes_needed","params":["items","per_box"],
          "wrong":"def boxes_needed(items, per_box):\n    return items // per_box\n",
          "require":"Count required boxes rounding UP a partial final box. "
                    "Return (items + per_box - 1) // per_box. Inputs already validated externally.",
          "cases":[((11,4),3),((8,4),2),((0,5),0),((7,3),3)]}
}
SAFE={ast.Module,ast.FunctionDef,ast.arguments,ast.arg,ast.Return,ast.BinOp,
      ast.Name,ast.Load,ast.Mult,ast.Add,ast.Sub,ast.FloorDiv,ast.Constant}

def safe_file(name):
    if name not in FILES and name!="verification-manifest.json":raise ValueError("Unknown synthetic artifact")
    ROOT.mkdir(parents=True,exist_ok=True)
    f=ROOT/name
    if ROOT.is_symlink() or f.is_symlink() or f.resolve().parent!=ROOT.resolve():
        raise ValueError("Unsafe artifact")
    return f

def verify(code,key):
    spec=SPEC[key]
    tree=ast.parse(code)
    if len(tree.body)!=1 or type(tree.body[0]) is not ast.FunctionDef:
        raise ValueError("One function required")
    fn=tree.body[0]
    if fn.name!=spec["name"] or [a.arg for a in fn.args.args]!=spec["params"] or fn.decorator_list or len(fn.body)!=1 or type(fn.body[0]) is not ast.Return:
        raise ValueError("Unsafe signature or function shape")
    for n in ast.walk(tree):
        if type(n) not in SAFE:raise ValueError("Disallowed syntax")
        if isinstance(n,ast.Name) and n.id not in spec["params"]:raise ValueError("Unexpected identifier")
        if isinstance(n,ast.Constant) and (type(n.value) is not int or abs(n.value)>10):raise ValueError("Unexpected constant")
    scope={"__builtins__":{}}
    exec(compile(tree,"<synthetic-code>","exec"),scope)
    fn=scope[spec["name"]]
    for args,expected in spec["cases"]:
        if fn(*args)!=expected:raise ValueError("Incorrect arithmetic output")
    return len(spec["cases"])

def run_tests():
    env={k:v for k,v in os.environ.items() if k in ("PATH","HOME","LANG","TMPDIR")}
    test=subprocess.run([sys.executable,"-S","test_app.py"],cwd=ROOT,
            capture_output=True,text=True,timeout=18,env=env)
    if test.returncode!=0:raise ValueError("Second-app regression tests failed: "+test.stderr[-350:])
    smoke=subprocess.run([sys.executable,"-S","main.py","2","3","4","11","4"],
            cwd=ROOT,capture_output=True,text=True,timeout=12,env=env)
    if smoke.returncode!=0 or smoke.stdout.strip()!="24 3":
        raise ValueError("Second-app command test failed")
    return {"passed":10,"total":10,"smoke_output":"24 3"}

def validated_manifest(report):
    if report.get("status")!="two_models_reviewed" or report.get("reviewer",{}).get("verdict")!="REVIEW_OK":
        raise ValueError("Missing independent model approval")
    if report.get("tests",{}).get("passed")!=10:raise ValueError("Not all checks passed")
    if set(report.get("hashes",{}))!=set(FILES):raise ValueError("Missing file proofs")
    for f in FILES:
        if hashlib.sha256(safe_file(f).read_bytes()).hexdigest()!=report["hashes"][f]:
            raise ValueError("A source file changed after approval")
    for key in SPEC:
        verify(safe_file(key+".py").read_text(encoding="utf-8"),key)
    run_tests()
    return True

def run():
    if os.environ.get("NEUROFACTORY_PUBLIC_FREE_RUN_CONFIRMED")!="yes":
        raise ValueError("Public GitHub-hosted runner free confirmation missing")
    if os.environ.get("GITHUB_REPOSITORY")!="DSLitvinov1/my_first_repo":
        raise ValueError("Unexpected repository")
    started=time.monotonic()
    for file in ("main.py","test_app.py"):
        safe_file(file).write_text((TEMPLATE/file).read_text(encoding="utf-8"),encoding="utf-8")
    safe_file("README.md").write_text(
        "# Qwen packaging assistant (synthetic)\n"
        "volume.py and boxes.py were authored by the first local Qwen model on an ephemeral public GitHub-hosted runner.\n"
        "The main script and 10 tests are preapproved templates. Second Qwen independently verifies the two functions.\n"
        "No real parcels, private projects, user data or paid APIs.\n",encoding="utf-8")
    report={"status":"started","application":"Synthetic packaging and box count",
            "writer":MODEL_WRITER,"reviewer":None,"verified_code_modules":[]}
    for key,spec in SPEC.items():
        prompt=("Return ONLY a complete corrected Python function, no markdown and no explanations. "
                +spec["require"]+"\nBroken code:\n"+spec["wrong"])
        raw=first.prompt_model(MODEL_WRITER,prompt,150)
        code=first.extract_function(raw,spec["name"])
        verified=verify(code,key)
        safe_file(key+".py").write_text(code,encoding="utf-8")
        report["verified_code_modules"].append({"name":key,"verified_examples":verified})
    report["tests"]=run_tests()
    explanation=("You are an independent programmer reviewing two pure functions against these EXACT formulas. "
        "parcel_volume(length,width,height) must return length * width * height. "
        "boxes_needed(items,per_box) must return (items + per_box - 1) // per_box, counting partial boxes. "
        "Read both actual function bodies below. Return ONLY a JSON object with field verdict "
        "equal to REVIEW_OK if both match exactly, otherwise REVIEW_BAD. No extra keys or reasoning.\n"
        "Function one:\n"+safe_file("volume.py").read_text(encoding="utf-8")
        +"\nFunction two:\n"+safe_file("boxes.py").read_text(encoding="utf-8"))
    raw=first.prompt_model(MODEL_REVIEWER,explanation,200)
    print("Second-app reviewer JSON:",repr(raw[:500]),flush=True)
    try:
        verdict=json.loads(raw).get("verdict")
    except (ValueError,AttributeError,TypeError):verdict=None
    if verdict not in ("REVIEW_OK","REVIEW_BAD"):verdict="UNCLEAR"
    report["reviewer"]={"model":MODEL_REVIEWER,"verdict":verdict}
    if verdict!="REVIEW_OK":raise ValueError("Second agent did not approve")
    report["status"]="two_models_reviewed"
    report["hashes"]={f:hashlib.sha256(safe_file(f).read_bytes()).hexdigest() for f in FILES}
    report["elapsed_seconds"]=round(time.monotonic()-started,1)
    validated_manifest(report)
    safe_file("verification-manifest.json").write_text(json.dumps(report,ensure_ascii=True,indent=2),encoding="utf-8")
    print(json.dumps({"status":report["status"],"module_count":2,"tests":10,
                      "reviewer":MODEL_REVIEWER,"time_seconds":report["elapsed_seconds"]}))
    return report
if __name__=="__main__":
    try:run()
    except Exception as e:
        print("Second synthetic application stopped safely:",type(e).__name__,str(e)[:240])
        sys.exit(1)
