"""Isolated GitHub-hosted Qwen first-app pilot (only for budget-approved runs).
Produces one independently tested sample application. It cannot access
business projects, accepts no untrusted task instructions and holds no token.
"""
import ast,hashlib,json,os,pathlib,re,subprocess,sys,time,urllib.request,datetime

MODEL_WRITER="qwen2.5-coder:1.5b"
MODEL_REVIEWER="qwen3:1.7b"
API="http://127.0.0.1:11434/api/generate"
ROOT=pathlib.Path(os.environ.get("RUNNER_TEMP","/tmp"))/"neurofactory_cloud_first_app"
REPO_ROOT=pathlib.Path(__file__).resolve().parents[3]
APP_REF=REPO_ROOT/"bridge/neurofactory/pilots/first_app"
CASES={
    "pricing":{"name":"line_total","params":("quantity","unit_price"),
               "broken":"def line_total(quantity, unit_price):\n    return quantity + unit_price\n",
               "tip":"Multiply quantity by unit_price, do not add.",
               "tests":[((3,150),450),((0,99),0),((7,12),84),((11,20),220)]},
    "discount":{"name":"discounted_total","params":("subtotal","percent"),
                "broken":"def discounted_total(subtotal, percent):\n    return subtotal - percent\n",
                "tip":"Return subtotal * (100 - percent) // 100 using integer arithmetic.",
                "tests":[((450,10),405),((100,0),100),((120,25),90),((99,100),0)]}
}
NAMES=("pricing.py","discount.py","main.py","test_app.py","README.md")
ALLOWED=(ast.Module,ast.FunctionDef,ast.arguments,ast.arg,ast.Return,
         ast.BinOp,ast.Name,ast.Load,ast.Mult,ast.Sub,ast.FloorDiv,ast.Constant)
def get_memory_gb():
    try:
        with open("/proc/meminfo",encoding="utf-8") as f:
            rows=dict(line.split(":",1) for line in f if ":" in line)
        return round(int(rows["MemAvailable"].strip().split()[0])/1048576,2)
    except Exception:return None

def prompt_model(model,prompt,limit=160):
    body={"model":model,"prompt":prompt,"stream":False,"think":False,
          "keep_alive":"0","options":{"num_ctx":768,"num_predict":limit,
          "num_thread":2,"num_gpu":0,"temperature":0}}
    req=urllib.request.Request(API,data=json.dumps(body).encode(),method="POST",
                               headers={"Content-Type":"application/json"})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req,timeout=210) as response:
        data=json.load(response)
    if not data.get("done"):raise ValueError("Model response incomplete")
    return data.get("response","")

def extract_function(answer,name):
    lines=answer.replace("\r","").splitlines()
    for i,line in enumerate(lines):
        if re.match(r"^def\s+"+re.escape(name)+r"\s*\(",line.strip()):
            first=line.strip()
            if first.split(":",1)[1].strip():return first+"\n"
            rest=[]
            for l in lines[i+1:]:
                if l.startswith(("    ","\t")):rest.append(l)
                elif rest:break
            if rest:return "\n".join([first,*rest])+"\n"
    raise ValueError("Writer did not return required function")

def verify(code,which):
    cfg=CASES[which]
    syntax=ast.parse(code)
    if len(syntax.body)!=1 or type(syntax.body[0]) is not ast.FunctionDef:
        raise ValueError("Unexpected function structure")
    fn=syntax.body[0]
    if (fn.name!=cfg["name"] or [x.arg for x in fn.args.args]!=list(cfg["params"])
        or fn.decorator_list or len(fn.body)!=1 or type(fn.body[0]) is not ast.Return):
        raise ValueError("Invalid signature or body")
    for n in ast.walk(syntax):
        if not isinstance(n,ALLOWED):raise ValueError("Unsafe code construct")
        if isinstance(n,ast.Name) and n.id not in cfg["params"]:
            raise ValueError("Unsafe variable")
        if isinstance(n,ast.Constant) and (type(n.value) is not int or abs(n.value)>100):
            raise ValueError("Unsafe literal")
    env={"__builtins__":{}}
    exec(compile(syntax,"<checked>","exec"),env)
    f=env[cfg["name"]]
    for args,expected in cfg["tests"]:
        if f(*args)!=expected:raise ValueError("Incorrect arithmetic")
    return 4

def publishable_file(n):
    if n not in NAMES and n!="verification-manifest.json":raise ValueError("Unlisted file")
    ROOT.mkdir(parents=True,exist_ok=True)
    p=ROOT/n
    if p.is_symlink() or ROOT.is_symlink() or p.resolve().parent!=ROOT.resolve():
        raise ValueError("Unsafe path")
    return p

def integration():
    env={k:v for k,v in os.environ.items() if k in ("PATH","HOME","LANG","TMPDIR")}
    tests=subprocess.run([sys.executable,"-S","test_app.py"],cwd=ROOT,
          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=16,
          text=True,env=env)
    if tests.returncode!=0:raise ValueError("Integration test failed: "+tests.stdout[-260:])
    smoke=subprocess.run([sys.executable,"-S","main.py","3","150","10"],cwd=ROOT,
          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15,
          text=True,env=env)
    if smoke.returncode!=0 or smoke.stdout.strip()!="405":
        raise ValueError("End-to-end command returned invalid calculation")
    return {"passed":10,"total":10,"smoke_output":smoke.stdout.strip()}

def check_manifest(m):
    if m.get("status")!="two_models_reviewed":raise ValueError("Reviewer not approved")
    if m.get("reviewer",{}).get("verdict")!="REVIEW_OK":raise ValueError("No model approval")
    if m.get("tests",{}).get("passed")!=10:raise ValueError("Insufficient integration evidence")
    if set(m.get("hashes",{}))!=set(NAMES):raise ValueError("Unexpected file manifest")
    for n in NAMES:
        digest=hashlib.sha256(publishable_file(n).read_bytes()).hexdigest()
        if m["hashes"][n]!=digest:raise ValueError("Model file was modified after tests")
    for name in ("pricing","discount"):
        verify(publishable_file(name+".py").read_text(encoding="utf-8"),name)
    integration()
    return True

def run_pilot():
    if os.getenv("NEUROFACTORY_PUBLIC_FREE_RUN_CONFIRMED")!="yes":
        raise ValueError("Explicit zero-spend quota authorization missing")
    if os.getenv("GITHUB_REPOSITORY")!="DSLitvinov1/my_first_repo":
        raise ValueError("Wrong repository identity")
    report={"status":"started","mode":"ephemeral_cloud","models":[],"paid_services_used":False,
            "production_projects_modified":False,
            "started_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}
    begin=time.monotonic()
    for source in ("main.py","test_app.py"):
        publishable_file(source).write_text((APP_REF/source).read_text(encoding="utf-8"),encoding="utf-8")
    publishable_file("README.md").write_text(
        "# Независимое облачное испытание Qwen\\n\\n"
        "Функции pricing.py и discount.py предложены моделью Qwen2.5-Coder 1.5B.\\n"
        "Файлы main.py и test_app.py — заранее утверждённые шаблоны проверки.\\n"
        "Второй агент Qwen3 1.7B оценивает результат независимо.\\n"
        "Публикация разрешена только после всех тестов и положительного заключения.\\n"
        "Учебная среда, не коммерческий и не пользовательский проект.\\n",encoding="utf-8")
    for part in ("pricing","discount"):
        cfg=CASES[part]
        prompt=("Return only the complete corrected Python function, no markdown or explanation. "
                +cfg["tip"]+"\nBroken:\n"+cfg["broken"])
        answer=prompt_model(MODEL_WRITER,prompt)
        proposed=extract_function(answer,cfg["name"])
        verify(proposed,part)
        publishable_file(part+".py").write_text(proposed,encoding="utf-8")
        report["models"].append({"name":MODEL_WRITER,"module":part,
                                  "validated_cases":4,"free_ram_gb":get_memory_gb()})
    report["tests"]=integration()
    reviewer_prompt=("Independent reviewer: examine these two functions. Should line_total multiply "
                     "quantity by unit_price and discounted_total apply subtotal * (100 - percent) // 100 "
                     "correctly? Reply REVIEW_OK if correct or REVIEW_BAD otherwise.\n"+
                     publishable_file("pricing.py").read_text(encoding="utf-8")+"\n"+
                     publishable_file("discount.py").read_text(encoding="utf-8"))
    verdict_raw=prompt_model(MODEL_REVIEWER,reviewer_prompt,60).upper()
    verdict="REVIEW_OK" if re.search(r"\bREVIEW_OK\b",verdict_raw) else (
            "REVIEW_BAD" if re.search(r"\bREVIEW_BAD\b",verdict_raw) else "UNCLEAR")
    report["reviewer"]={"model":MODEL_REVIEWER,"verdict":verdict}
    if verdict!="REVIEW_OK":raise ValueError("Second independent model did not approve")
    report["status"]="two_models_reviewed"
    report["hashes"]={n:hashlib.sha256(publishable_file(n).read_bytes()).hexdigest() for n in NAMES}
    report["elapsed_seconds"]=round(time.monotonic()-begin,1)
    if not check_manifest(report):raise ValueError("Final integrity proof failed")
    publishable_file("verification-manifest.json").write_text(
         json.dumps(report,ensure_ascii=True,indent=2),encoding="utf-8")
    print(json.dumps({"status":report["status"],"tests":10,"modules":2,
                      "reviewer":verdict,"duration_s":report["elapsed_seconds"]},ensure_ascii=True))
    return report

if __name__=="__main__":
    try:run_pilot()
    except Exception as exc:
        print("Cloud sandbox stopped safely:",type(exc).__name__,str(exc)[:240])
        sys.exit(1)
