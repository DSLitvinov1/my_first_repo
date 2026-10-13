"""Restricted, independent local Qwen agents; no credentials or side effects outside scratch."""
import ast,hashlib,json,os,pathlib,re,sys,urllib.request
REPO="DSLitvinov1/my_first_repo"
TARGET="bridge/neurofactory/development/stage4_receipt_rules.py"
def check(src):
    tree=ast.parse(src)
    if len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef):raise ValueError("One function required")
    fn=tree.body[0]
    if fn.name!="receipt_matches" or [a.arg for a in fn.args.args]!=["record","repo","path","sha"]:raise ValueError("Wrong contract")
    if not 100<=len(src)<=1800:raise ValueError("Code size")
    banned=(ast.Import,ast.ImportFrom,ast.ClassDef,ast.Global,ast.Nonlocal,ast.With,ast.AsyncWith,ast.Try,ast.Raise,ast.While,ast.For,ast.AsyncFor,ast.Lambda,ast.Await,ast.Delete)
    for n in ast.walk(tree):
        if isinstance(n,banned):raise ValueError("Unsafe source")
        if isinstance(n,ast.Name) and n.id.startswith("__"):raise ValueError("Dunder denied")
        if isinstance(n,ast.Attribute) and n.attr!="get":raise ValueError("Method denied")
        if isinstance(n,ast.Call) and not ((isinstance(n.func,ast.Name) and n.func.id in ("isinstance","len","all")) or (isinstance(n.func,ast.Attribute) and n.func.attr=="get")):raise ValueError("Call denied")
    env={"__builtins__":{"isinstance":isinstance,"len":len,"all":all,"dict":dict,"str":str}}
    exec(compile(tree,"<isolated-tested-receipt>","exec"),env)
    func=env["receipt_matches"]
    sha="b"*40; obj={"repo":REPO,"path":TARGET,"sha":sha}
    cases=[(obj,REPO,TARGET,sha,True),(obj,REPO,TARGET,"c"*40,False),
      ({**obj,"sha":"c"*40},REPO,TARGET,sha,False),({**obj,"repo":"bad/other"},REPO,TARGET,sha,False),
      ({**obj,"path":"../bad"},REPO,TARGET,sha,False),(obj,"bad/other",TARGET,sha,False),
      (obj,REPO,"../bad",sha,False),({**obj,"sha":"x"*40},REPO,TARGET,"x"*40,False),
      ({**obj,"sha":"B"*40},REPO,TARGET,"B"*40,False),({**obj,"sha":"b"*39},REPO,TARGET,"b"*39,False),
      (None,REPO,TARGET,sha,False),([],REPO,TARGET,sha,False),({},REPO,TARGET,sha,False),
      (obj,REPO,TARGET,23,False),(obj,REPO,TARGET,"",False)]
    for i,(o,r,p,s,want) in enumerate(cases):
        try:got=func(o,r,p,s)
        except Exception as exc:raise ValueError("Case raised "+str(i)) from exc
        if type(got)!=bool or got!=want:raise ValueError("Failed case "+str(i))
    return hashlib.sha256(src.encode()).hexdigest(),len(cases)
def ask(model,prompt,structured=False):
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):raise ValueError("Agent cannot access token")
    data={"model":model,"prompt":prompt[:8500],"stream":False,"think":False,"keep_alive":"0","options":{"num_ctx":6000,"num_predict":800,"num_thread":3,"num_gpu":0,"temperature":0}}
    if structured:data["format"]="json"
    req=urllib.request.Request("http://127.0.0.1:11434/api/generate",data=json.dumps(data).encode(),method="POST",headers={"Content-Type":"application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=240) as resp:ans=json.load(resp)
    if ans.get("done") is not True:raise ValueError("Incomplete AI response")
    return str(ans.get("response","")).strip()
def main():
    if len(sys.argv)!=4:raise ValueError("Need mode, source, report")
    mode,src_path,review_path=sys.argv[1:];source=pathlib.Path(src_path);report=pathlib.Path(review_path)
    if source.is_symlink() or report.is_symlink() or not source.parent.is_dir():raise ValueError("Unsafe scratch")
    if mode=="owned-crash":
        print("NF4_OWN_WORKER_TERMINATED",flush=True);os._exit(73)
    if mode=="writer":
        task=("FIRST independent AI developer. Write real Neurofactory security validator as ONLY Python source, no markdown. "
          "Exactly def receipt_matches(record, repo, path, sha): returning bool. "
          "Accept only if record is dict with keys repo,path,sha matching inputs, "
          "repo strictly 'DSLitvinov1/my_first_repo', path strictly "
          "'bridge/neurofactory/development/stage4_receipt_rules.py', "
          "sha exactly 40 lowercase hex digits a-f0-9. Reject wrong types or SHA format. "
          "No imports, IO, syscalls, nested functions or shell. Use isinstance,len,all and dict.get.")
        last=""
        for attempt in range(3):
            response=ask("qwen2.5-coder:7b",task+last)
            match=re.search(r"(?m)^def receipt_matches\(",response)
            if match:
                candidate=response[match.start():].split(chr(96)*3)[0].strip()+"\n"
                try:
                    digest,total=check(candidate)
                    source.write_text(candidate,encoding="utf-8")
                    print("NF4_WRITER_REAL_ACCEPTED",attempt+1,total,digest,flush=True)
                    return
                except (ValueError,SyntaxError) as exc:last="\nFix last failed candidate: "+str(exc)[:160]
            else:last="\nPrevious answer missing exact function, give only Python source."
        raise ValueError("No verified AI candidate")
    if mode=="reviewer":
        src=source.read_text("utf-8");digest,total=check(src)
        prompt=("SECOND INDEPENDENT Qwen3:4b security reviewer. The first agent wrote REAL Neurofactory "
          "receipt validation code. Independently verify exact repo, path, 40-character lowercase SHA, "
          "malicious input rejection, no side effects, and 15 checked cases. "
          "Respond JSON only with verdict REVIEW_OK or REVIEW_BAD and reason under 60 words. "
          "For REVIEW_BAD name concrete failing input. Source:\n"+src)
        result=json.loads(ask("qwen3:4b",prompt,True));verdict=result.get("verdict");reason=str(result.get("reason",""))[:480]
        print("NF4_REVIEWER_REAL_VERDICT",verdict,reason,flush=True)
        if verdict!="REVIEW_OK" or len(reason)<12:raise ValueError("Independent rejection")
        report.write_text(json.dumps({"stage":"NF-DEV-04","writer":"qwen2.5-coder:7b","reviewer":"qwen3:4b","verdict":verdict,"source_sha256":digest,"test_count":total,"reason":reason},sort_keys=True)+"\n",encoding="utf-8")
        return
    raise ValueError("Denied worker role")
if __name__=="__main__":main()
