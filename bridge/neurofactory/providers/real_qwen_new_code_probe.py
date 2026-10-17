"""Fresh free Qwen CPU-produced Python function; pure AST tests; NO project writes."""
import ast,hashlib,json,os,shutil,sys
from pathlib import Path
MODEL="Qwen/Qwen2.5-0.5B-Instruct"
PROMPT=("Write exactly one Python function named add_two(a, b). "
        "It must return the sum of two input numbers. "
        "Output only Python function definition and body. No examples or prose.")
CASES=(((0,0),0),((2,3),5),((-4,7),3),((10,-8),2),
       ((-10,-20),-30),((1000000,3),1000003),((1.5,2.5),4.0),((99,1),100))
ALLOWED=(ast.Module,ast.FunctionDef,ast.arguments,ast.arg,ast.Return,
         ast.If,ast.Compare,ast.BoolOp,ast.BinOp,ast.UnaryOp,ast.Name,
         ast.Load,ast.Constant,ast.Mod,ast.Eq,ast.NotEq,ast.And,ast.Or,
         ast.Not,ast.UAdd,ast.USub,ast.Add,ast.Pass)
def mem():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):return int(line.split()[1])*1024
    raise RuntimeError("RAM_UNKNOWN")
def verify(answer):
    fence=chr(96)*3
    if fence in answer:
        snippet=answer.split(fence)[1].removeprefix("python").strip()
    else:
        start=answer.find("def add_two(")
        if start<0:raise ValueError("missing newly generated function")
        snippet=answer[start:].strip()
    # Keep the first model-generated function and its indented body, never
    # replace an invalid reply with any pre-written solution.
    lines=snippet.splitlines()
    selected=[lines[0]]
    for line in lines[1:]:
        if not line.strip():continue
        if not line[0].isspace():break
        selected.append(line)
    raw="\n".join(selected)
    if len(raw.encode())>2000:raise ValueError("too long")
    tree=ast.parse(raw)
    if len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef):
        raise ValueError("not exactly one function")
    fn=tree.body[0]
    if (fn.name!="add_two" or fn.decorator_list or len(fn.args.args)!=2
        or [a.arg for a in fn.args.args]!=["a","b"] or fn.args.defaults or fn.args.kwonlyargs
        or fn.args.posonlyargs or fn.args.vararg or fn.args.kwarg):
        raise ValueError("wrong function")
    fn.returns=None
    for a in fn.args.args:a.annotation=None
    for node in ast.walk(tree):
        if not isinstance(node,ALLOWED):raise ValueError("unsafe syntax "+type(node).__name__)
        if isinstance(node,ast.Name) and node.id not in ("a","b"):raise ValueError("external name")
    scope={}
    exec(compile(ast.fix_missing_locations(tree),"<pure_candidate>","exec"),
         {"__builtins__":{}},scope)
    for arguments,expected in CASES:
        actual=scope["add_two"](*arguments)
        if type(actual) not in (int,float) or actual!=expected:
            raise ValueError("candidate failed at "+str(arguments))
    return raw
def main():
    if (sys.platform!="linux" or os.getenv("NF_REAL_QWEN_NEW_CODE_TEST_ONLY")!="1"
        or any(os.getenv(x) for x in ("OPENAI_API_KEY","ANTHROPIC_API_KEY","HF_TOKEN"))):
        raise RuntimeError("test gating denied")
    ram=mem();disk=shutil.disk_usage("/tmp").free
    print(json.dumps({"stage":"resource check","available_ram_mib":ram//1048576,
                      "disk_free_mib":disk//1048576}),flush=True)
    if ram<5*1024**3 or disk<4*1024**3:
        print("BLOCKED_RESOURCE_NO_INFERENCE",flush=True);return
    import torch
    from transformers import AutoModelForCausalLM,AutoTokenizer
    from huggingface_hub import snapshot_download
    torch.set_num_threads(2)
    location=snapshot_download(MODEL,revision="main",
        cache_dir="/tmp/nf-qwen-coding-test",allow_patterns=[
             "*.safetensors","*.json","tokenizer*","vocab*","merges.txt"])
    revision=Path(location).name
    if len(revision)!=40:raise RuntimeError("model SHA not verified")
    t=AutoTokenizer.from_pretrained(location,trust_remote_code=False,local_files_only=True)
    m=AutoModelForCausalLM.from_pretrained(location,torch_dtype=torch.float32,
            trust_remote_code=False,local_files_only=True)
    m.eval()
    inputs=t.apply_chat_template([
        {"role":"system","content":"You output only correct, simple Python source code."},
        {"role":"user","content":PROMPT}],add_generation_prompt=True,return_tensors="pt")
    with torch.inference_mode():
        generated=m.generate(inputs,max_new_tokens=150,do_sample=False,
                             pad_token_id=t.eos_token_id)[0,inputs.shape[1]:]
    answer=t.decode(generated,skip_special_tokens=True)
    print(json.dumps({"stage":"REAL_QWEN_NEW_CODE_GENERATION",
       "model":MODEL,"model_revision":revision,
       "new_inference":True,"generated_tokens":len(generated),
       "raw_response_sha256":hashlib.sha256(answer.encode()).hexdigest(),
       "mock":False,"project_files_written":False,"production_approved":False}),flush=True)
    try:source=verify(answer)
    except (SyntaxError,ValueError,TypeError) as e:
        print(json.dumps({"stage":"CODE_REJECTED_FAIL_CLOSED",
             "reason":str(e)[:120],"auto_retry":False,
             "project_files_written":False}),flush=True)
        return
    print(json.dumps({"stage":"REAL_QWEN_PROGRAM_PASSED_PURE_TESTS",
        "code_sha256":hashlib.sha256(source.encode()).hexdigest(),
        "test_count":len(CASES),"generated_code":source,
        "human_review_approved":False,"applied":False,"published":False,
        "project_files_written":False}),flush=True)
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(json.dumps({"stage":"NEW_QWEN_CODE_NOT_VERIFIED",
              "error_type":type(e).__name__,
              "project_files_written":False}),flush=True)
        sys.exit(2)
