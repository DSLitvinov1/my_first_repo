"""Two independent local models propose and review real crash-recovery decisions."""
import ast
import hashlib
import json
import os
import pathlib
import re
import sys

from real_self_improve import ask, WRITER, REVIEWER
from stage3_guard import read
from control_plane import validate

OUT = pathlib.Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "nf-recovery-improvement"
OUT.mkdir(parents=True, exist_ok=True)
FILENAME = "recovery_decision.py"
REVIEW_FILE = "recovery-verification.json"
BANNED = (
    ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal, ast.ClassDef,
    ast.With, ast.AsyncWith, ast.Try, ast.Raise, ast.For, ast.AsyncFor,
    ast.While, ast.Delete, ast.Lambda, ast.Yield, ast.YieldFrom, ast.Await,
    ast.FunctionDef if False else ast.AsyncFunctionDef
)

def check_source(source):
    if not isinstance(source, str) or not 200 <= len(source) <= 2400:
        raise ValueError("Invalid production recovery candidate size")
    tree = ast.parse(source)
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError("Exactly one pure recovery function required")
    fn = tree.body[0]
    if fn.name != "resume_unfinished" or [arg.arg for arg in fn.args.args] != ["task", "now", "max_attempts"]:
        raise ValueError("Wrong production recovery function signature")
    if fn.decorator_list:
        raise ValueError("No decorators allowed")
    for node in ast.walk(tree):
        if isinstance(node, BANNED) or (isinstance(node, ast.FunctionDef) and node is not fn):
            raise ValueError("Forbidden recovery function operation")
        if isinstance(node, ast.Attribute) and node.attr not in {"get", "copy"}:
            raise ValueError("Unexpected attribute access in recovery decision")
        if isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name) and target.id == "isinstance":
                continue
            if isinstance(target, ast.Attribute) and target.attr in {"get", "copy"}:
                continue
            raise ValueError("Unapproved recovery function call")
        if isinstance(node, ast.Name) and node.id.startswith("__"):
            raise ValueError("Private names prohibited")
    return tree

def acceptance(source):
    tree = check_source(source)
    ns = {"__builtins__": {"isinstance": isinstance, "dict": dict, "int": int, "bool": bool}}
    exec(compile(tree, "<isolated-recovery-decision>", "exec"), ns)
    fn = ns["resume_unfinished"]
    cases = [
        ({"id":"a","state":"verified_done","attempts":1,"lease_until":0}, 100, 3, "verified_done"),
        ({"id":"b","state":"queued","attempts":0,"lease_until":None}, 100, 3, "queued"),
        ({"id":"c","state":"running","attempts":1,"lease_until":110}, 100, 3, "running"),
        ({"id":"d","state":"running","attempts":1,"lease_until":99}, 100, 3, "queued"),
        ({"id":"e","state":"running","attempts":1,"lease_until":100}, 100, 3, "queued"),
        ({"id":"f","state":"running","attempts":3,"lease_until":99}, 100, 3, "retry_exhausted"),
        ({"id":"g","state":"publishing","attempts":1,"lease_until":99}, 100, 3, "needs_receipt_check"),
        ({"id":"h","state":"needs_receipt_check","attempts":1,"lease_until":99}, 100, 3, "needs_receipt_check"),
        ({"id":"i","state":"failed","attempts":3,"lease_until":99}, 100, 3, "failed"),
        ({"id":"j","state":"running","attempts":1,"lease_until":None}, 100, 3, "needs_manual_review"),
        ({"id":"k","state":"running","attempts":-1,"lease_until":80}, 100, 3, "needs_manual_review"),
    ]
    for item, now, limit, expected in cases:
        original = dict(item)
        answer = fn(item, now, limit)
        if not isinstance(answer, dict) or answer.get("state") != expected:
            raise ValueError("Recovery decision violates "+item["id"]+": expected "+expected)
        if item != original or answer.get("id") != item["id"]:
            raise ValueError("Recovery mutated task or lost stable identity")
        if answer is item:
            raise ValueError("Recovery must return a new copy")
        if fn(answer, now, limit) != answer:
            raise ValueError("Recovery decision not idempotent")
        if expected in ("queued","retry_exhausted") and answer.get("lease_until") is not None:
            raise ValueError("Stale lease retained after recovery")
    return len(cases)

def generate():
    if os.environ.get("GITHUB_REPOSITORY") != "DSLitvinov1/my_first_repo":
        raise ValueError("Wrong repository")
    if os.environ.get("NF_FREE_PUBLIC_CONFIRMED") != "yes" or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        raise ValueError("Free model-only execution required, no publisher credentials")
    plan=validate(read())
    if next(x for x in plan["milestones"] if x["id"]=="NF-DEV-04")["state"]!="active":
        raise ValueError("Recovery stage must be explicitly active")
    guide=(
        "Write ONE new real production Neurofactory pure Python function "
        "def resume_unfinished(task, now, max_attempts): with NO imports or markdown. "
        "It decides how to recover previously persisted task records after interruption. "
        "task is a dictionary with id, state, attempts, lease_until. "
        "ALWAYS make and return a fresh copy using task.copy(); never mutate the input. "
        "If state verified_done, failed, queued, retry_exhausted, needs_receipt_check: return unchanged copy. "
        "If state publishing: change state to needs_receipt_check, NEVER queue publication again until remote receipt reconciliation. "
        "If state running and lease_until is an integer greater than now: return unchanged copy. "
        "If state running and lease_until is missing/noninteger: set needs_manual_review. "
        "If state running, expired lease, attempts is negative or not an integer: set needs_manual_review. "
        "If running lease expired with attempts >= max_attempts: set retry_exhausted and lease_until=None. "
        "If running lease expired with valid attempts < max_attempts: set queued and lease_until=None. "
        "NEVER increment attempts while deciding recovery: attempts increment only when a worker claims the queued task. "
        "Never restart a verified task. Idempotent: applying twice yields identical output. "
        "For valid records, id must remain unchanged. "
        "No IO, subprocesses, other functions, loops, try, imports or external dependencies. "
        "Allowed calls: isinstance(), dict.get(), dict.copy(). "
        "Reference behavior: stale running attempts=1, limit=3 => queued; "
        "running with unexpired lease => running; publishing => needs_receipt_check; "
        "verified_done => verified_done; stale running attempts=3 => retry_exhausted; "
        "missing lease => needs_manual_review. "
        "Output ONLY function source, no explanations."
    )
    code=None
    feedback=""
    seen=set()
    for attempt in range(3):
        try:
            raw=ask(WRITER,guide+feedback)
            m=re.search(r"(?m)^def resume_unfinished\(task, now, max_attempts\):",raw)
            if not m:
                raise ValueError("Missing exact production function")
            candidate=raw[m.start():].split(chr(96)*3,1)[0].strip()+"\n"
            digest=hashlib.sha256(candidate.encode()).hexdigest()
            if digest in seen:
                raise ValueError("Identical failed candidate, refuse replay")
            seen.add(digest)
            n=acceptance(candidate)
            code=candidate
            print("RECOVERY_WRITER_ACCEPTED", n, digest, flush=True)
            break
        except (SyntaxError, ValueError, TypeError) as e:
            print("RECOVERY_WRITER_REJECTED",attempt+1,str(e)[:140],flush=True)
            if "Identical failed" in str(e):
                break
            feedback="\nPrior candidate rejected: "+str(e)[:200]+". Fix only this real recovery defect."
    if code is None:
        raise ValueError("Writer did not produce an accepted real recovery candidate")
    spec=(
        "You are Qwen3, a SEPARATE independent reviewer of a real Neurofactory "
        "crash recovery state-transition function, NOT the writer. "
        "Review the source against the stated real production rules. "
        "Never retry a verified_done state, never automatically republish a publishing "
        "state, preserve id, do not mutate caller's object. Running tasks with "
        "unexpired leases stay running; expired tasks return queued if attempts < limit, "
        "otherwise retry_exhausted; invalid lease/attempt counters need manual review. "
        "All 11 predefined behavior checks passed, including idempotence. "
        "Your verdict MUST be REVIEW_OK or REVIEW_BAD. A rejection MUST include "
        "a concrete input state and specific violated requirement; do not invent failures "
        "for conditions already checked. Return JSON verdict and reason. "
        "Candidate source:\n"+code
    )
    review=json.loads(ask(REVIEWER,spec,True))
    print("RECOVERY_INDEPENDENT_REVIEW",review.get("verdict"),str(review.get("reason",""))[:340],flush=True)
    if review.get("verdict")!="REVIEW_OK":
        raise ValueError("Independent reviewer rejected recovery logic; no publication")
    out={"stage":"NF-DEV-04","writer":WRITER,"reviewer":REVIEWER,
         "review_verdict":"REVIEW_OK","tests_passed":n,"sha256":hashlib.sha256(code.encode()).hexdigest(),
         "reason":str(review.get("reason",""))[:350],"scope":"neurofactory_only"}
    (OUT/FILENAME).write_text(code, encoding="utf-8",newline="\n")
    (OUT/REVIEW_FILE).write_text(json.dumps(out,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("RECOVERY_PROPOSAL_ACCEPTED",out["sha256"],flush=True)

if __name__=="__main__":
    try:
        generate()
    except Exception as exc:
        print("RECOVERY_SAFE_STOP",type(exc).__name__,str(exc)[:250],flush=True)
        sys.exit(1)
