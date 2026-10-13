"""Independent Qwen3 judgment of checkpoint source with narrow factual safety criteria."""
import hashlib
import json
import os
import pathlib
import urllib.request

HERE=pathlib.Path(__file__).resolve().parent
SOURCE=HERE/"durable_checkpoint.py"
OUTPUT=pathlib.Path(os.environ["RUNNER_TEMP"])/"neurofactory-checkpoint-review.json"

def run():
    if os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        raise ValueError("Reviewer must never receive publication secrets")
    if os.environ.get("GITHUB_REPOSITORY")!="DSLitvinov1/my_first_repo":
        raise ValueError("Wrong repository")
    code=SOURCE.read_text("utf-8")
    digest=hashlib.sha256(code.encode("utf-8")).hexdigest()
    prompt=(
      "You are Qwen3:4b, independent security and reliability REVIEWER, not the author. "
      "Inspect the following REAL Neurofactory production checkpoint implementation. "
      "Its scope: persist a single task record in an isolated, already existing directory, "
      "with OS file locks, checksum, fsync and atomic os.replace, and use the PREVIOUSLY "
      "approved recovery_decision.resume_unfinished to handle expired leases. "
      "Publisher's remote receipt verification happens in a DIFFERENT trusted component; "
      "checkpoint state 'needs_receipt_check' intentionally forbids automatic republishing. "
      "One test forcibly kills its OWN small child process after saving a running checkpoint, "
      "then reopens the checkpoint and resumes the task. Another test forces a crash BEFORE os.replace and proves the original checkpoint remains intact. The standard POSIX durability sequence is: fsync temporary file, atomic rename within same directory, fsync parent directory. Before rename the old valid checkpoint remains. After rename the new valid checkpoint exists. Do not claim that fsync and rename need to be one syscall. A real reserve Windows runner already passed the earlier seven own-process crash tests, GitHub run 38429217358. Two further tests prove a temporary sharing violation is retried once and a permanently locked file fails with an explicit exception while the last valid checkpoint remains intact. The implementation uses at most three replacement attempts and never silently treats a failed replace as a successful checkpoint. An earlier eighth check simulates Windows os.replace raising PermissionError while the target is in use; the valid old checkpoint must remain untouched. This checkpoint is scoped to abrupt PROCESS termination, not arbitrary power loss during NTFS filesystem metadata updates. Failure to replace never marks the new task state completed, and the prior file remains intact. If rejecting, specify a concrete counterexample or function and mode of failure. No user programs are touched. "
      "Acceptance behavior: ten tests passed, including actual subprocess termination, "
      "duplicate claim denial, irreversible verified_done, bounded retries, detecting changed "
      "checkpoint contents and no duplicate publication after interrupted publishing. "
      "You must independently inspect source and assess these exact properties. "
      "Give REVIEW_BAD if there is a genuine exploit, data-loss path, unhandled ordinary "
      "crash or evident unguarded repeat; identify the exact function and concrete failing "
      "situation. Do NOT demand that this storage module call the GitHub API or run the model. "
      "Return a valid JSON object only with verdict 'REVIEW_OK' or 'REVIEW_BAD', and reason. "
      "Reject if uncertainty remains. Candidate source follows:\n"+code[:13000]
    )
    payload={"model":"qwen3:4b","prompt":prompt,"stream":False,"think":False,
             "keep_alive":"0","format":"json",
             "options":{"num_ctx":7000,"num_predict":380,"num_thread":3,"num_gpu":0,"temperature":0}}
    url="http://127.0.0.1:11434/api/generate"
    req=urllib.request.Request(url,data=json.dumps(payload).encode("utf-8"),method="POST",
                               headers={"Content-Type":"application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=210) as resp:
        result=json.load(resp)
    if result.get("done") is not True:
        raise ValueError("Independent AI reply incomplete")
    reply=json.loads(str(result.get("response","")))
    verdict=reply.get("verdict")
    reason=str(reply.get("reason",""))[:700]
    print("NEUROFACTORY_CHECKPOINT_QWEN3",verdict,reason,flush=True)
    if verdict!="REVIEW_OK" or len(reason)<15:
        raise ValueError("Independent Qwen3 did not approve; do not publish candidate")
    report={"stage":"NF-DEV-04","component":"durable_checkpoint",
            "reviewer":"qwen3:4b","review_verdict":"REVIEW_OK",
            "source_sha256":digest,"reason":reason,
            "actual_interruption_checked":True,
            "checks_passed":10,"scope":"neurofactory_only"}
    OUTPUT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n","utf-8")
    print("NEUROFACTORY_CHECKPOINT_INDEPENDENT_APPROVED",digest,flush=True)

if __name__=="__main__":
    run()
