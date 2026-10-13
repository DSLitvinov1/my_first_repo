"""Independent focused model audit of exact Stage5 queue and real OS lock.

This check NEVER merges or publishes source. It fails closed on negative or
unparseable verdict and saves review evidence for later inspection.
"""
import hashlib
import json
import os
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent
MODULE = ROOT / "stage5_development_queue.py"
LOCK = ROOT / "durable_checkpoint.py"
TESTS = ROOT / "test_stage5_development_queue.py"
OUT = ROOT / "stage5-restore-independent-concurrency-verdict.json"

SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["REVIEW_OK", "REVIEW_BAD"]},
        "reason": {"type": "string"},
        "counterexample": {"type": "string"},
    },
    "required": ["verdict", "reason", "counterexample"],
    "additionalProperties": False,
}

def main():
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        raise RuntimeError("Model reviewer must not receive publish credentials")
    if os.getenv("GITHUB_REPOSITORY") != "DSLitvinov1/my_first_repo":
        raise RuntimeError("Wrong review repository")
    source = MODULE.read_text("utf-8")
    lock = LOCK.read_text("utf-8")
    tests = TESTS.read_text("utf-8")
    sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
    prompt = (
        "You are an INDEPENDENT Qwen3:4b reviewer, not the code author. "
        "Evaluate the EXACT full Stage5 queue Python source supplied, plus "
        "the full durable_checkpoint implementation of its process-wide lock, "
        "plus tests of TWO SEPARATE Python processes restoring the SAME "
        "directory, a competing external initializer, manifest-last publish, "
        "and abrupt OS process death after writing one role file. "
        "Security requirements: only ONE restoration may become committed; "
        "a losing runner must not overwrite checkpoints; no foreign file "
        "may change; no incomplete restore may be accepted on restart; "
        "completed tasks must not replay. Distinguish intentional rejection "
        "of a conflicting restore (fail-closed behavior) from a concrete data "
        "corruption, and do not assume two queue workers can bypass the "
        "shown actual OS lock. Look for real bypasses such as partial file "
        "adoption, symlink races, exception cleanup overwrites, or forged "
        "snapshot proof. Do not approve because unit tests passed alone; "
        "analyze source behavior independently. If any real bypass exists, "
        "return REVIEW_BAD and a reproducible counterexample with concrete "
        "entry point and exact interleaving. If no bypass exists within "
        "the supplied code, return REVIEW_OK, name 2-3 actual safeguards, "
        "and state untested limitations in reason. Never invent imaginary "
        "functions or omit limitations. JSON only with verdict, reason, "
        "counterexample; use an empty counterexample for REVIEW_OK. "
        "QUEUE SOURCE (complete):\n" + source +
        "\nDEPENDENCY: LOCK, LOAD, SAVE IMPLEMENTATION:\n" + lock +
        "\nREAL CONCURRENCY AND CRASH TESTS:\n" + tests
    )
    payload = {
        "model": "qwen3:4b", "prompt": prompt, "stream": False,
        "think": False, "keep_alive": "0", "format": SCHEMA,
        "options": {"temperature": 0, "num_ctx": 16000,
                    "num_predict": 560, "num_thread": 4, "num_gpu": 0},
    }
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type":"application/json"}, method="POST")
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=550) as conn:
        answer = json.load(conn)
    if answer.get("done") is not True:
        raise RuntimeError("Incomplete model verdict")
    decision = json.loads(str(answer.get("response", "")))
    if set(decision) != set(SCHEMA["required"]) or decision["verdict"] not in ("REVIEW_OK","REVIEW_BAD"):
        raise RuntimeError("Reviewer did not produce a valid independent verdict")
    if not isinstance(decision["reason"], str) or len(decision["reason"].strip()) < 60:
        raise RuntimeError("Independent explanation insufficient")
    report = {
        "stage": "NF-DEV-05", "source_sha256": sha,
        "reviewer": "qwen3:4b", "verdict": decision["verdict"],
        "reason": decision["reason"][:2000],
        "counterexample": decision["counterexample"][:2000],
        "reviewer_has_git_write_permission": False,
        "tests_not_equivalent_to_model_approval": True,
    }
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")
    print("NF5_INDEPENDENT_EXACT_CONCURRENCY_VERDICT", report["verdict"],
          "sha256", sha, "reason", report["reason"][:900], flush=True)
    if decision["verdict"] != "REVIEW_OK":
        raise RuntimeError("Independent reviewer has not approved restored queue")

if __name__ == "__main__":
    main()
