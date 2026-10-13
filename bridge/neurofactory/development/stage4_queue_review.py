"""Second-model read-only safety review of newly integrated stage-4 queue."""
import hashlib
import json
import os
import pathlib
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "stage4_queue.py"
OUTPUT = HERE / "stage4-queue-review-result.json"


def main():
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        raise RuntimeError("Independent reviewer must not have GitHub write credentials")
    if os.getenv("GITHUB_REPOSITORY") != "DSLitvinov1/my_first_repo":
        raise RuntimeError("Wrong review repository")
    source = SOURCE.read_text("utf-8")
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    prompt = (
        "Act as Qwen3 4b, independent safety reviewer of Neurofactory STAGE 4. "
        "This source is a candidate only, not deployed. Inspect it rather than trusting claims. "
        "It calls the already-approved durable_checkpoint module for atomic fsync/replace/OS locks "
        "and uses a global lock for claims. Three strict lanes: qwen2.5-coder writer, "
        "qwen3 reviewer, trusted publisher. ChatGPT auto-send must remain paused. "
        "A role's before_external_effect checkpoint is saved before any external operation. "
        "After interruption at publishing the state goes to needs_receipt_check and no retry "
        "or republication is allowed. A remote_verified Boolean is accepted only from a "
        "trusted separate publisher process; THIS module intentionally performs zero network "
        "operations and cannot claim independently that an arbitrary receipt was checked. "
        "It is also not itself a model executor. Evaluate whether the state machine has genuine "
        "uncaught ordinary exceptions, mixed-role claims, data-loss paths, accidental task replay "
        "or missing proof equality, and identify function and concrete counterexample if rejected. "
        "Report only JSON with verdict REVIEW_OK or REVIEW_BAD and specific reason under 60 words. "
        "Do not guess. Source below:\n" + source[:14500]
    )
    query = {"model": "qwen3:4b", "prompt": prompt, "stream": False,
             "think": False, "format": "json", "keep_alive": "0",
             "options": {"num_ctx": 10000, "num_predict": 800,
                         "num_thread": 3, "num_gpu": 0, "temperature": 0}}
    req = urllib.request.Request("http://127.0.0.1:11434/api/generate",
                                 data=json.dumps(query).encode("utf-8"),
                                 method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=230) as resp:
        result = json.load(resp)
    if result.get("done") is not True:
        raise ValueError("Model result incomplete")
    reply = json.loads(str(result.get("response", "")))
    verdict = reply.get("verdict")
    reason = str(reply.get("reason", ""))
    print("STAGE4_SECOND_AGENT_VERDICT", verdict, reason[:600], flush=True)
    if verdict != "REVIEW_OK" or len(reason) < 12:
        raise ValueError("Independent review not approved")
    OUTPUT.write_text(json.dumps({"stage": "NF-DEV-04", "component": "stage4_queue",
                                  "reviewer": "qwen3:4b", "verdict": verdict,
                                  "source_sha256": digest, "reason": reason,
                                  "checks_required": 10, "scope": "neurofactory_only"},
                                 indent=2) + "\n", "utf-8")


if __name__ == "__main__":
    main()
