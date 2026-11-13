"""Manual, non-destructive live Qwen staging smoke.

Uses the real already-running owner-hosted llama.cpp model on loopback.
No third-party account mutations. All prompts contain synthetic public data.
Only prints state, metadata, and safe normalized script.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import tempfile
import time

from work_core import WorkStore
from qwen_planner_one import QwenPlannerOne
from llama_connector_one import LlamaCppQwenOne


class ApprovedBrowser:
    allowed_hosts=frozenset(("example.org",))

    def open(self, *args, **kwargs):
        raise AssertionError("Qwen must never execute directly")


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--key-file",type=Path,required=True)
    args=ap.parse_args()
    model=LlamaCppQwenOne(key_file=args.key_file)
    assert model.available(), "LOCAL_QWEN_HEALTH_NOT_READY"
    print("QWEN_MODEL_HEALTH_OK",flush=True)
    with tempfile.TemporaryDirectory(prefix="nf-qwen-live-") as temp:
        root=Path(temp)
        store=WorkStore(root/"projects",root/"data")
        project=store.create_project("Safe Qwen smoke","empty")["id"]
        planner=QwenPlannerOne(store,ApprovedBrowser(),model_fn=model)
        goal=("Открой публичную главную страницу https://example.org/, "
              "проверь наличие надписи Example Domain и сделай снимок. "
              "Ничего не отправляй и не изменяй.")
        started=time.monotonic()
        response=planner.propose(project,goal)
        print("QWEN_PLAN_ACCEPTED",response["state"],flush=True)
        while time.monotonic()-started<145:
            report=planner.get(project,response["id"])
            if report["state"]!="GENERATING":
                print("QWEN_RESULT_STATE",report["state"],flush=True)
                print("QWEN_ELAPSED_SEC",round(time.monotonic()-started,2),flush=True)
                if report["state"]=="PROPOSED":
                    print("QWEN_SAFE_PLAN_STEPS",report.get("steps"),flush=True)
                    print("QWEN_SAFE_SCRIPT",repr(report.get("script")),flush=True)
                    return
                print("QWEN_ERROR",report.get("error"),flush=True)
                raise SystemExit(3)
            time.sleep(.3)
        print("QWEN_TIMED_OUT_UNKNOWN_NO_AUTO_RETRY",flush=True)
        raise SystemExit(4)


if __name__=="__main__":
    main()
