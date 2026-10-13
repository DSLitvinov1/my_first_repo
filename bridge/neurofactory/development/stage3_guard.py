"""Gate real self-development by verified foundation or explicit user-approved chat deferral."""
import copy,json,pathlib,re
from control_plane import validate,outbox
ROOT=pathlib.Path(__file__).resolve().parent
def approved_stage3(plan):
    validate(plan)
    stages={step["id"]:step for step in plan["milestones"]}
    t1=stages["NF-DEV-01"]
    t2=stages["NF-DEV-02"]
    t3=stages["NF-DEV-03"]
    # The user explicitly deferred optional ChatGPT delivery. Stage 03 only
    # needs verified Stage 01, and MUST remain independent of browser sending.
    # This alternative does not verify or silently complete Stage 02.
    if (t1["state"]=="verified" and t2["state"]=="deferred"
        and t3["state"]=="active"
        and plan.get("chat_delivery_paused") is True
        and plan.get("stage3_independent_of_chat") is True
        and not t2.get("evidence")):
        return True
    proof=t2.get("evidence",{})
    # Reconstruct the exact approved stage-two outbox independently from the plan.
    stage2_plan=copy.deepcopy(plan)
    for step in stage2_plan["milestones"]:
        if step["id"]=="NF-DEV-02":step["state"]="active"
        if step["id"]=="NF-DEV-03":step["state"]="pending"
    expected=outbox(stage2_plan)["sequence"]
    return bool(
        t2["state"]=="verified" and t3["state"]=="active"
        and proof.get("live_chat_delivery_verified") is True
        and proof.get("observer")=="visible_chat_turn"
        and isinstance(proof.get("conversation_url"),str)
        and re.fullmatch(r"https://chatgpt\.com/c/[A-Za-z0-9-]+/?",proof["conversation_url"])
        and isinstance(proof.get("delivery_sequence"),str)
        and proof["delivery_sequence"]==expected
        and proof.get("independent_review") is True
        and proof.get("tests_passed") is True)
def read():
    return json.loads((ROOT/"roadmap.json").read_text("utf-8"))
if __name__=="__main__":
    print("STAGE3_READY" if approved_stage3(read()) else "STAGE3_BLOCKED_BY_PLAN_OR_EVIDENCE")
