"""Prevent real self-modification until exact-chat stage 02 is independently verified."""
import copy,json,pathlib,re
from control_plane import validate,outbox
ROOT=pathlib.Path(__file__).resolve().parent
def approved_stage3(plan):
    validate(plan)
    stages={step["id"]:step for step in plan["milestones"]}
    t2=stages["NF-DEV-02"]
    t3=stages["NF-DEV-03"]
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
    print("STAGE3_READY" if approved_stage3(read()) else "STAGE3_BLOCKED_UNTIL_REAL_CHAT_RECEIPT")
