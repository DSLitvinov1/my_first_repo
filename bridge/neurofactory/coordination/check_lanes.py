"""Fail-closed ownership gate for parallel Neurofactory chats.

Reads only the coordination map. Never dispatches models, accesses network,
changes other branches, or enables ChatGPT delivery.
"""
import argparse
import json
from pathlib import Path
import sys

POLICY = Path(__file__).with_name("lanes.json")
ALLOWED_GLOBAL = "bridge/neurofactory/"
WORKFLOW_GLOBAL = ".github/workflows/neurofactory-"


class OwnershipError(ValueError):
    pass


def load_policy(path=POLICY):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != 1 or data.get("project") != "НЕЙРОЗАВОД":
        raise OwnershipError("Invalid project policy")
    gates = data.get("gates", {})
    expected = {
        "chatgpt_delivery": "paused",
        "paid_api": "forbidden",
        "autopublish_without_independent_Qwen3": "forbidden",
        "repeat_finished_jobs": "forbidden",
        "production_branch_direct_writes": "forbidden",
        "windows_bridge_restart": "forbidden",
    }
    if any(gates.get(k) != v for k, v in expected.items()):
        raise OwnershipError("One or more user safety gates were relaxed")
    lanes = data.get("chat_lanes")
    if not isinstance(lanes, list) or len(lanes) != 5:
        raise OwnershipError("Expected five isolated ownership lanes")
    if len({row["id"] for row in lanes}) != len(lanes):
        raise OwnershipError("Duplicate owner lane")
    if len({row["branch"] for row in lanes}) != len(lanes):
        raise OwnershipError("Two chats own one working branch")
    for row in lanes:
        if not row.get("include") or row["branch"] == data.get("reference_branch"):
            raise OwnershipError("Shared production branch or missing scope")
    return data


def matches(rule, path):
    return path == rule or path.startswith(rule) if rule.endswith(("/", "-")) else path == rule


def owners_for(path, policy):
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        raise OwnershipError("Unsafe or absolute file path")
    if any(fragment in ("..", ".", "") for fragment in path.split("/")):
        raise OwnershipError("Traversal or noncanonical path")
    if not (path.startswith(ALLOWED_GLOBAL) or path.startswith(WORKFLOW_GLOBAL)):
        raise OwnershipError("Other project or unapproved GitHub configuration")
    if path.startswith("bridge/neurofactory/development/chat_agent/"):
        raise OwnershipError("Paused ChatGPT delivery is strictly off limits")
    return [lane["id"] for lane in policy["chat_lanes"]
            if any(matches(rule, path) for rule in lane["include"])]


def check_change_set(lane_id, paths, policy):
    if lane_id not in {lane["id"] for lane in policy["chat_lanes"]}:
        raise OwnershipError("Unrecognized chat owner")
    if not isinstance(paths, list) or not paths:
        raise OwnershipError("No reviewed files")
    for path in paths:
        owners = owners_for(path, policy)
        if owners != [lane_id]:
            raise OwnershipError(f"Ownership violation for {path}: {owners}; expected {lane_id}")
    return {"ok": True, "lane": lane_id, "files": len(paths)}


def check_overlaps(policy):
    """Check ownership uniqueness on enumerated files and representative prefixes."""
    samples = set()
    for lane in policy["chat_lanes"]:
        for rule in lane["include"]:
            samples.add(rule + ("sample.py" if rule.endswith(("/", "-")) else ""))
    collisions = []
    for path in samples:
        owners = owners_for(path, policy)
        if len(owners) != 1:
            collisions.append({"path": path, "owners": owners})
    if collisions:
        raise OwnershipError("Ambiguous/missing owner: " + json.dumps(collisions))
    return len(samples)


def main():
    arg = argparse.ArgumentParser()
    arg.add_argument("--lane", choices=["core", "handoff", "review", "providers", "coordinator"])
    arg.add_argument("--changes-json")
    arg.add_argument("--check-policy", action="store_true")
    args = arg.parse_args()
    policy = load_policy()
    count = check_overlaps(policy)
    if args.check_policy:
        print(f"NEUROFACTORY_LANE_POLICY_OK rules={count}")
    if args.lane:
        if not args.changes_json:
            raise OwnershipError("Change list required for lane validation")
        source = Path(args.changes_json)
        changed = json.loads(source.read_text(encoding="utf-8"))
        print(json.dumps(check_change_set(args.lane, changed, policy)))


if __name__ == "__main__":
    try:
        main()
    except OwnershipError as error:
        print("NEUROFACTORY_LANE_DENIED:", str(error), file=sys.stderr)
        sys.exit(1)
