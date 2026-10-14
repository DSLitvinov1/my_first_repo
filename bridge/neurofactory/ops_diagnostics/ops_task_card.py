"""Strict offline compatibility for coordinator's optional task_status_card.

The coordinator task input SHA is NOT the OPS diagnostic code SHA, and the
task's self-reported phase is not a trusted runner/queue state. No IO.
"""
import re

from diagnose import SnapshotError

TASK_ID = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
CARD_FIELDS = {
    "schema", "kind", "task_id", "display_phase", "source_sha",
    "source_trust", "actions_allowed"
}
PHASES = {"candidate", "waiting_dependency", "waiting_review"}


def adapt_task_card(card=None):
    """Validate a coordinator-produced card as UNTRUSTED display metadata."""
    absent = {
        "source": "COORDINATOR_TASK_CARD_UNATTESTED",
        "task_id": None,
        "reported_phase": "unknown",
        "display_phase": "UNKNOWN",
        "task_input_sha": None,
        "input_sha_vs_ops_sha": "NOT_COMPARABLE",
        "source_verified": False,
        "actions_allowed": False,
    }
    if card is None:
        return absent
    if type(card) is not dict or set(card) != CARD_FIELDS:
        raise SnapshotError("Invalid coordinator task card fields")
    if (type(card["schema"]) is not int or card["schema"] != 1 or
            card["kind"] != "task_status_card" or
            card["source_trust"] != "not_attested" or
            card["actions_allowed"] is not False):
        raise SnapshotError("Untrusted or authorization-capable coordinator task card")
    task_id, phase, sha = card["task_id"], card["display_phase"], card["source_sha"]
    if task_id is None:
        if phase != "unknown" or sha is not None:
            raise SnapshotError("Unknown task card cannot claim a task or input SHA")
        return absent
    if (type(task_id) is not str or not TASK_ID.fullmatch(task_id) or
            type(phase) is not str or phase not in PHASES or
            type(sha) is not str or not SHA.fullmatch(sha)):
        raise SnapshotError("Invalid or conflicting coordinator task card")
    return {
        **absent,
        "task_id": task_id,
        "reported_phase": phase,
        "task_input_sha": sha,
    }
