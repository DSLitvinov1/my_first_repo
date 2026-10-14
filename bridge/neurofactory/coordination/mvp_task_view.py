"""Read-only adapter from coordinator task projection to future UI/OPS summary."""
import re

class ViewError(ValueError):
    pass

_SHA = re.compile(r"[a-f0-9]{40}\Z")
_ID = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_STATES = {
    "PENDING_APPROVAL": "waiting_review",
    "AUTHORIZED": "candidate",
    "READY_FOR_CORE": "waiting_dependency",
    "RESPONSE_UNVERIFIED": "waiting_review",
    "SOURCE_VERIFIED": "waiting_review",
}
_FIELDS = {"schema", "task_id", "project_id", "source_sha", "stage",
           "result_digest", "review_provenance", "source_verified_by_host",
           "external_execution_allowed", "publication_allowed",
           "automatic_retry_allowed", "handoff"}

def task_card(view):
    """Validate exact metadata, preserve UNKNOWN, and never grant authority."""
    if view is None:
        return {"schema": 1, "kind": "task_status_card", "task_id": None,
                "display_phase": "unknown", "source_sha": None,
                "source_trust": "not_attested", "actions_allowed": False}
    if type(view) is not dict or set(view) != _FIELDS:
        raise ViewError("unexpected projection fields")
    if (type(view["schema"]) is not int or view["schema"] != 1 or
        type(view["task_id"]) is not str or not _ID.fullmatch(view["task_id"]) or
        type(view["source_sha"]) is not str or not _SHA.fullmatch(view["source_sha"]) or
        type(view["project_id"]) is not str or not re.fullmatch(r"[a-z][a-z0-9-]{2,39}", view["project_id"]) or
        type(view["stage"]) is not str or view["stage"] not in _STATES or
        view["review_provenance"] != "NOT_ATTESTED_BY_PROJECTION" or
        view["source_verified_by_host"] is not False or
        view["external_execution_allowed"] is not False or
        view["publication_allowed"] is not False or
        view["automatic_retry_allowed"] is not False or
        view["handoff"] != "PAUSED_BY_USER"):
        raise ViewError("untrusted stage or unsafe action")
    result_hash = view["result_digest"]
    if result_hash is not None and (type(result_hash) is not str or not re.fullmatch(r"[a-f0-9]{64}", result_hash)):
        raise ViewError("invalid result digest")
    if (view["stage"] in ("PENDING_APPROVAL", "AUTHORIZED", "READY_FOR_CORE")) != (result_hash is None):
        raise ViewError("result digest does not match task stage")
    return {"schema": 1, "kind": "task_status_card", "task_id": view["task_id"],
            "display_phase": _STATES[view["stage"]], "source_sha": view["source_sha"],
            "source_trust": "not_attested", "actions_allowed": False}
