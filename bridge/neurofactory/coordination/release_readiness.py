"""Read-only fail-closed release readiness projection. NEVER an execution permit.

Caller-provided evidence, including apparently positive reviewer text, is NOT
authenticated by this module. Trusted release approvals belong off-host.
"""
import re

class ReadinessError(ValueError):
    pass

_IDS = (
    "OWNER_AND_PROJECT_AUTHORITY",
    "EXTERNAL_SIGNER_KEY_CUSTODY",
    "OFF_DB_MONOTONIC_ANTIROLLBACK",
    "REAL_OS_WRITER_ISOLATION",
    "AUTHENTICATED_CENTRAL_CAS",
    "RECIPIENT_FENCING_IDEMPOTENCY",
    "TWO_PHYSICAL_HOST_ADVERSARIAL_E2E",
    "MODEL_RESOURCE_PROVENANCE",
    "EXTERNAL_INDEPENDENT_RELEASE_SIGNOFF",
    "HANDOFF_EXPLICIT_UNPAUSE",
)
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[A-Z0-9_]{3,72}\Z")
_ALLOWED = frozenset({"NOT_STARTED","OFFLINE_ONLY","INCOMPLETE","REVIEW_PENDING","DEPLOYMENT_MISSING","UNKNOWN"})
_FIELDS = {"id","lane","reported_state","source_sha","evidence_note"}
_ALLOWED_LANES = frozenset({"CORE","TRUSTED_HOST","COORDINATOR","REVIEW","PROVIDERS","HANDOFF"})

def inspect_release_readiness(candidate):
    """Display a bounded advisory checklist, never trust self-reported completion."""
    if (type(candidate) is not dict or set(candidate)!={"schema","project","gates"} or
        candidate["schema"]!="neurofactory.coordination.release_readiness.v1" or
        candidate["project"]!="НЕЙРОЗАВОД" or
        type(candidate["gates"]) is not list or len(candidate["gates"])!=len(_IDS)):
        raise ReadinessError("invalid release checklist")
    found=set()
    entries=[]
    for entry in candidate["gates"]:
        if type(entry) is not dict or set(entry)!=_FIELDS:
            raise ReadinessError("invalid gate")
        gate=entry["id"]
        if (type(gate) is not str or gate not in _IDS or gate in found or
            type(entry["lane"]) is not str or entry["lane"] not in _ALLOWED_LANES or
            type(entry["reported_state"]) is not str or entry["reported_state"] not in _ALLOWED or
            type(entry["source_sha"]) is not str or _SHA.fullmatch(entry["source_sha"]) is None or
            type(entry["evidence_note"]) is not str or
            not 1 <= len(entry["evidence_note"]) <= 300 or
            any(ord(c)<32 or ord(c)==127 for c in entry["evidence_note"])):
            raise ReadinessError("invalid or untrusted gate values")
        found.add(gate)
        entries.append({"gate_id":gate, "lane":entry["lane"],
                        "reported_state":entry["reported_state"],
                        "external_release_authority_authenticated":False})
    if found != set(_IDS):
        raise ReadinessError("missing release requirements")
    return {
        "schema":"neurofactory.coordination.release_readiness_report.v1",
        "project":"НЕЙРОЗАВОД",
        "status":"BLOCKED_EXTERNAL_TRUST_NOT_DEPLOYED",
        "required_gates":len(_IDS),
        "independently_authenticated_gate_count":0,
        "pending_gate_ids":list(_IDS),
        "gates":entries,
        "source_origin_authenticated":False,
        "external_signer_authenticated":False,
        "independent_release_review_authenticated":False,
        "live_execution_allowed":False,
        "automatic_retry_allowed":False,
        "publication_allowed":False,
        "merge_allowed":False,
        "paid_api_allowed":False,
        "handoff":"PAUSED_BY_USER",
    }
