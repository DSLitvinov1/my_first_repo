"""Strict one-task bridge: UI draft -> offline owner-signed permit -> REAL CORE enqueue.

The browser can ONLY read a digest-bound admission request; signing keys never
exist in HTTP/UI. Admission function is for a separately authorized TRUSTED HOST
controller with a pinned owner Ed25519 public key and OS-protected CORE object.

No permission to claim, invoke a model, apply an effect, publish or retry.
This bridge's process boundary and public-key custody are NOT deployed on the
user's Windows device. Its positive path is an isolated signed CI exercise.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time

_DRAFT_ID = re.compile(r"[a-f0-9]{32}\Z")
_CORE_TASK = re.compile(r"NF-DEV-05-Q[0-9]{3}\Z")
_SHA40 = re.compile(r"[a-f0-9]{40}\Z")
_SHA64 = re.compile(r"[a-f0-9]{64}\Z")
_MODELS = frozenset(("qwen3:0.6b", "qwen3:4b", "qwen2.5-coder:7b",
                     "qwen2.5-coder:1.5b"))
_CORE_SPEC_KEYS = frozenset((
    "schema", "task_id", "project_id", "target", "objective",
    "source_sha", "source_sha256", "model", "reserved_units",
    "approval_commit",
))
_BODY_KEYS = frozenset((
    "schema", "scope", "draft", "spec", "nonce",
    "issued_at", "expires_at",
))
_ALL_KEYS = _BODY_KEYS | {"owner_signature"}
_SCOPE = "OWNER_SIGNED_SINGLE_TEST_CORE_ENQUEUE_NO_EXECUTION"


class AdmissionDenied(ValueError):
    """Reject forged/stale/cross-project/unknown authorization, no retry."""


def _canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _one_draft(store, draft_id):
    """Read a durable, immutable UI draft and linked PROJECT from workspace DB."""
    if type(draft_id) is not str or not _DRAFT_ID.fullmatch(draft_id):
        raise AdmissionDenied("Invalid draft identity")
    with store.connect() as db:
        row = db.execute(
            "SELECT t.id,t.project_id,t.objective,t.model_preference,t.state,"
            "t.created_utc,p.id FROM tasks t "
            "JOIN projects p ON p.id=t.project_id WHERE t.id=?",
            (draft_id,),
        ).fetchone()
    if (row is None or len(row) != 7 or row[1] != row[6] or
            row[4] != "DRAFT_PENDING_OWNER_AUTH" or
            type(row[2]) is not str or not 25 <= len(row[2]) <= 320 or
            any(ord(c) < 32 for c in row[2]) or
            row[3] not in ("auto", "qwen3:0.6b", "qwen2.5-coder:1.5b")):
        raise AdmissionDenied("Draft is not eligible for restricted CORE contract")
    # This is a deterministic mapping, not a user-controlled CORE project slug.
    return {"draft_id": row[0], "project_uuid": row[1],
            "core_project_id": "p-" + row[1],
            "objective": row[2], "model_preference": row[3],
            "created_utc": row[5]}


def prepare_draft_request(store, draft_id):
    """Unprivileged read-only UI preparation. No source paths or signer here."""
    original = _one_draft(store, draft_id)
    digest = _sha(_canon(original))
    return {"schema": "nf.onepc.draft_admission_request.v1",
            **original, "draft_sha256": digest,
            "owner_signed": False, "execution_allowed": False,
            "queue_mutation_allowed": False}


def _signed_body(permit):
    if (type(permit) is not dict or set(permit) != _ALL_KEYS or
            any(type(permit.get(k)) is not str for k in
                ("owner_signature", "nonce", "scope", "schema"))):
        raise AdmissionDenied("Invalid signed admission envelope")
    body = {key: permit[key] for key in _BODY_KEYS}
    raw = _canon(body)
    if len(raw) > 5000 or len(_canon(permit)) > 6500:
        raise AdmissionDenied("Oversized admission envelope")
    return body, raw


def verify_owner_permit(permit, *, owner_public_raw, expected_draft, now=None):
    """Verify domain-separated signature; caller supplies a PROTECTED pinned key.

    A public key from HTTP, model output or unsigned permit is not trust.
    """
    body, raw = _signed_body(permit)
    now = int(time.time()) if now is None else now
    if (type(now) is not int or now < 0 or
            type(body["issued_at"]) is not int or
            type(body["expires_at"]) is not int or
            body["issued_at"] > now or
            now >= body["expires_at"] or
            not 0 < body["expires_at"] - body["issued_at"] <= 600 or
            body["schema"] != "nf.onepc.owner_core_admission.v1" or
            body["scope"] != _SCOPE or
            not re.fullmatch(r"[a-f0-9]{32}", body["nonce"]) or
            type(expected_draft) is not dict or
            body["draft"] != expected_draft or
            body["draft"].get("owner_signed") is not False or
            body["draft"].get("queue_mutation_allowed") is not False or
            body["draft"].get("execution_allowed") is not False):
        raise AdmissionDenied("Expired, mismatched or out-of-scope owner permit")
    spec = body["spec"]
    if type(spec) is not dict or set(spec) != _CORE_SPEC_KEYS:
        raise AdmissionDenied("CORE specification must be exact")
    if (spec.get("schema") != "neurofactory.core.task.v1" or
            type(spec.get("task_id")) is not str or
            not _CORE_TASK.fullmatch(spec["task_id"]) or
            spec.get("project_id") != expected_draft["core_project_id"] or
            spec.get("objective") != expected_draft["objective"] or
            type(spec.get("model")) is not str or
            spec["model"] not in _MODELS or
            (expected_draft["model_preference"] != "auto" and
             spec["model"] != expected_draft["model_preference"]) or
            type(spec.get("source_sha")) is not str or
            not _SHA40.fullmatch(spec["source_sha"]) or
            spec.get("approval_commit") != spec["source_sha"] or
            type(spec.get("source_sha256")) is not str or
            not _SHA64.fullmatch(spec["source_sha256"]) or
            type(spec.get("reserved_units")) is not int or
            not 1 <= spec["reserved_units"] <= 100000):
        raise AdmissionDenied("CORE candidate differs from exact immutable draft")
    if (type(owner_public_raw) is not bytes or len(owner_public_raw) != 32 or
            len(permit["owner_signature"]) != 88):
        raise AdmissionDenied("No pinned owner Ed25519 key/signature")
    try:
        signature = base64.b64decode(permit["owner_signature"], validate=True)
        if len(signature) != 64:
            raise AdmissionDenied("Invalid owner signature size")
        # Import only inside protected verifier. Packaged UI draft runtime
        # doesn't load cryptography or hold any signing authority.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        Ed25519PublicKey.from_public_bytes(owner_public_raw).verify(
            signature, b"NF_OWNER_CORE_ADMISSION_V1\x00" + raw)
    except (ValueError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise AdmissionDenied("Signature from pinned owner not verified") from exc
    return spec


def admit_signed_draft(store, core, signed_permit, *, owner_public_raw, now=None):
    """Only trusted controller calls this, NEVER registered as an HTTP handler.

    On any uncertain failure before/during durable CORE enqueue, the operator
    must inspect CORE. The UI draft is never automatically submitted/retried.
    """
    if type(signed_permit) is not dict or type(signed_permit.get("draft")) is not dict:
        raise AdmissionDenied("Signed draft missing")
    draft_id = signed_permit["draft"].get("draft_id")
    original = prepare_draft_request(store, draft_id)
    spec = verify_owner_permit(
        signed_permit, owner_public_raw=owner_public_raw,
        expected_draft=original, now=now)
    # The callback is actually checked by OneTaskCore.enqueue immediately
    # before the pinned local Git preimage and SQLite transaction.
    # Not an unconditional lambda True, not controlled by browser input.
    def authenticated_check(candidate):
        if candidate != spec:
            return False
        verified = verify_owner_permit(
            signed_permit, owner_public_raw=owner_public_raw,
            expected_draft=prepare_draft_request(store, draft_id), now=now)
        return verified == candidate

    try:
        snapshot = core.enqueue(spec, trusted_approval_check=authenticated_check)
    except Exception as exc:
        # Fail closed: because different SQLite stores are not atomic,
        # never try to recover or retry an uncertain queue admission.
        raise AdmissionDenied("CORE admission denied or unknown; inspect manually") from exc
    if snapshot.get("state") != "QUEUED" or snapshot.get("task_id") != spec["task_id"]:
        raise AdmissionDenied("CORE checkpoint uncertain after signed admission")
    return {"schema": "nf.onepc.trusted_admission_observed.v1",
            "core_task_id": spec["task_id"],
            "draft_id": draft_id, "core_project_id": spec["project_id"],
            "source_sha": spec["source_sha"],
            "draft_sha256": original["draft_sha256"],
            "core_reported_state": "QUEUED",
            "operator_verified_signed_permit": True,
            "queue_claim_allowed": False,
            "host_execution_allowed": False,
            "independent_review": False,
            "production_release": False}
