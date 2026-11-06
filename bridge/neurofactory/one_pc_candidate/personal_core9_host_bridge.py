"""Existing OneTaskCore v1 queue -> real owner-reviewed personal HOST file.

Only the protected LocalService entrypoint may import and call this module.
A human-signed CORE admission and a distinct signed project-file envelope
must match a SINGLE actual QUEUED task in preprovisioned OneTaskCore SQLite.
The service itself claims the lease, reserves one signed Linux epoch, performs
one CREATE_NEW text-file effect and checkpoints its CORE completion.

NO model execution, shell, paid API, directory traversal or auto recovery.
Any crash after CLAIMED is manual review; never start old pending work again.
"""
from __future__ import annotations

import base64
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import time
import re

from cryptography.exceptions import InvalidSignature
from one_task_core import OneTaskCore, CoreSafetyError, _canonical as core_canon, _verify_git_source
from core_readonly_observer import observe_core
from signed_owner_admission import verify_owner_permit, AdmissionDenied
from personal_project_file_effect import (
    PROJECT_FILE_SCHEMA, PROJECT_FILE_FIELDS, PROJECT_FILE_ACTION,
    check_core_permission, project_target, apply_approved_project_file,
)
from personal_ssh_highwater import _canon, REQ_SCHEMA
import personal_windows_host_service as h

V2_SCHEMA = "nf.personal.owner_core9_file_v2"
V2_DOMAIN = b"NF_PERSONAL_OWNER_CORE9_SIGNED_FILE_V2\x00"
CORE_WORKER = "personal-host-service"
CORE_TARGET = "bridge/neurofactory/development/core_owned/windows_pilot.txt"
CORE_FIELDS = frozenset(("core_owner_permit","core_task_id","core_spec_sha256"))
V2_FIELDS = (PROJECT_FILE_FIELDS | CORE_FIELDS)
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


class CoreHostIntegrationDenied(ValueError):
    pass


def _deny(msg):
    raise CoreHostIntegrationDenied("CORE #9 protected service refused: " + msg)


def _verified_core9_body(packet, operator, owner):
    if (type(packet) is not dict or set(packet) != V2_FIELDS
            or packet.get("schema") != V2_SCHEMA
            or packet.get("operation") != PROJECT_FILE_ACTION
            or type(packet.get("core_owner_permit")) is not dict
            or type(packet.get("core_task_id")) is not str
            or type(packet.get("core_spec_sha256")) is not str
            or not HEX64.fullmatch(packet["core_spec_sha256"])
            or len(_canon(packet)) > 12000):
        _deny("invalid strictly bounded dual-signed owner envelope")
    body={k:v for k,v in packet.items() if k!="owner_signature_base64"}
    # Outer owner Ed25519 explicitly approves BOTH CORE permit and project
    # file under an independent domain, without giving the model a key.
    try:
        raw=base64.b64decode(packet["owner_signature_base64"],validate=True)
        if len(raw)!=64:
            _deny("invalid owner signature size")
        owner.verify(raw,V2_DOMAIN+_canon(body))
    except (InvalidSignature,TypeError,ValueError) as exc:
        raise CoreHostIntegrationDenied("owner-signed CORE9 envelope altered") from exc
    project_body={
        **{k:body[k] for k in PROJECT_FILE_FIELDS
           if k!="owner_signature_base64"},
        "schema":PROJECT_FILE_SCHEMA,
    }
    # Reuse original, already physically accepted strict owner HOST checks.
    # The standard _signed_body checks metadata, scope, epoch and expiration,
    # here signature authority is the outer V2 Ed25519 domain instead.
    now=int(time.time())
    if (any(project_body.get(k)!=operator[k]
            for k in ("source_sha40","machine_sha256","package_sha256"))
            or type(project_body.get("issued_unix")) is not int
            or type(project_body.get("expires_unix")) is not int
            or not now-30<=project_body["issued_unix"]<=now+2
            or not now<project_body["expires_unix"]<=now+90
            or type(project_body.get("external_epoch")) is not int
            or project_body["external_epoch"]<1):
        _deny("release/operator/short expiry scope changed")
    # The strict original validator must run before ANY remote reservation.
    check_core_permission(project_body)
    signed_core=body["core_owner_permit"]
    expected_draft=signed_core.get("draft")
    try:
        spec=verify_owner_permit(
            signed_core,
            owner_public_raw=owner.public_bytes_raw(),
            expected_draft=expected_draft,
            now=now)
    except (AdmissionDenied,KeyError,TypeError,ValueError) as exc:
        raise CoreHostIntegrationDenied("independent CORE owner signature invalid") from exc
    if (spec.get("task_id") != packet["core_task_id"]
            or spec.get("project_id") != "p-" + project_body["project_id"]
            or spec.get("source_sha") != project_body["source_sha40"]
            or spec.get("target") != CORE_TARGET
            or spec.get("model") != project_body["core_permission"]["model"]
            or expected_draft.get("draft_id") != project_body["task_id"]
            or expected_draft.get("project_uuid") != project_body["project_id"]
            or expected_draft.get("objective") != spec["objective"]
            or type(expected_draft.get("model_preference")) is not str
            or expected_draft.get("model_preference") not in ("auto",spec["model"])
            or packet["core_spec_sha256"] != sha256(core_canon(spec)).hexdigest()):
        _deny("owner CORE and HOST scope disagree")
    return body,project_body,spec


def run_signed_core9_project_file(packet):
    """Called only for V2 envelopes in existing protected personal SCM inbox."""
    operator,owner,witness=h._config()
    signed,project_body,spec=_verified_core9_body(packet,operator,owner)
    target=project_target(h.PROJECTS,project_body["project_id"],
                          project_body["relative_path"])
    if target.is_symlink() or target.exists():
        _deny("one-use project target already exists")
    root=h.ROOT/"core9"
    core=OneTaskCore(root,root/"git")
    obs=observe_core(root/"state")
    task=obs.get("task")
    if (obs.get("reported_state")!="QUEUED"
            or obs.get("execution_allowed") is not False
            or type(task) is not dict
            or task.get("task_id")!=spec["task_id"]
            or task.get("core_spec_sha256")!=packet["core_spec_sha256"]
            or task.get("source_sha40")!=operator["source_sha40"]
            or task.get("model")!=spec["model"]
            or task.get("project_id")!=spec["project_id"]):
        _deny("real CORE queue contains no exact signed QUEUED task")
    # Ensure Git HEAD/source preimage STILL matches operator-pinned release.
    _verify_git_source(core.repo,spec)
    h.assert_external_head_matches_local_fence()
    # Real durable CORE CLAIMED before a Linux remote request or any file
    # effect. Crash after this step is UNKNOWN/MANUAL. No auto repeat.
    claimed=core.claim(CORE_WORKER,now=int(time.time()),lease_seconds=240)
    if (claimed["task_id"]!=spec["task_id"]
            or claimed["model"]!=spec["model"]):
        _deny("atomic CORE claim differs from signed spec")
    operation_hash=sha256(_canon(signed)).hexdigest()
    # Original protected personal HOST local UNKNOWN and external witness.
    h._reserve_local_unknown(project_body,operation_hash)
    claim={
        "schema":REQ_SCHEMA,
        "task_id":project_body["task_id"],
        "project_id":project_body["project_id"],
        "operation_sha256":operation_hash,
        "nonce":project_body["nonce"],
        "external_epoch":project_body["external_epoch"],
        "issued_unix":project_body["issued_unix"],
        "expires_unix":project_body["expires_unix"],
        "source_sha40":project_body["source_sha40"],
        "machine_sha256":project_body["machine_sha256"],
        "package_sha256":project_body["package_sha256"],
    }
    try:
        ack=h.reserve_personal_epoch(
            trusted_service_root=h.ROOT,claim=claim,
            pinned_public_raw=witness.public_bytes_raw())
        if (ack.get("status")!="SIGNED_EXTERNAL_EPOCH_OBSERVED_NO_EFFECT_AUTHORITY"
                or ack.get("epoch")!=project_body["external_epoch"]
                or ack.get("signed_witness_verified") is not True
                or ack.get("automatic_retry_allowed") is not False
                or not int(time.time())<project_body["expires_unix"]):
            _deny("signed Linux epoch not verified before file write")
        # CORE state can change while network request proceeds; before
        # effect recheck claim's nonexpired owner/worker/digest, but this
        # local snapshot alone is not new execution authority.
        second=observe_core(root/"state")
        st=second.get("task")
        if (second.get("reported_state")!="CLAIMED"
                or type(st) is not dict
                or st.get("task_id")!=spec["task_id"]
                or st.get("core_spec_sha256")!=packet["core_spec_sha256"]
                or st.get("lease_until",0)<=int(time.time())):
            _deny("CORE changed after signed Linux reservation")
        with closing(sqlite3.connect(
                (root/"state"/"queue.sqlite3").as_uri()+"?mode=ro",
                uri=True,timeout=3)) as con:
            owner_row=con.execute(
                "SELECT owner FROM single_job WHERE singleton=1").fetchone()
        if owner_row!=(CORE_WORKER,):
            _deny("CORE lease worker not protected recipient")
        effect=apply_approved_project_file(
            signed_body=project_body,projects_root=h.PROJECTS)
        h._mark_executed(project_body,ack["ledger_head"])
        proof={
            "schema":"nf.personal.core9.host_completion.v1",
            "core_task_id":spec["task_id"],
            "qwen_task_uuid":project_body["task_id"],
            "project_uuid":project_body["project_id"],
            "relative_path":project_body["relative_path"],
            "content_sha256":project_body["content_sha256"],
            "external_epoch":project_body["external_epoch"],
            "linux_ledger_head":ack["ledger_head"],
            "source_sha40":operator["source_sha40"],
            "linux_signature_checked":True,
            "generated_source_executed":False,
            "automatic_retry_allowed":False,
        }
        def readback(p):
            # Independently fetch signed current Linux head, now bound to
            # local HOST committed fence. Not just an unsigned caller flag.
            head=h.assert_external_head_matches_local_fence()
            if (head.get("remote_status_signature_verified") is not True
                    or head.get("epoch")!=p["external_epoch"]
                    or head.get("ledger_head")!=p["linux_ledger_head"]
                    or not target.is_file() or target.is_symlink()
                    or sha256(target.read_bytes()).hexdigest()!=p["content_sha256"]):
                return False
            with closing(h._connect_existing()) as con:
                row=con.execute(
                    "SELECT status,external_epoch,remote_head FROM intents "
                    "WHERE task_id=?", (p["qwen_task_uuid"],)).fetchone()
            return row==("EXECUTED",p["external_epoch"],p["linux_ledger_head"])
        checkpoint=core.finalize_personal_host(
            spec["task_id"],claimed["token"],proof,
            trusted_effect_readback=readback)
        if checkpoint.get("state")!="HOST_CHECKPOINTED_PERSONAL":
            _deny("CORE refused durable completed receipt")
        verified=head=h.assert_external_head_matches_local_fence()
        if not core.verify_personal_host_result(
                protected_projects=h.PROJECTS,host_fence=h.FENCE,
                signed_remote_head=verified):
            _deny("post-completion protected readback disagreed")
        return {
            "status":"CORE9_OWNER_QWEN_PHYSICAL_HOST_FILE_EXECUTED_ONCE",
            "core_task_id":spec["task_id"],
            "qwen_task_uuid":project_body["task_id"],
            "external_epoch":project_body["external_epoch"],
            "source_executed":False,
            "automatic_retry_allowed":False,
        }
    except Exception as exc:
        # Core remains CLAIMED or HOST local UNKNOWN, even if Linux committed.
        # No replay, no auto-repair. Human must reconcile both durable ledgers.
        raise CoreHostIntegrationDenied(
            "CORE/physical HOST execution or completion UNKNOWN: NO AUTO RETRY"
        ) from exc


def verify_protected_core9_after_scm_start():
    """Only read existing queue and independently signed Linux HEAD."""
    root=h.ROOT/"core9"
    if not root.exists():
        _deny("mandatory protected CORE9 queue missing; service boot refused")
    core=OneTaskCore(root,root/"git")
    snapshot=core.snapshot()
    state=snapshot["state"]
    if state=="EMPTY":
        return "CORE9_EMPTY_NO_AUTO_WORK"
    if state=="HOST_CHECKPOINTED_PERSONAL":
        remote=h.assert_external_head_matches_local_fence()
        core.verify_personal_host_result(
            protected_projects=h.PROJECTS,host_fence=h.FENCE,
            signed_remote_head=remote)
        return "CORE9_COMPLETION_AND_SIGNED_LINUX_RESTORED"
    # A previous host attempt cannot be silently repeated at service boot.
    if state in ("QUEUED","CLAIMED","APPLYING","NEEDS_MANUAL_REVIEW",
                 "HOST_CHECKPOINTED_TEST","CHECKPOINTED_TEST"):
        return "CORE9_PENDING_OR_NONPERSONAL_NO_AUTOMATIC_EXECUTION_"+state
    _deny("unknown CORE9 protected queue state")
