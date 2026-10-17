"""Signer's authenticated TEST-ONLY authorization gate for existing HOST receiver.

Requires a current protected signer-owned scope witness over an authenticated
local Unix socket before calling the existing actual Postgres-backed receiver.
Not production: recipient is not a separately privileged protected OS daemon,
the permit fixture is not human approved, and a different caller can still
invoke the old test-only receiver directly. NEVER treat a success as release.
"""
from __future__ import annotations

import hashlib
from contextlib import nullcontext
import json
import os
import re
from offline_operator_ipc import client_send, OperatorIPCError
from offline_fenced_file_receiver import (
    OfflineFencedFileReceiver,OfflineReceiverDenied,OfflineEffectUnknown,
)
from signed_effect_permit import _validated_payload,SignedEffectPermitError

_SHA64=re.compile(r"[0-9a-f]{64}\Z")

def _reject():
    raise OfflineReceiverDenied("signed external operator scope not confirmed; no file action")

class OperatorGatedOfflineReceiver:
    def __init__(self,receiver,*,socket_path,pinned_signer_uid,
                 independently_pinned_public_sha,independently_pinned_public_b64):
        if (os.name!="posix" or
            os.environ.get("NF_HOST_RECEIVER_FIXTURE_ONLY")!="1" or
            os.environ.get("NF_OPERATOR_ANCHOR_FIXTURE_ONLY")!="1" or
            type(receiver) is not OfflineFencedFileReceiver or
            type(socket_path) is not str or
            not socket_path.endswith("/nf-operator-api/nf-readonly-operator.sock") or
            type(pinned_signer_uid) is not int or pinned_signer_uid<=0 or
            type(independently_pinned_public_sha) is not str or
            not _SHA64.fullmatch(independently_pinned_public_sha) or
            type(independently_pinned_public_b64) is not str):
            _reject()
        self._receiver=receiver
        self._socket=socket_path
        self._server_uid=pinned_signer_uid
        self._public_sha=independently_pinned_public_sha
        self._public_b64=independently_pinned_public_b64

    def apply_fixture_with_operator_witness_once(self,*,signed_packet,
                                                   witness,content,
                                                   simulate_crash_after_fsync=False,
                                                   protected_journal=None,
                                                   signed_owner_grant=None,
                                                   external_witness_config=None):
        if (type(content) is not bytes or len(content)>65536 or
            type(signed_packet) is not dict or
            type(witness) is not dict or
            type(simulate_crash_after_fsync) is not bool):
            _reject()
        try:
            canonical=_validated_payload(signed_packet["payload"])
            digest=hashlib.sha256(canonical).hexdigest()
        except (SignedEffectPermitError,KeyError,TypeError,ValueError):
            _reject()
        if hashlib.sha256(content).hexdigest()!=signed_packet["payload"]["proposed_content_sha256"]:
            _reject()
        if signed_owner_grant is not None:
            if (type(signed_owner_grant) is not dict or
                set(signed_owner_grant)!={"statement","signature_base64"} or
                type(signed_owner_grant["statement"]) is not dict):
                _reject()
            request={
                "schema":"neurofactory.operator.scope_and_owner_check_fixture.v1",
                "signed_permit":signed_packet,"witness":witness,
                "signed_owner_grant":signed_owner_grant,
                "public_sha":self._public_sha,"public_key":self._public_b64}
        else:
            # Kept for unchanged offline unit compatibility; the isolated
            # OS recipient now ALWAYS supplies signed_owner_grant.
            request={
                "schema":"neurofactory.operator.scope_check_fixture.v1",
                "signed_permit":signed_packet,"witness":witness,
                "public_sha":self._public_sha,"public_key":self._public_b64}
        try:
            check=client_send(self._socket,request,pinned_signer_uid=self._server_uid)
        except (ValueError,OSError,TimeoutError,UnicodeError,json.JSONDecodeError):
            _reject()
        if signed_owner_grant is not None:
            from offline_operator_anchor import _canonical
            claim=signed_owner_grant["statement"]
            if (type(check) is not dict or
                set(check)!={"status","signed_permit_sha256","operation_id",
                              "owner_grant_sha256","current_signer_sequence",
                              "peer_uid_checked","private_key_shared",
                              "real_owner_identity_authenticated","filesystem_write_allowed"} or
                check["status"]!="PINNED_OWNER_AND_SIGNER_SCOPE_MATCH_TEST_ONLY" or
                check["signed_permit_sha256"]!=digest or
                check["operation_id"]!=signed_packet["payload"]["operation_id"] or
                check["owner_grant_sha256"]!=hashlib.sha256(_canonical(claim)).hexdigest() or
                type(check["current_signer_sequence"]) is not int or
                check["current_signer_sequence"]<1 or
                check["peer_uid_checked"] is not True or
                check["private_key_shared"] is not False or
                check["real_owner_identity_authenticated"] is not False or
                check["filesystem_write_allowed"] is not False):
                _reject()
        elif (type(check) is not dict or
              set(check)!={"status","signed_permit_sha256","operation_id",
                        "current_signer_sequence","peer_uid_checked",
                        "private_key_shared","owner_authenticated","filesystem_write_allowed"}
              or check["status"]!="OWNER_SCOPE_FIXTURE_MATCHED_NOT_AUTHORITY"
              or check["signed_permit_sha256"]!=digest or
              check["operation_id"]!=signed_packet["payload"]["operation_id"]
              or type(check["current_signer_sequence"]) is not int or
              check["current_signer_sequence"]<1 or
              check["peer_uid_checked"] is not True or
              check["private_key_shared"] is not False or
              check["owner_authenticated"] is not False or
              check["filesystem_write_allowed"] is not False):
            _reject()
        if external_witness_config is not None:
            if signed_owner_grant is None:
                _reject()
            cfg=external_witness_config
            if type(cfg) is not dict or (
                set(cfg)!={"socket","uid","public"} and
                set(cfg)!={"mode","host","port","client_cert","client_key",
                            "ca_cert","server_cert_sha256","public"}):
                _reject()
            import secrets
            from offline_external_effect_witness import request_once,WitnessDenied
            body=signed_packet["payload"]
            claim={"schema":"nf.remote_witness.claim.v1",
                "owner_id":"151650108","repo_id":"723328237",
                "task_id":body["task_id"],"operation_id":body["operation_id"],
                "target":body["target"],"lease_epoch":body["lease_epoch"],
                "permit_sha256":digest,
                "content_sha256":hashlib.sha256(content).hexdigest(),
                "nonce":secrets.token_hex(32)}
            try:
                if "mode" in cfg:
                    if cfg["mode"]!="MTLS_LOOPBACK_TEST_ONLY":
                        _reject()
                    from offline_mtls_witness_transport import request_test_once
                    ack=request_test_once(cfg["host"],cfg["port"],claim,
                        client_cert=cfg["client_cert"],client_key=cfg["client_key"],
                        ca_cert=cfg["ca_cert"],
                        pinned_server_cert_sha256=cfg["server_cert_sha256"],
                        pinned_witness_public_b64=cfg["public"])
                    if ack["status"]!="MUTUAL_TLS_REMOTE_WITNESS_DURABLE_TEST_ONLY":
                        _reject()
                else:
                    ack=request_once(cfg["socket"],claim,
                        expected_witness_uid=cfg["uid"],
                        pinned_witness_public_b64=cfg["public"])
                    if ack["status"]!="REMOTE_UID_WITNESS_PRECOMMIT_TEST_ONLY":
                        _reject()
            except (WitnessDenied,ValueError,OSError,KeyError,TypeError):
                _reject()

        # The signer has already verified all exact owner/source/worker
        # claims. An *optional* independent OS-owned protected ledger must
        # reserve UNKNOWN durably before the DB journal and file effect.
        # Older test-only wrappers still run without an external ledger.
        if protected_journal is not None:
            from offline_recipient_protected_journal import RecipientProtectedJournal
            if type(protected_journal) is not RecipientProtectedJournal:
                _reject()
            body=signed_packet["payload"]
            barrier=protected_journal.intent_once(
                task_id=body["task_id"],operation_id=body["operation_id"],
                target=body["target"],
                content_sha256=body["proposed_content_sha256"])
        else:
            barrier=nullcontext()
        with barrier:
            # HOST must still independently verify a CURRENT real PG lease
            # under its row lock, and fail UNKNOWN on any uncertain write.
            result=self._receiver.write_fixture_once(
                signed_packet=signed_packet,content=content,
                simulate_crash_after_fsync=simulate_crash_after_fsync)
            if (type(result) is not dict or
                result.get("status")!="ONE_FILE_COMPLETED_OFFLINE_TEST_ONLY" or
                result.get("content_sha256")!=hashlib.sha256(content).hexdigest() or
                result.get("live_execution_allowed") is not False):
                raise OfflineEffectUnknown("receiver receipt not confirmed: manual STOP")
        return {
            "status":"ONE_SIGNER_SCOPE_GATED_FIXTURE_FILE_ONLY",
            "operation_id":check["operation_id"],
            "content_sha256":result["content_sha256"],
            "live_execution_allowed":False,
            "independent_human_owner_approved":False,
            "production_recipient_os_isolated":False,
            "auto_retry_allowed":False,
        }
