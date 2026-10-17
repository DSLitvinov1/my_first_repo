"""EXPLICITLY NON-PRODUCTION CORE+HOST signed-scope fixture.

Combines HOST cryptographic format verification, independently-supplied TEST
scope, live PostgreSQL lease/intent fixture, then the existing temporary
CORE offline fixture only. NEVER authorizes real operations or models.
No key or trust root is provisioned by this module.
"""
from __future__ import annotations
import hashlib
import os
import re

from fenced_offline_core import FencedOfflineTestBridge, FencedOfflineBoundaryError

class SignedScopeFixtureError(ValueError):
    pass

_SHA64=re.compile(r"[0-9a-f]{64}\Z")

class SignedScopeFixtureBridge(FencedOfflineTestBridge):
    def __init__(self, core, host_effect_gate, permit_verifier):
        super().__init__(core,host_effect_gate)
        if os.environ.get("NF_CORE_SIGNED_SCOPE_FIXTURE")!="1":
            raise SignedScopeFixtureError("signed offline fixture not enabled")
        if not callable(permit_verifier):
            raise SignedScopeFixtureError("missing immutable pinned HOST verifier")
        self._verifier=permit_verifier

    def apply_signed_test_once(self, *, signed_packet, externally_pinned_key,
                               trusted_scope, host_claim, core_token, proposal,
                               worker_id, policy_sha256, idempotency_key,
                               operation_id, now_unix, core_test_now):
        """One inert fixture effect, requiring signature + HOST lease/intent.

        The trust root, private signer and scope are not protected here.
        The verifier's success remains explicitly NO EXECUTION AUTHORITY;
        the method is usable solely for ephemeral offline testing.
        """
        if (os.environ.get("NF_CORE_SIGNED_SCOPE_FIXTURE")!="1"
                or os.environ.get("NF_CORE_FENCED_TEST_ONLY")!="1"
                or os.environ.get("NF_CORE_OFFLINE_FIXTURE")!="1"
                or os.name!="posix"):
            raise SignedScopeFixtureError("non-production fixture guard unavailable")
        if (type(signed_packet) is not dict or
                type(trusted_scope) is not dict or
                type(host_claim) is not dict or
                type(proposal) is not dict or
                type(operation_id) is not str or
                type(now_unix) is not int or
                not 1<=now_unix<2**63 or
                type(core_test_now) is not int or not 0 <= core_test_now < 2**31 or
                type(idempotency_key) is not str or
                not _SHA64.fullmatch(idempotency_key) or
                not hasattr(externally_pinned_key,"verify")):
            raise SignedScopeFixtureError("malformed signed fixture request")
        if type(worker_id) is not str or type(core_token) is not str:
            raise SignedScopeFixtureError("missing worker identity or local test token")
        with self.core._connect() as con:
            con.execute("BEGIN")
            row=self.core._row(con)
            if row is None or row["state"]!="CLAIMED":
                raise SignedScopeFixtureError("no CORE fixture claim")
            spec=dict(row["spec"])
            if row["owner"]!=worker_id or proposal.get("target")!=spec["target"]:
                raise SignedScopeFixtureError("worker or output target mismatch")
        if (set(host_claim)!={"status","task_id","lease_epoch",
                              "fencing_token","lease_deadline"} or
                host_claim["status"]!="CLAIMED" or
                host_claim["task_id"]!=spec["task_id"] or
                type(host_claim["lease_epoch"]) is not int or
                host_claim["lease_epoch"]<1 or
                type(host_claim["fencing_token"]) is not str):
            raise SignedScopeFixtureError("central HOST lease absent")
        identity={
            "project_id":spec["project_id"],
            "task_id":spec["task_id"],
            "worker_id":worker_id,
            "source_sha40":spec["source_sha"],
            "source_file_sha256":spec["source_sha256"],
            "input_task_sha256":hashlib.sha256(
                self._canonical_core_spec(spec)).hexdigest(),
            "policy_sha256":policy_sha256,
            "target":spec["target"],
            "proposed_content_sha256":proposal.get("content_sha256"),
            "fencing_token_sha256":hashlib.sha256(
                host_claim["fencing_token"].encode()).hexdigest(),
            "lease_epoch":host_claim["lease_epoch"],
            "idempotency_key":idempotency_key,
            "operation_id":operation_id,
        }
        if any(trusted_scope.get(k)!=v or type(trusted_scope.get(k))!=type(v)
               for k,v in identity.items()):
            raise SignedScopeFixtureError("claimed operation not bound to local source")
        # Do not accept an attacker-supplied shortened trusted scope.
        if set(trusted_scope) != {
            "issuer_id","key_id","owner_id","repository",*identity.keys()
        }:
            raise SignedScopeFixtureError("incomplete expected signed scope")
        # Host verifier ALWAYS says execution_allowed=false.  This method
        # deliberately does not promote that report into runtime authority.
        try:
            report=self._verifier(
                signed_packet,externally_pinned_public_key=externally_pinned_key,
                trusted_expected_scope=trusted_scope,now_unix=now_unix)
        except Exception as exc:
            raise SignedScopeFixtureError("untrusted signed scope") from exc
        if (type(report) is not dict or
                report.get("status")!="CRYPTO_SCOPE_MATCHES_NO_EXECUTION_AUTHORITY"
                or report.get("task_id")!=spec["task_id"]
                or report.get("operation_id")!=operation_id
                or report.get("cryptographic_signature_verified") is not True
                or report.get("exact_external_scope_compared") is not True
                or report.get("filesystem_execution_allowed") is not False
                or report.get("real_owner_rights_authenticated") is not False
                or report.get("receiver_idempotency_enforced") is not False):
            raise SignedScopeFixtureError("signed report cannot be trusted")
        return super().apply_once(
            task_id=spec["task_id"], core_token=core_token, proposal=proposal,
            worker_id=worker_id,host_claim=host_claim,
            policy_sha256=policy_sha256,
            idempotency_key=idempotency_key,
            now=core_test_now)
