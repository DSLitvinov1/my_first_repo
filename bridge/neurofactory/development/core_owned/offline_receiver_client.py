"""CORE-owned fail-closed CALLER for the HOST disposable fenced receiver.

Does not write any file locally, does not restart old apply_offline_test and
never authorizes production effects. The trusted receiver must perform actual
signed, lease, replay checks independently. For test-only receipt integration.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time

class OfflineProtectedRouteDenied(ValueError):
    pass

def _deny(message):
    raise OfflineProtectedRouteDenied(message)

class CoreOfflineReceiverClient:
    def __init__(self, core, trusted_host_receiver):
        if os.name!="posix" or os.environ.get("NF_CORE_OFFLINE_RECEIVER_TEST_ONLY")!="1":
            _deny("protected route remains test-only")
        if core is None or trusted_host_receiver is None:
            _deny("both pinned endpoints required")
        self.core=core
        self.receiver=trusted_host_receiver

    def propose_one_test_effect(self, *, task_id, core_token, worker_id,
                                proposal, signed_packet):
        """Read real CORE local claim, then ask HOST to make the sole effect.

        This adapter is NOT an authenticated transport. Production must use
        a separate OS-protected receiver and independent trust root.
        """
        if (type(task_id) is not str or type(core_token) is not str
            or type(worker_id) is not str or
            type(proposal) is not dict or
            set(proposal)!={"schema","target","content","content_sha256","mode"} or
            proposal.get("schema")!="neurofactory.core.proposal.v1" or
            proposal.get("mode")!="OFFLINE_TEST" or
            type(proposal.get("target")) is not str or
            type(proposal.get("content")) is not str or
            type(proposal.get("content_sha256")) is not str or
            type(signed_packet) is not dict):
            _deny("invalid CORE proposal or signed packet")
        data=proposal["content"].encode("utf8")
        if len(data)>65536 or hashlib.sha256(data).hexdigest()!=proposal["content_sha256"]:
            _deny("proposal bytes differ from hash")
        now=int(time.time())
        with self.core._connect() as conn:
            conn.execute("BEGIN")
            row=self.core._row(conn)
            if (row is None or row["state"]!="CLAIMED" or
                row["spec"]["task_id"]!=task_id or
                row["owner"]!=worker_id or row["lease_until"]<=now or
                not hmac.compare_digest(
                    hashlib.sha256(core_token.encode("utf8")).hexdigest(),
                    row["token"]) or
                proposal["target"]!=row["spec"]["target"]):
                _deny("CORE local task state/worker/expiry denied")
            spec=dict(row["spec"])
        body=signed_packet.get("payload")
        if type(body) is not dict:
            _deny("missing signed body")
        # Local scope check only; not a replacement for HOST's verified DB
        # row and cryptographic check immediately at protected file recipient.
        expected={
            "task_id":spec["task_id"],
            "project_id":spec["project_id"],
            "source_sha40":spec["source_sha"],
            "source_file_sha256":spec["source_sha256"],
            "target":spec["target"],
            "worker_id":worker_id,
            "proposed_content_sha256":proposal["content_sha256"],
        }
        if any(body.get(k)!=v for k,v in expected.items()):
            _deny("signed scope does not match current CORE checkpoint")
        receipt=self.receiver.write_fixture_once(
            signed_packet=signed_packet,content=data)
        if (type(receipt) is not dict or
            receipt.get("status")!="ONE_FILE_COMPLETED_OFFLINE_TEST_ONLY" or
            receipt.get("task_id")!=task_id or
            receipt.get("content_sha256")!=proposal["content_sha256"] or
            any(receipt.get(k) is not False for k in (
                "external_owner_authenticated",
                "protected_signer_custody_attested",
                "production_lease_authenticated",
                "true_independent_recipient_fencing",
                "live_execution_allowed","auto_retry_allowed",
                "publication_allowed"))):
            raise OfflineProtectedRouteDenied("HOST receipt not independently approved")
        return {
            "status":"CORE_TO_HOST_ONE_EFFECT_OBSERVED_OFFLINE_ONLY",
            "task_id":task_id,"content_sha256":receipt["content_sha256"],
            "one_disposable_file_effect_observed":True,
            "core_checkpoint_production_authorized":False,
            "live_execution_allowed":False,"auto_retry_allowed":False,
            "publication_allowed":False,
        }
