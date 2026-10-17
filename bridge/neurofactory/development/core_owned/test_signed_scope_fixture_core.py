"""Pinned CORE/HOST Ed25519 scope + PostgreSQL fixture + one inert file.

All secrets are ephemeral, in-memory TEST keys.  Owner/operator attestation,
protected OS signer, external monotonic root and LIVE receiver remain absent.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import time
import unittest

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_fenced_offline_core as prior
from signed_scope_fixture_core import SignedScopeFixtureBridge, SignedScopeFixtureError

CORE_LEGACY_BLOB="ab1471813c6da29407c913b974a2209467a4b961"
HOST_SHA="66dfbc6957c04cd9f8d19ba52ec783fa1dec129d"

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

class SignedScopeFixtureTests(prior.RealPinnedTestIntegration):
    @classmethod
    def setUpClass(cls):
        if os.name!="posix" or not all(os.environ.get(k)=="1" for k in (
                "NF_CORE_FENCED_TEST_ONLY","NF_CORE_OFFLINE_FIXTURE",
                "NF_CORE_SIGNED_SCOPE_FIXTURE")):
            raise RuntimeError("only isolated ephemeral signed fixture")
        root=Path(__file__).resolve().parents[4]
        blob=prior.git(root,"hash-object",
                       "bridge/neurofactory/development/core_owned/one_task_core.py")
        if blob!=CORE_LEGACY_BLOB:
            raise RuntimeError("CORE executable code changed without new review")
        host=root/"_pinned_fixture"/"host"
        if prior.git(host,"rev-parse","HEAD")!=HOST_SHA:
            raise RuntimeError("HOST exact signed verifier source SHA changed")
        cls.hostcas=load("core_signed_host_cas",
                         host/"bridge/neurofactory/trusted_host/offline_cas.py")
        cls.hosteffect=load("core_signed_host_effect",
                          host/"bridge/neurofactory/trusted_host/offline_effect_reservation.py")
        cls.verifier=load("core_signed_host_permit",
                          host/"bridge/neurofactory/trusted_host/signed_effect_permit.py")
        with prior.connect() as c:
            c.execute((host/"bridge/neurofactory/trusted_host/schema_v1.sql").read_text())
            c.execute((host/"bridge/neurofactory/trusted_host/offline_effect_reservation_schema.sql").read_text())

    def setUp(self):
        super().setUp()
        self.signed_bridge=SignedScopeFixtureBridge(
            self.core,self.gate,self.verifier.inspect_signed_effect_permit)
        self.signer=Ed25519PrivateKey.generate()  # TEST ONLY, never saved.
        self.trusted_key=self.signer.public_key()
        self.now_unix=int(time.time())
        self.scope_base=dict(
            issuer_id="ephemeral-test-issuer",
            key_id="one-use-test-key",
            owner_id="sandbox-fixture-owner",
            repository="DSLitvinov1/my_first_repo",
        )

    def packet_for(self,claim,**changes):
        token_digest=hashlib.sha256(claim["fencing_token"].encode()).hexdigest()
        current=dict(
            schema="neurofactory.trusted_host.signed_effect_permit.v1",
            purpose="EFFECT_RESERVATION_SCOPE_ONLY",
            **self.scope_base,
            project_id=self.spec["project_id"],
            task_id=prior.TASK,
            worker_id=prior.WORKER,
            source_sha40=self.spec["source_sha"],
            source_file_sha256=self.spec["source_sha256"],
            input_task_sha256=hashlib.sha256(
                prior.one_task_core._canonical(self.spec)).hexdigest(),
            policy_sha256=prior.POLICY,
            target=prior.TARGET,
            proposed_content_sha256=self.proposal["content_sha256"],
            fencing_token_sha256=token_digest,
            lease_epoch=claim["lease_epoch"],
            issued_unix=self.now_unix-1,
            expires_unix=self.now_unix+45,
            idempotency_key=secrets.token_hex(32),
            operation_id="synthetic-one-operation",
        )
        current.update(changes)
        encoded=json.dumps(current,sort_keys=True,separators=(",",":"),
                           ensure_ascii=True,allow_nan=False).encode("ascii")
        return {
           "payload":current,
           "signature_base64":base64.b64encode(self.signer.sign(encoded)).decode("ascii"),
        }

    @staticmethod
    def expected(packet):
        return {k:v for k,v in packet["payload"].items() if k not in
                ("schema","purpose","issued_unix","expires_unix")}

    def signed_call(self,claimed,packet=None,**changes):
        if packet is None:
            packet=self.packet_for(claimed)
        args=dict(signed_packet=packet,
                  externally_pinned_key=self.trusted_key,
                  trusted_scope=self.expected(packet),
                  host_claim=claimed,
                  core_token=self.local["token"],
                  proposal=self.proposal,worker_id=prior.WORKER,
                  policy_sha256=prior.POLICY,
                  idempotency_key=packet["payload"]["idempotency_key"],
                  operation_id=packet["payload"]["operation_id"],
                  now_unix=self.now_unix,
                  core_test_now=101)
        args.update(changes)
        return self.signed_bridge.apply_signed_test_once(**args)

    def test_signed_positive_ONE_inert_file_no_model(self):
        claim=self.claim()
        packet=self.packet_for(claim)
        receipt=self.signed_call(claim,packet)
        out=self.core.sandbox/prior.TARGET
        self.assertEqual(out.read_bytes(),self.proposal["content"].encode())
        self.assertEqual(self.core.snapshot()["state"],"CHECKPOINTED_TEST")
        self.assertEqual(self.core.snapshot()["attempts"],1)
        self.assertFalse(receipt["model_invoked"])
        self.assertFalse(receipt["published"])
        self.assertEqual(receipt["api_cost_usd"],0)
        self.assertEqual(self.c.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0],1)
        with self.assertRaises((SignedScopeFixtureError,prior.FencedOfflineBoundaryError)):
            self.signed_call(claim,packet)
        self.assertEqual(self.c.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0],1)
        print("NF_SIGNED_SCOPE_EPHEMERAL_ONE_FILE=PASS_NO_LIVE_AUTHORITY")

    def test_host_BLOCKED_pre_effect_zero_write(self):
        claim=self.claim()
        self.c.execute("UPDATE nf_task SET phase='BLOCKED' WHERE task_id=%s",
                       (prior.TASK,))
        with self.assertRaises(prior.FencedOfflineBoundaryError):
            self.signed_call(claim)
        self.no_write()

    def test_host_UNKNOWN_pre_effect_zero_write(self):
        claim=self.claim()
        self.assertTrue(self.cas.mark_unknown(
            prior.TASK,prior.WORKER,claim["lease_epoch"],claim["fencing_token"]))
        with self.assertRaises(prior.FencedOfflineBoundaryError):
            self.signed_call(claim)
        self.no_write()

    def test_expired_database_lease_and_signed_time_zero_write(self):
        claim=self.claim()
        self.c.execute("UPDATE nf_task SET lease_deadline=clock_timestamp()-"
                       "interval '4 seconds' WHERE task_id=%s",(prior.TASK,))
        with self.assertRaises(prior.FencedOfflineBoundaryError):
            self.signed_call(claim)
        self.no_write()
        self.assertEqual(self.c.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0],0)
        # Fresh fixture in independent scenario below tests signed expiry.
    
    def test_stale_worker_epoch_and_fence_zero_write(self):
        claim=self.claim()
        for changed in (
            {"worker_id":"stale-worker"},
            {"lease_epoch":claim["lease_epoch"]+1},
            {"fencing_token_sha256":"f"*64},
        ):
            with self.subTest(changed=changed):
                packet=self.packet_for(claim,**changed)
                with self.assertRaises(SignedScopeFixtureError):
                    self.signed_call(claim,packet)
        self.no_write()

    def test_consumed_idempotency_and_duplicate_zero_write(self):
        claim=self.claim()
        packet=self.packet_for(claim)
        values=packet["payload"]
        reserved=self.gate.reserve_once(
            task_id=prior.TASK, project_id=self.spec["project_id"],
            source_sha40=self.spec["source_sha"],
            source_file_sha256=self.spec["source_sha256"],
            input_task_sha256=values["input_task_sha256"],
            target=prior.TARGET,policy_sha256=prior.POLICY,
            worker_id=prior.WORKER,
            lease_epoch=claim["lease_epoch"],
            fencing_token=claim["fencing_token"],
            idempotency_key=values["idempotency_key"])
        self.assertEqual(reserved["status"],"RESERVED_OFFLINE_TEST_ONLY")
        with self.assertRaises(prior.FencedOfflineBoundaryError):
            self.signed_call(claim,packet)
        self.no_write()
        self.assertEqual(self.c.execute(
            "SELECT count(*) FROM nf_effect_intent").fetchone()[0],1)

    def test_wrong_signer_forged_signature_zero_write(self):
        claim=self.claim()
        packet=self.packet_for(claim)
        forged=dict(packet)
        forged["signature_base64"]=base64.b64encode(
            Ed25519PrivateKey.generate().sign(b"not operator scope")
        ).decode()
        with self.assertRaises(SignedScopeFixtureError):
            self.signed_call(claim,forged)
        self.no_write()

    def test_valid_signature_but_wrong_owner_repo_and_target_zero_write(self):
        claim=self.claim()
        for changed in (
            {"owner_id":"attacker-owner"},
            {"repository":"Attacker/other_repo"},
            {"target":"bridge/neurofactory/development/core_owned/wrong.py"},
            {"proposed_content_sha256":"e"*64},
            {"input_task_sha256":"e"*64},
            {"policy_sha256":"e"*64},
        ):
            with self.subTest(changed=changed):
                packet=self.packet_for(claim,**changed)
                # Even if scope is entirely client-supplied and self-matching,
                # the live local source/proposal binding detects most changes;
                # owner/repo still depend on independent actual trust anchor.
                if "owner_id" in changed or "repository" in changed:
                    with self.assertRaises(SignedScopeFixtureError):
                        self.signed_call(claim,packet,
                            trusted_scope=self.expected(self.packet_for(claim)))
                else:
                    with self.assertRaises(SignedScopeFixtureError):
                        self.signed_call(claim,packet)
        self.no_write()

    def test_expired_signed_permit_refused(self):
        claim=self.claim()
        packet=self.packet_for(claim,issued_unix=self.now_unix-61,
                               expires_unix=self.now_unix-1)
        with self.assertRaises(SignedScopeFixtureError):
            self.signed_call(claim,packet)
        self.no_write()

    def test_unprotected_legacy_local_token_still_denied(self):
        with self.assertRaisesRegex(prior.one_task_core.CoreSafetyError,
                                    "LEGACY_WRITE_DISABLED"):
            self.core.apply_offline_test(
                prior.TASK,self.local["token"],self.proposal,now=101)
        self.no_write()

if __name__=="__main__":
    unittest.main()
