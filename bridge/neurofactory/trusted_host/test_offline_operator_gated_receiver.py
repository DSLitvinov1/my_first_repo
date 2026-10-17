"""Fail-closed test-only boundary between signer socket and actual HOST receiver.

This suite mocks only the socket transport / underlying already tested
PostgreSQL receiver so each new approval boundary condition is targeted;
it does not claim real production effects or owner authorization.
"""
import base64
import hashlib
import json
import os
from unittest import TestCase,main
from unittest.mock import patch
from offline_fenced_file_receiver import (
    OfflineFencedFileReceiver,OfflineReceiverDenied,OfflineEffectUnknown)
from offline_operator_gated_receiver import OperatorGatedOfflineReceiver

CONTENT=b"temporary file fixture only\n"
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(p):return json.dumps(p,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()

class OperatorGatedTests(TestCase):
    def setUp(self):
        self.env=patch.dict(os.environ,{
          "NF_HOST_RECEIVER_FIXTURE_ONLY":"1",
          "NF_OPERATOR_ANCHOR_FIXTURE_ONLY":"1"})
        self.env.start();self.addCleanup(self.env.stop)
        self.actual=object.__new__(OfflineFencedFileReceiver)
        self.p={
           "schema":"neurofactory.trusted_host.signed_effect_permit.v1",
           "purpose":"EFFECT_RESERVATION_SCOPE_ONLY",
           "issuer_id":"ephemeral-issuer","key_id":"issuer-key-test",
           "owner_id":"approved-fixture-owner","repository":"DSLitvinov1/my_first_repo",
           "project_id":"nf-sandbox","task_id":"NF-DEV-05-Q990",
           "worker_id":"allowed-worker-01","source_sha40":"a"*40,
           "source_file_sha256":"b"*64,"input_task_sha256":"c"*64,
           "policy_sha256":"d"*64,
           "target":"bridge/neurofactory/development/core_owned/guarded_test.txt",
           "proposed_content_sha256":sha(CONTENT),
           "fencing_token_sha256":"f"*64,"lease_epoch":7,
           "issued_unix":1800000000,"expires_unix":1800000060,
           "idempotency_key":"1"*64,"operation_id":"guarded-fixture-one"}
        self.packet={"payload":self.p,"signature_base64":base64.b64encode(b"0"*64).decode()}
        self.witness={"schema":"only a mocked IPC request fixture"}
        self.expected_report={
            "status":"OWNER_SCOPE_FIXTURE_MATCHED_NOT_AUTHORITY",
            "signed_permit_sha256":sha(canonical(self.p)),
            "operation_id":self.p["operation_id"],
            "current_signer_sequence":1,
            "peer_uid_checked":True,"private_key_shared":False,
            "owner_authenticated":False,"filesystem_write_allowed":False}
        self.underlying={
            "status":"ONE_FILE_COMPLETED_OFFLINE_TEST_ONLY",
            "content_sha256":sha(CONTENT),"live_execution_allowed":False}
        self.guard=OperatorGatedOfflineReceiver(
            self.actual,
            socket_path="/tmp/nf-operator-api/nf-readonly-operator.sock",
            pinned_signer_uid=2222,
            independently_pinned_public_sha="e"*64,
            independently_pinned_public_b64="test_public_key_fixture")
    def call(self,*,report=None,packet=None,data=CONTENT,side_effect=None):
        socket_patch=patch("offline_operator_gated_receiver.client_send",
                   side_effect=side_effect,
                   return_value=self.expected_report if report is None else report)
        ipc=socket_patch.start();self.addCleanup(socket_patch.stop)
        writer_patch=patch.object(OfflineFencedFileReceiver,"write_fixture_once",
                                  return_value=self.underlying)
        filewriter=writer_patch.start();self.addCleanup(writer_patch.stop)
        fn=lambda:self.guard.apply_fixture_with_operator_witness_once(
            signed_packet=self.packet if packet is None else packet,
            witness=self.witness,content=data)
        return fn,ipc,filewriter
    def test_scope_consented_still_nonlive_and_routes_exact_one_effect(self):
        fn,ipc,writer=self.call()
        r=fn()
        self.assertEqual(r["status"],"ONE_SIGNER_SCOPE_GATED_FIXTURE_FILE_ONLY")
        self.assertFalse(r["live_execution_allowed"])
        self.assertFalse(r["independent_human_owner_approved"])
        self.assertFalse(r["production_recipient_os_isolated"])
        ipc.assert_called_once()
        self.assertEqual(ipc.call_args.kwargs["pinned_signer_uid"],2222)
        writer.assert_called_once_with(signed_packet=self.packet,content=CONTENT,
                                       simulate_crash_after_fsync=False)
    def test_owner_project_worker_target_epoch_source_tampering_blocks_writer(self):
        for key,val in [("owner_id","forged-owner"),("repository","Bad/repo"),
                        ("project_id","other-project"),("worker_id","other-worker"),
                        ("lease_epoch",8),("source_sha40","8"*40),
                        ("target","bridge/neurofactory/development/core_owned/other.txt"),
                        ("operation_id","other-op")]:
            p=dict(self.p);p[key]=val
            fn,ipc,writer=self.call(packet=dict(self.packet,payload=p))
            with self.subTest(key=key),self.assertRaises(OfflineReceiverDenied):fn()
            writer.assert_not_called()
    def test_stale_signer_head_or_rollback_refused(self):
        fn,ipc,writer=self.call(report={"status":"DENIED_WITNESS"})
        with self.assertRaises(OfflineReceiverDenied):fn()
        writer.assert_not_called()
    def test_signer_disconnected_never_falls_back(self):
        fn,ipc,writer=self.call(side_effect=OSError("socket unavailable"))
        with self.assertRaises(OfflineReceiverDenied):fn()
        writer.assert_not_called()
    def test_fake_positive_escalation_response_denied(self):
        fake=dict(self.expected_report,filesystem_write_allowed=True)
        fn,ipc,writer=self.call(report=fake)
        with self.assertRaises(OfflineReceiverDenied):fn()
        writer.assert_not_called()
    def test_wrong_server_peer_uid_refused_by_client(self):
        fn,ipc,writer=self.call(side_effect=ValueError("UNTRUSTED_SIGNER_SERVER_UID"))
        with self.assertRaises(OfflineReceiverDenied):fn()
        writer.assert_not_called()
    def test_digest_or_issuer_return_mismatch_denies_effect(self):
        for value in ("0"*64,"f"*64):
            fake=dict(self.expected_report,signed_permit_sha256=value)
            fn,ipc,writer=self.call(report=fake)
            with self.assertRaises(OfflineReceiverDenied):fn()
            writer.assert_not_called()
    def test_wrong_bytes_never_call_signer_or_write(self):
        fn,ipc,writer=self.call(data=b"wrong candidate")
        with self.assertRaises(OfflineReceiverDenied):fn()
        ipc.assert_not_called()
        writer.assert_not_called()
    def test_existing_receiver_replay_denial_is_propagated(self):
        with patch("offline_operator_gated_receiver.client_send",
                   return_value=self.expected_report):
            with patch.object(OfflineFencedFileReceiver,"write_fixture_once",
                side_effect=OfflineReceiverDenied("replay blocked")):
                with self.assertRaises(OfflineReceiverDenied):
                    self.guard.apply_fixture_with_operator_witness_once(
                        signed_packet=self.packet,witness=self.witness,content=CONTENT)
    def test_receiver_crash_unknown_prevents_false_success(self):
        with patch("offline_operator_gated_receiver.client_send",
                   return_value=self.expected_report):
            with patch.object(OfflineFencedFileReceiver,"write_fixture_once",
                side_effect=OfflineEffectUnknown("manual reconciliation")):
                with self.assertRaises(OfflineEffectUnknown):
                    self.guard.apply_fixture_with_operator_witness_once(
                        signed_packet=self.packet,witness=self.witness,content=CONTENT)
    def test_absent_test_only_environment_rejects_construction(self):
        with patch.dict(os.environ,{"NF_HOST_RECEIVER_FIXTURE_ONLY":"0"}):
            with self.assertRaises(OfflineReceiverDenied):
                OperatorGatedOfflineReceiver(
                    self.actual,socket_path="/tmp/nf-operator-api/nf-readonly-operator.sock",
                    pinned_signer_uid=2222,
                    independently_pinned_public_sha="e"*64,
                    independently_pinned_public_b64="test_public_key_fixture")

if __name__=="__main__":main()
