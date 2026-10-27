"""Synthetic witness receipt, fake network exchange. No real server or keys."""
import base64
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import secrets
import socket
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from independent_witness_receipt import _DOMAIN, _canonical
from remote_highwater_client import (
    observe_remote_reservation,RemoteHighwaterDenied,_verified_public_peer,
    _operator_file,
)

def digest(s):
    return sha256(s.encode("ascii")).hexdigest()

class RemoteHighwaterTrustBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.now=int(time.time())
        self.key=Ed25519PrivateKey.generate()
        self.claim={
            "schema":"nf.onepc.highwater.claim.v1",
            "source_sha40":"a"*40,
            "package_sha256":digest("signed installer hash"),
            "machine_identity_sha256":digest("independently pinned machine"),
            "review_evidence_sha256":digest("signed reviewer verdict fixture"),
            "operation_sha256":digest("one explicitly permitted operation"),
            "external_epoch":19,
            "nonce":secrets.token_hex(32),
        }
        self.evidence={
            "schema":"nf.onepc.external_witness.highwater.v1",
            "claim_sha256":sha256(_canonical(self.claim)).hexdigest(),
            "source_sha40":self.claim["source_sha40"],
            "machine_identity_sha256":self.claim["machine_identity_sha256"],
            "witness_id":"independent-test-remote",
            "highest_committed_epoch":19,
            "previous_accepted_epoch":18,
            "recorded_unix":self.now-3,
            "expires_unix":self.now+50,
            "decision":"RECORDED_EXTERNALLY_NO_AUTO_RETRY",
            "separate_device_claimed":True,
        }
    def packet(self,evidence=None, signer=None):
        e=self.evidence if evidence is None else evidence
        k=self.key if signer is None else signer
        return {"evidence":deepcopy(e),"signature_base64":
                base64.b64encode(k.sign(_DOMAIN+_canonical(e))).decode("ascii")}
    def invoke(self,packet=None,**changes):
        args=dict(hostname="witness.example.invalid",port=443,
                  claim=self.claim,
                  ca_path=Path("/separately-owned/root-ca.pem"),
                  client_cert_path=Path("/separately-owned/client.pem"),
                  client_key_path=Path("/separately-owned/client.key"),
                  independently_pinned_server_der_sha256="d"*64,
                  independently_pinned_witness_public=self.key.public_key(),
                  independently_pinned_witness_id="independent-test-remote",
                  independently_observed_minimum_epoch=19,now_unix=self.now)
        args.update(changes)
        with patch("remote_highwater_client._wire_exchange",
                   return_value=self.packet() if packet is None else packet) as x:
            result=observe_remote_reservation(**args)
            self.assertEqual(x.call_count,1)
            return result
    def denied(self,receipt=None,**changes):
        with self.assertRaises(RemoteHighwaterDenied):
            self.invoke(packet=receipt,**changes)
    def test_signed_remote_observation_does_not_grant_service_execution(self):
        v=self.invoke()
        self.assertTrue(v["tls_authenticated_with_pinned_certificate"])
        self.assertTrue(v["signed_receipt_verified"])
        self.assertEqual(v["highwater_epoch"],19)
        self.assertFalse(v["external_rollback_protection_proven"])
        self.assertFalse(v["host_effect_allowed"])
        self.assertFalse(v["production_service_install_allowed"])
        self.assertFalse(v["retry_after_unknown_allowed"])
    def test_forged_key_refused(self):
        self.denied(self.packet(signer=Ed25519PrivateKey.generate()))
    def test_expired_replay_refused(self):
        self.denied(self.packet({**self.evidence,"expires_unix":self.now}))
    def test_downgrade_highwater_refused(self):
        self.denied(self.packet({**self.evidence,
                                  "highest_committed_epoch":18}))
        self.denied(independently_observed_minimum_epoch=20)
    def test_different_machine_or_task_refused(self):
        self.denied(claim={**self.claim,
                           "machine_identity_sha256":digest("another machine")})
        self.denied(claim={**self.claim,
                           "operation_sha256":digest("another action")})
        self.denied(claim={**self.claim,"nonce":secrets.token_hex(32)})
    def test_wrong_witness_identity_refused(self):
        self.denied(independently_pinned_witness_id="other")
    def test_timeout_no_auto_retry(self):
        params=dict(hostname="witness.example.invalid",port=443,claim=self.claim,
                    ca_path=Path("/ca.pem"),client_cert_path=Path("/client.pem"),
                    client_key_path=Path("/client.key"),
                    independently_pinned_server_der_sha256="c"*64,
                    independently_pinned_witness_public=self.key.public_key(),
                    independently_pinned_witness_id="independent-test-remote",
                    independently_observed_minimum_epoch=19,now_unix=self.now)
        with patch("remote_highwater_client._wire_exchange",
                   side_effect=RemoteHighwaterDenied("simulated unknown")) as x:
            with self.assertRaises(RemoteHighwaterDenied):
                observe_remote_reservation(**params)
            self.assertEqual(x.call_count,1)
    def test_localhost_and_unpinned_ip_denied(self):
        for value in (("127.0.0.1",443),("::1",443),
                      ("169.254.1.1",443),("0.0.0.0",443)):
            with self.subTest(value=value), self.assertRaises(RemoteHighwaterDenied):
                _verified_public_peer(value)
        _verified_public_peer(("192.168.50.2",443)) # private VLAN allowed if separately controlled
    def test_symlink_operator_cert_denied(self):
        import tempfile
        with tempfile.TemporaryDirectory() as dir:
            root=Path(dir).resolve()
            secret=root/"cert.pem"
            secret.write_bytes(b"test")
            link=root/"link.pem"
            link.symlink_to(secret)
            with self.assertRaises(RemoteHighwaterDenied):
                _operator_file(link)
    def test_untrusted_client_keys_not_from_signed_network_response(self):
        self.denied(self.packet({**self.evidence,
                                   "decision":"AUTHORIZE_TASK"}))
        self.denied(self.packet({**self.evidence,
                                   "separate_device_claimed":False}))

if __name__=="__main__":
    unittest.main()
