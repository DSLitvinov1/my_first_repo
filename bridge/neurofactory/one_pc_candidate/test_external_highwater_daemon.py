"""CI-only persistent witness daemon tests; no real deployment or keys."""
from __future__ import annotations
import json
import os
from pathlib import Path
import secrets
import socket
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from external_highwater_daemon import (
    DaemonDenied,parse_operator_config,serve_bound_service,
)
from external_highwater_mtls_server import (
    _operator_tls_server_context, _load_private_witness_signer,
)
from external_highwater_store import inspect_external_highwater
from remote_highwater_client import observe_remote_reservation,RemoteHighwaterDenied

def sample_config(address="10.40.17.3",port=16373):
    return {
        "schema":"nf.witness.vps.operator_config.v1",
        "listen_address":address,
        "port":port,
        "witness_id":"witness-operator-node",
        "client_der_sha256":"a"*64,
        "server_der_sha256":"b"*64,
        "witness_public_sha256":"c"*64,
        "machine_sha256":"d"*64,
        "package_sha256":"e"*64,
        "source_sha40":"f"*40,
    }

class LinuxWitnessConfigStrictTest(unittest.TestCase):
    def test_private_vpn_addresses_only(self):
        for a in ("10.4.0.5","172.16.1.20","192.168.1.15"):
            with self.subTest(a=a):
                x=parse_operator_config(json.dumps(sample_config(a)).encode())
                self.assertEqual(x["listen_address"],a)
        for a in ("127.0.0.1","0.0.0.0","::","8.8.8.8","169.254.5.3","100.64.0.1"):
            with self.subTest(a=a),self.assertRaises(DaemonDenied):
                parse_operator_config(json.dumps(sample_config(a)).encode())
    def test_reject_weak_or_duplicate_authority_pins(self):
        good=json.dumps(sample_config(),separators=(",",":"))
        with self.assertRaises(DaemonDenied):
            parse_operator_config(good[:-1]+',"package_sha256":"'+'a'*64+'"}')
        for key,value in (
            ("witness_public_sha256","0"*63),
            ("client_der_sha256",None),
            ("port",True),
            ("source_sha40","x"*40),
            ("witness_id","/root/.ssh"),
        ):
            bad=sample_config();bad[key]=value
            with self.subTest(key=key),self.assertRaises(DaemonDenied):
                parse_operator_config(json.dumps(bad).encode())
    def test_unit_has_separate_identity_persistent_storage_and_auto_recovery(self):
        unit=Path(__file__).parent/"vps_witness_systemd"/"neurofactory-witness.service"
        text=unit.read_text(encoding="utf-8")
        for setting in (
            "User=neurofactory-witness",
            "Group=neurofactory-witness",
            "Restart=on-failure",
            "RestartSec=5s",
            "ProtectSystem=strict",
            "NoNewPrivileges=yes",
            "StateDirectory=neurofactory-witness",
            "IPAddressDeny=any",
            "ExecStartPre=",
            "ExecStart=",
        ):
            self.assertIn(setting,text)
        self.assertNotIn("Environment=NF_",text)

class RealPersistentTLSServiceTest(unittest.TestCase):
    def setUp(self):
        # Reuse previous genuine TLS1.3 cert/CA+SQLite fixture, without
        # importing its TestCase at module scope (to avoid duplicate tests).
        import test_external_highwater_mtls_server as fixtures
        self.existing=fixtures.MutualTLSDurableWitnessTest(
            "test_real_mutual_tls_remote_sqlite_commit_signed_ack")
        self.existing.setUp()
        self.base=fixtures
    def tearDown(self):
        self.existing.tearDown()
    def test_three_connections_two_fresh_transactions_one_replay_denied(self):
        if os.name!="posix" or os.geteuid()==0 or os.getenv("RUNNER_ENVIRONMENT")!="github-hosted":
            self.skipTest("hosted Linux non-root CI test")
        x=self.existing
        cfg=sample_config("127.0.0.1")
        cfg.update(
            witness_id="separate-test-node",
            machine_sha256=x.machine,package_sha256=x.package,
            source_sha40=x.source,client_der_sha256=x.client_sha,
            server_der_sha256=x.cert_sha,
        )
        import hashlib
        from cryptography.hazmat.primitives import serialization
        raw=x.witness_signer.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        cfg["witness_public_sha256"]=hashlib.sha256(raw).hexdigest()
        listener=socket.socket()
        listener.bind(("127.0.0.1",0))
        port=listener.getsockname()[1]
        listener.close()
        cfg["port"]=port
        context=_operator_tls_server_context(
            x.server_certfile,x.server_keyfile,x.ca_file)
        signer=_load_private_witness_signer(x.witness_file)
        ready=threading.Event();stopping=threading.Event()
        outcome={}
        from external_highwater_daemon import parse_operator_config as real_parse
        # Production parsing NEVER bypasses the RFC1918 only restriction.
        # In this disposable non-root hosted CI fixture only, localhost
        # provides a real TCP+mutual TLS test socket without external access.
        def fixture_parse(raw,*,enforce_private_bind=True):
            return real_parse(raw,enforce_private_bind=False)
        def run():
            try:
                with patch("external_highwater_daemon.parse_operator_config",
                           side_effect=fixture_parse):
                    outcome.update(serve_bound_service(
                        settings=cfg,db=x.db,signer=signer,ssl_context=context,
                        stop_event=stopping,ready_callback=ready.set))
            except Exception as e:
                outcome["exception"]=type(e).__name__+":"+str(e)
        t=threading.Thread(target=run,daemon=True);t.start()
        self.assertTrue(ready.wait(6),"persistent witness never accepted socket")
        orig=socket.create_connection
        try:
            for iteration in (1,1,2):
                claim=x.claim.copy()
                claim["external_epoch"]=iteration
                if iteration==2:
                    claim["nonce"]=secrets.token_hex(32)
                    claim["operation_sha256"]=self.base.digest(b"another operation")
                with patch("remote_highwater_client.socket.create_connection",
                    side_effect=lambda addr,timeout:orig(("127.0.0.1",port),timeout)), \
                     patch("remote_highwater_client._verified_public_peer",return_value=None):
                    fn=lambda:observe_remote_reservation(
                        hostname="witness.test.invalid",port=port,claim=claim,
                        ca_path=x.ca_file,client_cert_path=x.client_certfile,
                        client_key_path=x.client_keyfile,
                        independently_pinned_server_der_sha256=x.cert_sha,
                        independently_pinned_witness_public=x.witness_signer.public_key(),
                        independently_pinned_witness_id="separate-test-node",
                        independently_observed_minimum_epoch=iteration,
                        now_unix=int(time.time()))
                    if iteration==1 and inspect_external_highwater(x.db)["highest_committed_epoch"]==1:
                        with self.assertRaises(RemoteHighwaterDenied):
                            fn()
                    else:
                        record=fn()
                        self.assertEqual(record["highwater_epoch"],iteration)
                        self.assertFalse(record["host_effect_allowed"])
        finally:
            stopping.set()
            t.join(timeout=8)
        self.assertFalse(t.is_alive())
        self.assertNotIn("exception",outcome)
        self.assertEqual(outcome["accepted"],2)
        audit=inspect_external_highwater(x.db)
        self.assertEqual(audit["highest_committed_epoch"],2)
        self.assertEqual(audit["reserved_operations"],2)

if __name__=="__main__":
    unittest.main()
