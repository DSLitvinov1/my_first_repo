"""Real TLS1.3 mutual-auth loopback handshake, ephemeral certs + durable DB only.

This is a single hosted CI machine; it cannot attest physical separation.
"""
import datetime
import hashlib
import os
from pathlib import Path
import secrets
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

from external_highwater_store import provision_empty_database, inspect_external_highwater
from external_highwater_mtls_server import serve_once
from remote_highwater_client import observe_remote_reservation, RemoteHighwaterDenied

def digest(data):
    return hashlib.sha256(data).hexdigest()

def selfsigned_ca():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.datetime.now(datetime.timezone.utc)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"NF CI isolated witness CA")])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(minutes=2))
          .not_valid_after(now+datetime.timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
          .sign(key,hashes.SHA256()))
    return key,cert

def issued(ca_key,ca_cert,*,client):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.datetime.now(datetime.timezone.utc)
    fqdn="nf-cli.test.invalid" if client else "witness.test.invalid"
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,fqdn)])
    eku=ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
    cert=(x509.CertificateBuilder().subject_name(name)
        .issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now-datetime.timedelta(minutes=2))
        .not_valid_after(now+datetime.timedelta(hours=1))
        .add_extension(x509.ExtendedKeyUsage([eku]),critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn)]),critical=False)
        .sign(ca_key,hashes.SHA256()))
    return key,cert

def write(path,raw):
    path.write_bytes(raw)
    path.chmod(0o600)
    return path

def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())

class MutualTLSDurableWitnessTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name).resolve()
        self.ca_key,self.ca=self.get_ca()
        self.server_key,self.server_cert=issued(self.ca_key,self.ca,client=False)
        self.client_key,self.client_cert=issued(self.ca_key,self.ca,client=True)
        self.ca_file=write(self.root/"ca.pem",self.ca.public_bytes(serialization.Encoding.PEM))
        self.server_certfile=write(self.root/"server.pem",self.server_cert.public_bytes(serialization.Encoding.PEM))
        self.server_keyfile=write(self.root/"server.key",private_pem(self.server_key))
        self.client_certfile=write(self.root/"client.pem",self.client_cert.public_bytes(serialization.Encoding.PEM))
        self.client_keyfile=write(self.root/"client.key",private_pem(self.client_key))
        self.witness_signer=Ed25519PrivateKey.generate()
        self.witness_file=write(self.root/"witness-private.key",
            self.witness_signer.private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,serialization.NoEncryption()))
        self.db=self.root/"remote-ledger.sqlite3"
        provision_empty_database(self.db)
        self.machine=digest(b"operator-pinned-physical-node-fixture")
        self.package=digest(b"operator-pinned-release-fixture")
        self.source="b"*40
        self.claim={
            "schema":"nf.onepc.highwater.claim.v1",
            "source_sha40":self.source,
            "package_sha256":self.package,
            "machine_identity_sha256":self.machine,
            "review_evidence_sha256":digest(b"synthetic-review"),
            "operation_sha256":digest(b"synthetic-permitted-op"),
            "external_epoch":1,"nonce":secrets.token_hex(32)}
        self.cert_sha=digest(self.server_cert.public_bytes(serialization.Encoding.DER))
        self.client_sha=digest(self.client_cert.public_bytes(serialization.Encoding.DER))
    @staticmethod
    def get_ca():
        return selfsigned_ca()
    def tearDown(self):
        self.temp.cleanup()
    def test_real_mutual_tls_remote_sqlite_commit_signed_ack(self):
        if os.name!="posix" or os.geteuid()==0:
            self.skipTest("non-root isolated Linux CI required")
        # localhost is allowed in the SERVER only in CI: the actual deployed
        # client rejects localhost, and this test patches just that check.
        os.environ["NF_EXTERNAL_WITNESS_EPHEMERAL_CI"]="1"
        port_holder=socket.socket()
        port_holder.bind(("127.0.0.1",0))
        port=port_holder.getsockname()[1]
        port_holder.close()
        ready=threading.Event()
        result={}
        def remote_server():
            try:
                result["reply"]=serve_once(
                    listen_address="127.0.0.1",port=port,
                    server_cert=self.server_certfile,server_key=self.server_keyfile,
                    trusted_clients_ca=self.ca_file,
                    pinned_client_der_sha256=self.client_sha,
                    db=self.db,witness_private_key=self.witness_file,
                    witness_id="separate-test-node",
                    machine_sha256=self.machine,package_sha256=self.package,
                    source_sha40=self.source,ready_callback=ready.set)
            except Exception as e:
                result["exception"]=e
        t=threading.Thread(target=remote_server,daemon=True)
        t.start()
        self.assertTrue(ready.wait(5),"live mTLS witness did not open listener")
        real_connect=socket.create_connection
        try:
            with patch("remote_highwater_client.socket.create_connection",
                       side_effect=lambda addr,timeout:real_connect(("127.0.0.1",port),timeout)), \
                 patch("remote_highwater_client._verified_public_peer",return_value=None):
                observed=observe_remote_reservation(
                    hostname="witness.test.invalid",port=port,
                    claim=self.claim,ca_path=self.ca_file,
                    client_cert_path=self.client_certfile,
                    client_key_path=self.client_keyfile,
                    independently_pinned_server_der_sha256=self.cert_sha,
                    independently_pinned_witness_public=self.witness_signer.public_key(),
                    independently_pinned_witness_id="separate-test-node",
                    independently_observed_minimum_epoch=1,
                    now_unix=int(time.time()))
            self.assertFalse(observed["host_effect_allowed"])
            self.assertTrue(observed["tls_authenticated_with_pinned_certificate"])
            self.assertTrue(observed["signed_receipt_verified"])
            self.assertFalse(observed["external_rollback_protection_proven"])
        finally:
            t.join(timeout=7)
            os.environ.pop("NF_EXTERNAL_WITNESS_EPHEMERAL_CI",None)
        self.assertNotIn("exception",result)
        self.assertEqual(result["reply"]["status"],"DURABLY_RESERVED_AND_SIGNED_NO_TASK_EXECUTION")
        self.assertEqual(inspect_external_highwater(self.db)["highest_committed_epoch"],1)
        self.assertEqual(inspect_external_highwater(self.db)["reserved_operations"],1)

if __name__=="__main__":
    unittest.main()
