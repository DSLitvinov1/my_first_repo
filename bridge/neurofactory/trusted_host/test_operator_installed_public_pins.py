"""No test environment can claim authorized operator pins or LIVE access."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from operator_installed_public_pins import (
    OperatorPinsDenied, _decode_exact_public_root,
    load_operator_installed_public_pins,
)

NOW = 1800000000


class OperatorRootTests(unittest.TestCase):
    def setUp(self):
        keys = [Ed25519PrivateKey.generate().public_key() for _ in range(4)]
        from cryptography.hazmat.primitives import serialization
        self.bytes = [k.public_bytes(serialization.Encoding.Raw,
                                     serialization.PublicFormat.Raw) for k in keys]
        self.body = dict(
            schema="neurofactory.operator.public_pins.v1",
            repository="DSLitvinov1/my_first_repo",
            github_user_id="151650108",
            repository_id="723328237",
            key_valid_from_unix=NOW-1,
            key_valid_until_unix=NOW+3600,
            operator_public_base64=base64.b64encode(self.bytes[0]).decode(),
            owner_public_base64=base64.b64encode(self.bytes[1]).decode(),
            host_public_base64=base64.b64encode(self.bytes[2]).decode(),
            witness_public_base64=base64.b64encode(self.bytes[3]).decode(),
            operator_public_sha256=hashlib.sha256(self.bytes[0]).hexdigest(),
            mtls_witness_cert_sha256=hashlib.sha256(b"synthetic TLS cert").hexdigest(),
        )

    def serialized(self, body=None):
        return json.dumps(self.body if body is None else body,
                          sort_keys=True,ensure_ascii=True,
                          separators=(",",":")).encode("ascii")

    def decode(self,body=None,now=NOW):
        return _decode_exact_public_root(self.serialized(body),now_unix=now)

    def test_four_distinct_operator_pins_can_be_parsed_but_not_deployed(self):
        res=self.decode()
        self.assertEqual(set(res["pinned_keys"]),{"operator","owner","host","witness"})
        self.assertEqual(res["metadata"]["repository"],"DSLitvinov1/my_first_repo")
        self.assertFalse(res["metadata"]["live_execution_allowed"])
        self.assertFalse(res["metadata"]["release_approved"])
        self.assertFalse(res["metadata"]["physical_node_attested_by_loader"])

    def test_missing_root_key_file_is_not_silently_provisioned(self):
        with patch("operator_installed_public_pins.TRUST_DIR",
                   Path("/etc/neurofactory/test-never-existing-pins")):
            with self.assertRaises(OperatorPinsDenied):
                load_operator_installed_public_pins()

    def test_user_env_cannot_install_fake_trust_root(self):
        with patch.dict(os.environ,{"NF_OPERATOR_ANCHOR_FIXTURE_ONLY":"1"}):
            with self.assertRaises(OperatorPinsDenied):
                load_operator_installed_public_pins()

    def test_changed_key_unknown_signer_and_reused_roles_denied(self):
        for field,value in (
            ("owner_public_base64",self.body["operator_public_base64"]),
            ("host_public_base64",self.body["owner_public_base64"]),
            ("operator_public_sha256","f"*64),
            ("witness_public_base64","?"*44),
        ):
            with self.subTest(field=field):
                with self.assertRaises(OperatorPinsDenied):
                    self.decode({**self.body,field:value})

    def test_unapproved_extra_field_and_missing_field_denied(self):
        with self.assertRaises(OperatorPinsDenied):
            self.decode({**self.body,"release_approved":True})
        d=dict(self.body)
        d.pop("operator_public_base64")
        with self.assertRaises(OperatorPinsDenied):
            self.decode(d)

    def test_expired_and_overlong_keys_denied(self):
        for field,value in (
            ("key_valid_until_unix",NOW),
            ("key_valid_until_unix",NOW+91*86400),
            ("key_valid_from_unix",NOW+10),
            ("key_valid_from_unix",True),
        ):
            with self.subTest(field=field):
                with self.assertRaises(OperatorPinsDenied):
                    self.decode({**self.body,field:value})

    def test_private_key_or_credential_in_pin_document_denied(self):
        for marker in (b"BEGIN PRIVATE KEY",b"api_token",b"password"):
            with self.subTest(marker=marker):
                encoded=self.serialized()
                with self.assertRaises(OperatorPinsDenied):
                    _decode_exact_public_root(encoded+b"\n"+marker,now_unix=NOW)

    def test_invalid_numeric_repo_id_and_wrong_schema_denied(self):
        for field,value in (
            ("github_user_id","0"),
            ("repository_id",True),
            ("repository","repo-wrong-format"),
            ("schema","neurofactory.owner.key.fixture.v1"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(OperatorPinsDenied):
                    self.decode({**self.body,field:value})

    def test_bounded_document_rejects_junk_and_forged_approval(self):
        for data in (b"{}",b"\x00"*600,b"X"*10000):
            with self.subTest(size=len(data)):
                with self.assertRaises(OperatorPinsDenied):
                    _decode_exact_public_root(data,now_unix=NOW)

    def test_invalid_boolean_now_rejected(self):
        with self.assertRaises(OperatorPinsDenied):
            self.decode(now=True)


if __name__ == "__main__":
    unittest.main()
