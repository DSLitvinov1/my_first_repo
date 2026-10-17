"""Host author narrow negative tests. All keys and inputs ephemeral test fixtures."""
import base64
import copy
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_effect_permit import SignedEffectPermitError,inspect_signed_effect_permit

def fixture():
    private=Ed25519PrivateKey.generate()
    payload={
       "schema":"neurofactory.trusted_host.signed_effect_permit.v1",
       "purpose":"EFFECT_RESERVATION_SCOPE_ONLY",
       "issuer_id":"offline-test-issuer","key_id":"ephemeral-test-key",
       "owner_id":"sandbox-owner","repository":"DSLitvinov1/my_first_repo",
       "project_id":"nf-sandbox","task_id":"NF-DEV-05-Q972",
       "worker_id":"worker-sandbox-01","source_sha40":"a"*40,
       "source_file_sha256":"b"*64,"input_task_sha256":"c"*64,
       "policy_sha256":"d"*64,
       "target":"bridge/neurofactory/development/core_owned/fixture.py",
       "proposed_content_sha256":"e"*64,
       "fencing_token_sha256":"f"*64,
       "lease_epoch":7,"issued_unix":1800000000,"expires_unix":1800000060,
       "idempotency_key":"1"*64,"operation_id":"operation-one",
    }
    return private,payload

def signed(private,payload):
    b=json.dumps(payload,sort_keys=True,separators=(",",":"),
                 ensure_ascii=True,allow_nan=False).encode("ascii")
    return {"payload":copy.deepcopy(payload),
            "signature_base64":base64.b64encode(private.sign(b)).decode("ascii")}

def expected(payload):
    return {k:v for k,v in payload.items() if k not in
            ("schema","purpose","issued_unix","expires_unix")}

class SignedEffectPermitTests(unittest.TestCase):
    def setUp(self):
        self.private,self.payload=fixture()
        self.packet=signed(self.private,self.payload)
        self.public=self.private.public_key()
        self.expected=expected(self.payload)
    def check(self,packet=None,**kwargs):
        return inspect_signed_effect_permit(
            self.packet if packet is None else packet,
            externally_pinned_public_key=kwargs.get("key",self.public),
            trusted_expected_scope=kwargs.get("scope",self.expected),
            now_unix=kwargs.get("now",1800000012))
    def test_one_true_signature_and_exact_scope_still_never_grants_write(self):
        x=self.check()
        self.assertEqual(x["status"],"CRYPTO_SCOPE_MATCHES_NO_EXECUTION_AUTHORITY")
        self.assertTrue(x["cryptographic_signature_verified"])
        for field in ("protected_issuer_key_custody_attested",
                      "real_owner_rights_authenticated",
                      "independent_monotonic_epoch_protected",
                      "live_lease_authenticated","receiver_idempotency_enforced",
                      "filesystem_execution_allowed","publication_allowed",
                      "automatic_retry_allowed"):
            self.assertIs(x[field],False)
    def test_invalid_signature_from_different_signer(self):
        wrong=Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(SignedEffectPermitError):self.check(key=wrong)
    def test_modification_after_signature_refused(self):
        for field,value in (("worker_id","worker-attacker"),
            ("lease_epoch",8),("operation_id","another-operation"),
            ("target","bridge/neurofactory/development/core_owned/wrong.py"),
            ("owner_id","attacker-owner"),("source_sha40","9"*40),
            ("idempotency_key","9"*64),("expires_unix",1800000075),
            ("fencing_token_sha256","8"*64)):
            p=copy.deepcopy(self.packet)
            p["payload"][field]=value
            with self.subTest(field=field),self.assertRaises(SignedEffectPermitError):
                self.check(p)
    def test_validly_signed_wrong_expected_source_denied(self):
        for field,value in (("owner_id","attacker-owner"),
            ("repository","OtherUser/other_repo"),("project_id","wrong-project"),
            ("task_id","another-task"),("worker_id","stale-worker"),
            ("source_sha40","f"*40),("source_file_sha256","0"*64),
            ("input_task_sha256","0"*64),("policy_sha256","0"*64),
            ("target","bridge/neurofactory/development/core_owned/wrong.py"),
            ("lease_epoch",8),("idempotency_key","0"*64),
            ("operation_id","different-operation"),("key_id","different-key"),
            ("proposed_content_sha256","0"*64),("fencing_token_sha256","0"*64)):
            p=copy.deepcopy(self.payload);p[field]=value
            with self.subTest(field=field),self.assertRaises(SignedEffectPermitError):
                self.check(signed(self.private,p))
    def test_expired_and_not_yet_valid(self):
        for when in (1799999999,1800000060,1800000061,0):
            with self.subTest(when=when),self.assertRaises(SignedEffectPermitError):
                self.check(now=when)
    def test_missing_scope_fields_denied(self):
        p=copy.deepcopy(self.packet);p["payload"].pop("operation_id")
        with self.assertRaises(SignedEffectPermitError):self.check(p)
    def test_injected_permission_fields_denied_even_if_signed(self):
        p=copy.deepcopy(self.payload);p["execution_allowed"]=True
        with self.assertRaises(SignedEffectPermitError):
            self.check(signed(self.private,p))
    def test_wrong_purpose_denied_even_if_signed(self):
        p=copy.deepcopy(self.payload);p["purpose"]="AUTHORIZE_LIVE_FILESYSTEM_WRITE"
        with self.assertRaises(SignedEffectPermitError):
            self.check(signed(self.private,p))
    def test_windows_device_alias_denied(self):
        for name in ("CON.py","prn.md","AUX.txt","COM1.py","lpt9.json"):
            p=copy.deepcopy(self.payload)
            p["target"]="bridge/neurofactory/development/core_owned/"+name
            with self.subTest(name=name),self.assertRaises(SignedEffectPermitError):
                self.check(signed(self.private,p),scope=expected(p))
    def test_cross_project_traversal_denied(self):
        for path in ("../secrets.py","bridge/neurofactory/development/core_owned/a/../x.py",
                     "bridge/neurofactory/development/core_owned/.hidden.py",
                     "bridge/neurofactory/development/core_owned/a.exe"):
            p=copy.deepcopy(self.payload);p["target"]=path
            with self.subTest(path=path),self.assertRaises(SignedEffectPermitError):
                self.check(signed(self.private,p),scope=expected(p))
    def test_bool_epoch_and_timestamp_denied(self):
        for field in ("lease_epoch","issued_unix","expires_unix"):
            p=copy.deepcopy(self.payload);p[field]=True
            with self.subTest(field=field),self.assertRaises(SignedEffectPermitError):
                self.check(signed(self.private,p),scope=expected(p))
    def test_oversized_valid_signature_window_denied(self):
        p=copy.deepcopy(self.payload);p["expires_unix"]=p["issued_unix"]+301
        with self.assertRaises(SignedEffectPermitError):
            self.check(signed(self.private,p))
    def test_raw_signature_missing_or_bad_base64(self):
        for value in ("","?"*88,"a"*120,2,None):
            p=copy.deepcopy(self.packet);p["signature_base64"]=value
            with self.subTest(value=str(value)[:10]),self.assertRaises(SignedEffectPermitError):
                self.check(p)
    def test_caller_must_supply_all_external_expectations(self):
        p=copy.deepcopy(self.expected);p.pop("owner_id")
        with self.assertRaises(SignedEffectPermitError):self.check(scope=p)
    def test_signature_is_not_live_consent_even_with_fake_caller_values(self):
        # If an attacker controls BOTH expected scope and test signer, crypto
        # is still only a matching-format diagnostic, not permission.
        attacker=Ed25519PrivateKey.generate()
        p=copy.deepcopy(self.payload);p["owner_id"]="attacker-owner"
        x=self.check(signed(attacker,p),key=attacker.public_key(),scope=expected(p))
        self.assertFalse(x["filesystem_execution_allowed"])
        self.assertFalse(x["real_owner_rights_authenticated"])
        self.assertFalse(x["protected_issuer_key_custody_attested"])
    def test_input_arguments_are_not_modified(self):
        packet=copy.deepcopy(self.packet)
        scope=copy.deepcopy(self.expected)
        self.check()
        self.assertEqual(packet,self.packet)
        self.assertEqual(scope,self.expected)
    def test_unknown_reply_structure_denied(self):
        p=dict(self.packet,extra="approve")
        with self.assertRaises(SignedEffectPermitError):self.check(p)

if __name__=="__main__":
    unittest.main()
