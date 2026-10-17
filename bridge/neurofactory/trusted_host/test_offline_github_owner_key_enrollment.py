"""Seven isolated Ed25519 owner-proof tests; only temporary private test keys."""
import base64,hashlib,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from offline_github_owner_key_enrollment import seal_owner_key,EnrollmentDenied,canon,DOMAIN
def pub(k):return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def b64(x):return base64.b64encode(x).decode()
def sha(x):return hashlib.sha256(x).hexdigest()
class EnrollmentProofTests(unittest.TestCase):
    def setUp(self):
        self.now=1800000000
        self.operator=Ed25519PrivateKey.generate()
        self.owner=Ed25519PrivateKey.generate()
        self.snapshot={"schema":"neurofactory.github_acl_operator_snapshot.v1",
          "github_login":"DSLitvinov1","github_user_id":"151650108",
          "repository_full_name":"DSLitvinov1/my_first_repo",
          "repository_id":"723328237","repository_owner_user_id":"151650108",
          "permission":"admin","checked_unix":self.now-5,
          "valid_until_unix":self.now+170,
          "source":"AUTHENTICATED_GITHUB_API_OBSERVED_BY_OPERATOR",
          "operator_id":"operator-authorized-fixture","project_id":"nf-sandbox",
          "scope_sha256":sha(b"limited synthetic project")}
        self.challenge={"schema":"neurofactory.owner_possession_challenge.v1",
          "nonce_sha256":sha(b"synthetic challenge nonce"),
          "github_user_id":"151650108","repository_id":"723328237",
          "github_login":"DSLitvinov1","project_id":"nf-sandbox",
          "scope_sha256":self.snapshot["scope_sha256"],
          "owner_public_key_sha256":sha(pub(self.owner)),
          "operator_snapshot_sha256":sha(canon(self.snapshot)),
          "expires_unix":self.now+120}
    def check(self,**changes):
        d={"operator_public_b64":b64(pub(self.operator)),
          "operator_public_sha256":sha(pub(self.operator)),
          "snapshot":self.snapshot,
          "operator_signature_b64":b64(self.operator.sign(DOMAIN+b"OPERATOR_SNAPSHOT"+bytes([0])+canon(self.snapshot))),
          "challenge":self.challenge,
          "owner_signature_b64":b64(self.owner.sign(DOMAIN+b"OWNER_PROOF"+bytes([0])+canon(self.challenge))),
          "owner_public_b64":b64(pub(self.owner)),
          "nonce_already_used":False,"now":self.now}
        d.update(changes)
        return seal_owner_key(**d)
    def test_valid_fixture_no_live_permission(self):
        x=self.check()
        self.assertEqual(x["repository_id"],"723328237")
        self.assertFalse(x["production_authorization"])
        self.assertFalse(x["actual_independent_operator_enrolled"])
    def test_forged_operator_signature_denied(self):
        key=Ed25519PrivateKey.generate()
        with self.assertRaises(EnrollmentDenied):
            self.check(operator_signature_b64=b64(key.sign(b"incorrect")))
    def test_changed_github_permission_denied(self):
        with self.assertRaises(EnrollmentDenied):
            self.check(snapshot=dict(self.snapshot,permission="write"))
    def test_owner_public_key_substitution_denied(self):
        with self.assertRaises(EnrollmentDenied):
            self.check(owner_public_b64=b64(pub(Ed25519PrivateKey.generate())))
    def test_replayed_challenge_nonce_denied(self):
        with self.assertRaises(EnrollmentDenied):self.check(nonce_already_used=True)
    def test_expired_owner_proof_denied(self):
        with self.assertRaises(EnrollmentDenied):self.check(now=self.now+160)
    def test_stable_repo_id_switch_denied(self):
        with self.assertRaises(EnrollmentDenied):
            self.check(challenge=dict(self.challenge,repository_id="99999"))
if __name__=="__main__":unittest.main()
