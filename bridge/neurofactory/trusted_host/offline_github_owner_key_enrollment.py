"""Two-party owner-key enrollment verifier: operator-attested GitHub ACL + owner challenge.

Stage-only; does not fetch GitHub or enroll real users by itself. A DISTINCT
operator must inspect LIVE authenticated Github API data, validate stable IDs,
sign the snapshot and securely pin operator public key OUT OF BAND.
Owner private key signs one-time challenge scoped to same snapshot and
one intended public key. Models/DB cannot create authoritative ACL snapshots.
"""
import base64,binascii,hashlib,json,re,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

class EnrollmentDenied(ValueError):pass
USER="151650108"
REPO="723328237"
DOMAIN=b"NF-OWNER-ENROLLMENT-V1\x00"
HEX64=re.compile("[a-f0-9]{64}\\Z")
def fail():raise EnrollmentDenied("owner enrollment not authenticated by independent operator")
def canon(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True,
                      allow_nan=False).encode("ascii")
def digest(raw):return hashlib.sha256(raw).hexdigest()
def verify(pub_b64,sig_b64,message):
    try:
        pub=base64.b64decode(pub_b64,validate=True)
        sig=base64.b64decode(sig_b64,validate=True)
        if len(pub)!=32 or len(sig)!=64:fail()
        Ed25519PublicKey.from_public_bytes(pub).verify(sig,message)
    except (ValueError,binascii.Error,InvalidSignature,TypeError) as e:
        raise EnrollmentDenied("signature/key invalid") from e
def seal_owner_key(*,operator_public_b64,operator_public_sha256,
                   snapshot,operator_signature_b64,
                   challenge,owner_signature_b64,owner_public_b64,
                   nonce_already_used,now):
    """Return advisory sealed candidate only, never deploy/update actual pin."""
    if (type(now) is not int or type(nonce_already_used) is not bool or nonce_already_used
        or type(operator_public_b64) is not str or
        type(operator_public_sha256) is not str or
        not HEX64.fullmatch(operator_public_sha256) or
        type(owner_public_b64) is not str or
        type(snapshot) is not dict or type(challenge) is not dict or
        type(operator_signature_b64) is not str or
        type(owner_signature_b64) is not str):
        fail()
    snapfields={"schema","github_login","github_user_id","repository_full_name",
        "repository_id","repository_owner_user_id","permission","checked_unix",
        "valid_until_unix","source","operator_id","project_id","scope_sha256"}
    challengefields={"schema","nonce_sha256","github_user_id","repository_id",
        "github_login","project_id","scope_sha256","owner_public_key_sha256",
        "operator_snapshot_sha256","expires_unix"}
    if set(snapshot)!=snapfields or set(challenge)!=challengefields:fail()
    if (snapshot["schema"]!="neurofactory.github_acl_operator_snapshot.v1" or
        challenge["schema"]!="neurofactory.owner_possession_challenge.v1" or
        snapshot["source"]!="AUTHENTICATED_GITHUB_API_OBSERVED_BY_OPERATOR" or
        snapshot["permission"]!="admin" or
        type(snapshot["checked_unix"]) is not int or
        type(snapshot["valid_until_unix"]) is not int or
        not snapshot["checked_unix"]<=now<snapshot["valid_until_unix"]<=now+300 or
        snapshot["github_user_id"]!="151650108" or
        snapshot["repository_id"]!="723328237" or
        snapshot["repository_owner_user_id"]!="151650108" or
        snapshot["repository_full_name"]!="DSLitvinov1/my_first_repo" or
        snapshot["github_login"]!="DSLitvinov1" or
        type(snapshot["operator_id"]) is not str or
        not 1<=len(snapshot["operator_id"])<=80 or
        type(snapshot["project_id"]) is not str or
        not 1<=len(snapshot["project_id"])<=100 or
        type(snapshot["scope_sha256"]) is not str or
        not HEX64.fullmatch(snapshot["scope_sha256"]) or
        challenge["schema"]!="neurofactory.owner_possession_challenge.v1" or
        challenge["github_user_id"]!=snapshot["github_user_id"] or
        challenge["repository_id"]!=snapshot["repository_id"] or
        challenge["github_login"]!=snapshot["github_login"] or
        challenge["project_id"]!=snapshot["project_id"] or
        challenge["scope_sha256"]!=snapshot["scope_sha256"] or
        type(challenge["nonce_sha256"]) is not str or
        not HEX64.fullmatch(challenge["nonce_sha256"]) or
        type(challenge["expires_unix"]) is not int or
        not now<challenge["expires_unix"]<=min(now+180,snapshot["valid_until_unix"])):
        fail()
    op_pub=base64.b64decode(operator_public_b64,validate=True)
    owner_pub=base64.b64decode(owner_public_b64,validate=True)
    if len(op_pub)!=32 or digest(op_pub)!=operator_public_sha256 or len(owner_pub)!=32:
        fail()
    if challenge["owner_public_key_sha256"]!=digest(owner_pub):fail()
    snapshot_raw=canon(snapshot)
    if challenge["operator_snapshot_sha256"]!=digest(snapshot_raw):fail()
    verify(operator_public_b64,operator_signature_b64,
           DOMAIN+b"OPERATOR_SNAPSHOT\x00"+snapshot_raw)
    verify(owner_public_b64,owner_signature_b64,
           DOMAIN+b"OWNER_PROOF\x00"+canon(challenge))
    # The candidate MUST be installed only by an authorized operator into
    # signer-owned private storage together with persistent nonce/highwater
    # and separately pinned operator root; this API NEVER writes those files.
    return {"schema":"neurofactory.pending_owner_enrollment.v1",
        "status":"CRYPTOGRAPHIC_PROOF_CHECKED_OPERATOR_ENROLLMENT_STILL_REQUIRED",
        "owner_id":"DSLitvinov1","repository":"DSLitvinov1/my_first_repo",
        "github_user_id":snapshot["github_user_id"],
        "repository_id":snapshot["repository_id"],
        "project_id":snapshot["project_id"],
        "scope_sha256":snapshot["scope_sha256"],
        "owner_public_key_base64":owner_public_b64,
        "operator_snapshot_sha256":digest(snapshot_raw),
        "challenge_sha256":digest(canon(challenge)),
        "operator_public_sha256":operator_public_sha256,
        "live_repo_acl_rechecked_in_this_verifier":False,
        "actual_independent_operator_enrolled":False,
        "persistent_nonce_recorded":False,
        "production_authorization":False}
