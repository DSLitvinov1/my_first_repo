"""Read-only Linux operator-installed PUBLIC trust pins (not private keys).

Fixed root-owned location; caller/model/task cannot choose a different file,
provide a substitute public key, override host identity, or enable fixture
mode. Real operator and hardware identity, trust-root provisioning, rollback
immunity, live repo ACL and actual server operation are NOT performed here.
The resulting pinned public keys remain necessary but NOT sufficient to grant
any effect: inspect_signed_four_party_scope always returns no authority.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TRUST_DIR = Path("/etc/neurofactory/trust")
TRUST_FILENAME = "four-party-public-pins.json"
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
NUMID = re.compile(r"[1-9][0-9]{0,19}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
FIELDS = frozenset((
    "schema", "repository", "github_user_id", "repository_id",
    "key_valid_from_unix", "key_valid_until_unix",
    "operator_public_base64", "owner_public_base64",
    "host_public_base64", "witness_public_base64",
    "operator_public_sha256", "mtls_witness_cert_sha256",
))
PRIVATE_KEY_MARKERS = ("BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
                       "PRIVATE KEY-----", "secret_key", "private_key",
                       "password", "credential", "api_token", "access_token")


class OperatorPinsDenied(ValueError):
    pass


def _deny():
    raise OperatorPinsDenied("no independently provisioned protected public trust root")


def _decode_exact_public_root(raw: bytes, *, now_unix: int) -> dict:
    """Pure bounded parser; only the fixed-path loader can establish OS owner."""
    if type(raw) is not bytes or not 220 <= len(raw) <= 8192 or \
            type(now_unix) is not int or not 1 <= now_unix < 2**63:
        _deny()
    try:
        s = raw.decode("ascii")
        if any(x in s for x in PRIVATE_KEY_MARKERS):
            _deny()
        data = json.loads(s)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _deny()
    if type(data) is not dict or set(data) != FIELDS or \
            data["schema"] != "neurofactory.operator.public_pins.v1":
        _deny()
    for field in ("repository", "github_user_id", "repository_id",
                  "operator_public_sha256", "mtls_witness_cert_sha256"):
        if type(data[field]) is not str:
            _deny()
    if not REPO.fullmatch(data["repository"]) or \
            not NUMID.fullmatch(data["github_user_id"]) or \
            not NUMID.fullmatch(data["repository_id"]) or \
            not SHA64.fullmatch(data["operator_public_sha256"]) or \
            not SHA64.fullmatch(data["mtls_witness_cert_sha256"]):
        _deny()
    start = data["key_valid_from_unix"]
    expires = data["key_valid_until_unix"]
    if (type(start) is not int or type(expires) is not int or
            not 1 <= start <= now_unix < expires or
            expires - start > 90 * 86400):
        _deny()
    keys = {}
    raw_keys = []
    for role in ("operator", "owner", "host", "witness"):
        encoded = data[role + "_public_base64"]
        if type(encoded) is not str or len(encoded) != 44:
            _deny()
        try:
            pub = base64.b64decode(encoded, validate=True)
            if len(pub) != 32:
                _deny()
            keys[role] = Ed25519PublicKey.from_public_bytes(pub)
        except (binascii.Error, ValueError, TypeError):
            _deny()
        raw_keys.append(pub)
    if len(set(raw_keys)) != 4 or \
            hashlib.sha256(raw_keys[0]).hexdigest() != data["operator_public_sha256"]:
        _deny()
    return {
        "pinned_keys": keys,
        "metadata": {
            "schema": data["schema"],
            "repository": data["repository"],
            "github_user_id": data["github_user_id"],
            "repository_id": data["repository_id"],
            "operator_key_sha256": data["operator_public_sha256"],
            "mtls_witness_cert_sha256": data["mtls_witness_cert_sha256"],
            "valid_until_unix": expires,
            "physical_node_attested_by_loader": False,
            "external_monotonic_storage_attested": False,
            "live_execution_allowed": False,
            "release_approved": False,
        },
    }


def _stat_safe_dir(path: Path, *, exact_private: bool = False):
    try:
        if path.is_symlink():
            _deny()
        st = path.lstat()
    except (OSError, ValueError):
        _deny()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        _deny()
    if exact_private and st.st_mode & 0o077:
        _deny()


def load_operator_installed_public_pins() -> dict:
    """Read fixed root-only file, not an env/CLI-selected fake pin.

    Expected OS installation happens through separate authorized operator,
    with hardware-backed key custody and independent highwater. This loader
    never writes a file, enrolls a key or starts a service.
    """
    if (os.name != "posix" or not hasattr(os, "geteuid") or
            any(os.environ.get(x) == "1" for x in (
                "NF_HOST_RECEIVER_FIXTURE_ONLY",
                "NF_RECEIVER_OS_FIXTURE_ONLY",
                "NF_OPERATOR_ANCHOR_FIXTURE_ONLY",
                "NF_MTLS_WITNESS_TEST_ONLY"))):
        _deny()
    _stat_safe_dir(Path("/etc"))
    _stat_safe_dir(Path("/etc/neurofactory"), exact_private=True)
    _stat_safe_dir(TRUST_DIR, exact_private=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | \
        getattr(os, "O_CLOEXEC", 0)
    dfd = -1
    filefd = -1
    try:
        dfd = os.open(TRUST_DIR, flags | getattr(os, "O_DIRECTORY", 0))
        filefd = os.open(TRUST_FILENAME, flags, dir_fd=dfd)
        st = os.fstat(filefd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or \
                st.st_mode & 0o077 or not 220 <= st.st_size <= 8192:
            _deny()
        with os.fdopen(os.dup(filefd), "rb") as stream:
            raw = stream.read(8193)
        if len(raw) != st.st_size:
            _deny()
        # No secret/private-key bytes are printed or returned.
        return _decode_exact_public_root(raw, now_unix=int(time.time()))
    except (OSError, ValueError, TypeError):
        _deny()
    finally:
        if filefd >= 0:
            os.close(filefd)
        if dfd >= 0:
            os.close(dfd)
