"""Trusted integration boundary for the Stage-4 queue and real GitHub receipts.

This component NEVER edits another project, launches models, sends ChatGPT
messages, or publishes code. An authorized runner provides the actual publisher.
Publication may be acknowledged only when its existing remote result is verified.
"""
import base64
import binascii
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from stage4_queue import Stage4Queue, Stage4Error

REPO = "DSLitvinov1/my_first_repo"
BRANCH = "neurofactory-public-lab-20261012"
PREFIX = "bridge/neurofactory/"
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")


class ReceiptError(ValueError):
    pass


def approved_target(path):
    """Check path in addition to the existing reviewed path-policy gate."""
    return (isinstance(path, str) and path.startswith(PREFIX)
            and 0 < len(path) <= 220 and
            bool(re.fullmatch(r"[A-Za-z0-9_.\-/]+", path))
            and all(part not in ("", ".", "..") for part in path.split("/"))
            and path.endswith(".py"))


class ReadOnlyGithubReceipts:
    """Public, no-token read-only verifier; fetch is injectable for tests."""

    def __init__(self, fetch=None):
        self.fetch = fetch or self._fetch

    @staticmethod
    def _fetch(endpoint):
        if not isinstance(endpoint, str) or not endpoint.startswith(
                "https://api.github.com/repos/" + REPO + "/"):
            raise ReceiptError("Remote check outside authorized repository")
        req = urllib.request.Request(
            endpoint, headers={"Accept": "application/vnd.github+json",
                               "User-Agent": "NeurofactoryStage4Receipt",
                               "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                    req, timeout=18) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise ReceiptError("GitHub read failed") from error

    def verify(self, commit, path, source_sha256):
        if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
            raise ReceiptError("Invalid commit identifier")
        if not approved_target(path):
            raise ReceiptError("Unapproved result path")
        if not isinstance(source_sha256, str) or not DIGEST.fullmatch(source_sha256):
            raise ReceiptError("Missing reviewed source digest")
        base = "https://api.github.com/repos/" + REPO
        ancestry = self.fetch(base + "/compare/" + commit + "..." + BRANCH)
        if not isinstance(ancestry, dict) or ancestry.get("status") not in (
                "identical", "ahead"):
            raise ReceiptError("Receipt commit is not on approved published branch")
        commit_info = self.fetch(base + "/commits/" + commit)
        if not isinstance(commit_info, dict) or commit_info.get("sha") != commit:
            raise ReceiptError("Commit not found")
        changed = commit_info.get("files")
        if not isinstance(changed, list) or not any(
                isinstance(f, dict) and f.get("filename") == path
                and f.get("status") in ("added", "modified") for f in changed):
            raise ReceiptError("Commit did not publish requested source")
        # A matching source file does not bless an otherwise cross-project commit.
        for item in changed:
            name = item.get("filename") if isinstance(item, dict) else None
            if not (isinstance(name, str) and
                    (name.startswith("bridge/neurofactory/") or
                     (name.startswith(".github/workflows/neurofactory-")
                      and name.endswith(".yml"))) and
                    all(part not in ("", ".", "..") for part in name.split("/"))):
                raise ReceiptError("Receipt includes changes outside Neurofactory")
        item = self.fetch(base + "/contents/" + path + "?ref=" + commit)
        if not isinstance(item, dict) or item.get("encoding") != "base64":
            raise ReceiptError("Published source cannot be read")
        try:
            body = base64.b64decode(item["content"], validate=False)
        except (ValueError, KeyError, binascii.Error) as error:
            raise ReceiptError("Invalid remote source encoding") from error
        if hashlib.sha256(body).hexdigest() != source_sha256:
            raise ReceiptError("Remote source differs from independent review")
        return True

    def find_verified(self, path, source_sha256):
        """Find a prior receipt after an ambiguous publisher crash; never republish."""
        if not approved_target(path):
            raise ReceiptError("Unapproved result path")
        base = "https://api.github.com/repos/" + REPO
        query = urllib.parse.urlencode(
            {"path": path, "sha": BRANCH, "per_page": 8})
        history = self.fetch(base + "/commits?" + query)
        if not isinstance(history, list):
            raise ReceiptError("Cannot retrieve remote commit history")
        for item in history:
            sha = item.get("sha") if isinstance(item, dict) else None
            if isinstance(sha, str) and COMMIT.fullmatch(sha):
                try:
                    if self.verify(sha, path, source_sha256):
                        return sha
                except ReceiptError:
                    continue
        return None


class Stage4BridgeAdapter:
    """Connect existing durable role queue to the real, trusted receipt boundary.

    The existing first-chat Stage4Queue is left unmodified. Runtime activation
    must be separate from tests and requires an independently approved release.
    """

    def __init__(self, root, plan, receipts=None):
        self.queue = Stage4Queue(root, plan)
        self.receipts = receipts or ReadOnlyGithubReceipts()

    def recover(self, now, published_path):
        states = self.queue.prepare()
        states = self.queue.recover(now)
        publication = states["publisher"]
        if publication["state"] != "needs_receipt_check":
            return states
        digest = publication.get("proof", {}).get("source_sha256")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ReceiptError("Durable publisher intent is missing candidate digest")
        commit = self.receipts.find_verified(published_path, digest)
        if commit is None:
            # Ambiguous external effect. No replay and no blind acceptance.
            return self.queue.prepare()
        self.queue.acknowledge("publisher", commit, remote_verified=True)
        return self.queue.prepare()

    def complete_with_verified_receipt(self, role, commit, published_path):
        if role not in ("writer", "reviewer", "publisher"):
            raise ReceiptError("Unknown production role")
        states = self.queue.prepare()
        proof = states[role].get("proof", {})
        digest = proof.get("source_sha256")
        if states[role]["state"] not in ("publishing", "needs_receipt_check"):
            raise ReceiptError("Role has no durable publication intent")
        # Read-only GitHub checks happen before a caller is allowed to set
        # remote_verified=True on the already-reviewed state machine.
        self.receipts.verify(commit, published_path, digest)
        return self.queue.acknowledge(role, commit, remote_verified=True)

    def publish_trusted(self, now, approved_path, publisher, *, lease_seconds=180):
        """Integrate real publisher callback without granting rights to models.

        publisher(path, source_sha256) may raise after committing. This method
        never retries it; startup reconciliation must first check GitHub.
        """
        if not approved_target(approved_path):
            raise ReceiptError("Unsafe target")
        states = self.recover(now, approved_path)
        if states["publisher"]["state"] == "verified_done":
            return states["publisher"]
        if states["publisher"]["state"] in ("publishing", "needs_receipt_check"):
            raise ReceiptError("Uncertain external publication; never resend")
        if states["publisher"]["state"] != "queued":
            raise ReceiptError("Publisher is not ready for a new claim")
        self.queue.claim("publisher", now, lease_seconds=lease_seconds)
        intent = self.queue.before_external_effect("publisher")
        digest = intent["proof"]["source_sha256"]
        commit = publisher(approved_path, digest)
        return self.complete_with_verified_receipt("publisher", commit, approved_path)
