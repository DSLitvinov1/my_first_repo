"""Deterministic tests of actual persisted proof format, including tamper cases."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from model_handoff_owned import handoff_gate as gate
from model_handoff_owned import verify_live_archive as audit

SRC = "def normalize_label(value):\n    return value.strip().lower()\n"
TARGET = "bridge/neurofactory/development/model_handoff_owned/trial_only_not_published.py"
MODULE_SHA = "f" * 64

def make_archived_documents():
    c = gate.candidate_packet("NF-DEV-05-Q090", TARGET, SRC)
    review_response = {"verdict": "APPROVE", "candidate_sha256": c["candidate_sha256"],
                       "findings": ["Reviewed source and edge cases"]}
    review = gate.review_packet(c, json.dumps(review_response))
    proof = gate.handoff_dossier(c, review)
    module_response = {"verdict": "APPROVE", "candidate_sha256": MODULE_SHA,
                       "findings": ["No uncontrolled publishing"]}
    docs = {
        audit.MEMBERS[0]: c,
        audit.MEMBERS[1]: review,
        audit.MEMBERS[2]: proof,
        audit.MEMBERS[3]: {"model": gate.REVIEWER, "phase": "candidate_review", "attempt": 1,
                           "publication_enabled": False,
                           "subject_sha256": c["candidate_sha256"],
                           "raw_model_reply": json.dumps(review_response)},
        audit.MEMBERS[4]: {"stage": "awaiting_review_owner", "branch": gate.BRANCH,
                           "task_id": "NF-DEV-05-Q090",
                           "candidate_sha256": c["candidate_sha256"], "module_sha256": MODULE_SHA,
                           "publication_enabled": False, "publisher_enabled": False},
        audit.MEMBERS[5]: {"model": gate.REVIEWER, "phase": "module_review", "attempt": 1,
                           "publication_enabled": False, "subject_sha256": MODULE_SHA,
                           "raw_model_reply": json.dumps(module_response)},
        audit.MEMBERS[6]: {"source_sha256": MODULE_SHA, "verdict": "APPROVE",
                           "findings": module_response["findings"],
                           "release_authorized": False},
    }
    summary = {"task_id": "NF-DEV-05-Q090",
               "candidate_sha256": c["candidate_sha256"],
               "module_sha256": MODULE_SHA, "candidate_verdict": "APPROVE",
               "module_verdict": "APPROVE", "publication_count": 0,
               "release_authorized": False,
               "writer": {"model": gate.WRITER},
               "reviewer": {"model": gate.REVIEWER},
               "evidence_hashes": {
                   name.rsplit("/", 1)[-1]: hashlib.sha256(gate.encoded(docs[name]) + b"\n").hexdigest()
                   for name in audit.MEMBERS[:3]}}
    docs[audit.MEMBERS[7]] = summary
    return docs, c["candidate_sha256"]

def write_zip(path, documents):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, doc in documents.items():
            archive.writestr(name, gate.encoded(doc) + b"\n")

class ArtifactEvidenceTests(unittest.TestCase):
    def test_original_archive_accepts_without_granting_release(self):
        docs, sha = make_archived_documents()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.zip"
            write_zip(path, docs)
            verdict = audit.verify_archive(path, sha, MODULE_SHA)
            self.assertTrue(verdict["evidence_consistent"])
            self.assertFalse(verdict["publication_allowed"])
            self.assertEqual(verdict["independent_review_owner"], "PENDING")

    def test_altered_candidate_is_rejected(self):
        docs, sha = make_archived_documents()
        docs[audit.MEMBERS[0]]["candidate"] += "\n# changed"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.zip"
            write_zip(path, docs)
            with self.assertRaises(audit.ArtifactError):
                audit.verify_archive(path, sha, MODULE_SHA)

    def test_forged_raw_qwen3_reply_is_rejected(self):
        docs, sha = make_archived_documents()
        docs[audit.MEMBERS[3]]["raw_model_reply"] = '{"verdict":"REJECT"}'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.zip"
            write_zip(path, docs)
            with self.assertRaises(audit.ArtifactError):
                audit.verify_archive(path, sha, MODULE_SHA)

    def test_forbidden_release_is_rejected(self):
        docs, sha = make_archived_documents()
        docs[audit.MEMBERS[7]]["release_authorized"] = True
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.zip"
            write_zip(path, docs)
            with self.assertRaises(audit.ArtifactError):
                audit.verify_archive(path, sha, MODULE_SHA)

    def test_missing_proof_is_rejected(self):
        docs, sha = make_archived_documents()
        docs.pop(audit.MEMBERS[2])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.zip"
            write_zip(path, docs)
            with self.assertRaises(audit.ArtifactError):
                audit.verify_archive(path, sha, MODULE_SHA)

    def test_duplicate_zip_member_is_rejected(self):
        docs, sha = make_archived_documents()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.zip"
            write_zip(path, docs)
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "a") as archive:
                    archive.writestr(audit.MEMBERS[0], gate.encoded(docs[audit.MEMBERS[0]]))
            with self.assertRaises(audit.ArtifactError):
                audit.verify_archive(path, sha, MODULE_SHA)

    def test_wrong_module_digest_is_rejected(self):
        docs, sha = make_archived_documents()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.zip"
            write_zip(path, docs)
            with self.assertRaises(audit.ArtifactError):
                audit.verify_archive(path, sha, "0" * 64)

if __name__ == "__main__":
    unittest.main()
