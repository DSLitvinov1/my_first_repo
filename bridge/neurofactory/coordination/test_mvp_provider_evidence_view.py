import copy
from hashlib import sha256
import unittest
from mvp_provider_evidence_view import bind_reported_receipt, EvidenceBindingError

def summary():
    return {
        "schema": 1, "status": "RESPONSE_UNVERIFIED",
        "task_id": "NF-DEV-05-Q001", "source_sha": "a" * 40,
        "provider_status": "PROPOSED_UNVERIFIED",
        "proposed_path": "src/sample.py",
        "proposed_content_sha256": "d" * 64,
        "model_output_digest": "b" * 64,
        "source_verified": False, "automatic_retry_allowed": False,
        "publication_allowed": False,
    }

def receipt():
    return {
        "evidence_filename": sha256(b"NF-DEV-05-Q001").hexdigest() + ".json",
        "evidence_sha256": "c" * 64,
        "response_sha256": "b" * 64,
        "observed_at_utc": "2026-10-15T00:00:00.123+00:00",
        "elapsed_ms": 1234,
    }

class ReceiptBindingTests(unittest.TestCase):
    def test_valid_is_not_authenticated_or_allowed_to_publish(self):
        s, m = summary(), receipt()
        a, b = copy.deepcopy(s), copy.deepcopy(m)
        v = bind_reported_receipt(s, m)
        self.assertTrue(v["receipt_reported"])
        for key in ("receipt_externally_authenticated", "local_model_proven",
                    "independent_review_approved", "source_verified",
                    "automatic_retry_allowed", "publication_allowed"):
            self.assertFalse(v[key])
        self.assertEqual(v["handoff"], "PAUSED_BY_USER")
        self.assertNotIn("response_text", v)
        self.assertEqual(s, a)
        self.assertEqual(m, b)

    def test_other_task_receipt_rejected(self):
        m = receipt()
        m["evidence_filename"] = sha256(b"NF-DEV-05-Q002").hexdigest() + ".json"
        with self.assertRaises(EvidenceBindingError):
            bind_reported_receipt(summary(), m)

    def test_other_response_hash_rejected(self):
        m = receipt()
        m["response_sha256"] = "e" * 64
        with self.assertRaises(EvidenceBindingError):
            bind_reported_receipt(summary(), m)

    def test_response_text_or_hidden_privileges_rejected(self):
        for target in ("result", "metadata"):
            s, m = summary(), receipt()
            (s if target == "result" else m)["response_text"] = "secret-model-text"
            with self.subTest(target=target), self.assertRaises(EvidenceBindingError):
                bind_reported_receipt(s, m)

    def test_forged_approval_and_retry_rejected(self):
        for key in ("source_verified", "automatic_retry_allowed", "publication_allowed"):
            s = summary()
            s[key] = True
            with self.subTest(key=key), self.assertRaises(EvidenceBindingError):
                bind_reported_receipt(s, receipt())

    def test_blocked_or_unknown_status_never_binds_receipt(self):
        for status in ("BLOCKED", "UNKNOWN", "SOURCE_VERIFIED"):
            s = summary()
            s["status"] = status
            with self.subTest(status=status), self.assertRaises(EvidenceBindingError):
                bind_reported_receipt(s, receipt())

    def test_fake_timestamp_and_bool_elapsed_rejected(self):
        for key, value in (("observed_at_utc", "yesterday"), ("elapsed_ms", True),
                           ("evidence_sha256", "unsigned")):
            m = receipt()
            m[key] = value
            with self.subTest(key=key), self.assertRaises(EvidenceBindingError):
                bind_reported_receipt(summary(), m)

    def test_different_task_id_rejected(self):
        s = summary()
        s["task_id"] = "NF-DEV-05-Q002"
        with self.assertRaises(EvidenceBindingError):
            bind_reported_receipt(s, receipt())

    def test_path_traversal_and_hidden_segments_rejected(self):
        for unsafe in ("src/../escape.py", "src/./task.py", "docs/.hidden.py",
                       "src//gap.py", "docs/report.exe", "src/other\\\\escape.py",
                       "docs/folder/../../secret.json"):
            s = summary()
            s["proposed_path"] = unsafe
            with self.subTest(path=unsafe), self.assertRaises(EvidenceBindingError):
                bind_reported_receipt(s, receipt())

    def test_boolean_schema_must_not_pass_as_integer_one(self):
        s = summary()
        s["schema"] = True
        with self.assertRaises(EvidenceBindingError):
            bind_reported_receipt(s, receipt())

    def test_nested_approved_and_shell_unsafe_field_rejected(self):
        for field in ("review_approved", "execute", "response_text"):
            s = summary()
            s[field] = True
            with self.subTest(field=field), self.assertRaises(EvidenceBindingError):
                bind_reported_receipt(s, receipt())

if __name__ == "__main__":
    unittest.main()
