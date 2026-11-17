"""Offline regressions for Oleg V14 Bitrix failover, never submit a CRM form."""
import hashlib
from pathlib import Path
import unittest
from bitrix_resilient_contact_stage_v14 import ANCHOR, REPLACEMENT, PREVIOUS_SHA, MAIL, PHONE, patch

ROOT = Path(__file__).resolve().parent
CANDIDATE = ROOT / "v14-assets" / "legal-assistant-v4.js"
V14_SHA = "bdc89e956c80712fdb25c0333d941377d3b1b09afe0bf842a97cea1e9fb64c74"


class ContactFallbackV14(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v14 = CANDIDATE.read_bytes()
        cls.v13 = cls.v14.replace(REPLACEMENT.encode("utf8"), ANCHOR.encode("utf8"))

    def test_v14_hash_exact(self):
        self.assertEqual(hashlib.sha256(self.v14).hexdigest(), V14_SHA)

    def test_v13_expected_baseline_hash(self):
        self.assertEqual(hashlib.sha256(self.v13).hexdigest(), PREVIOUS_SHA)

    def test_patch_exact_and_preserves_other_code(self):
        self.assertEqual(patch(self.v13), self.v14)

    def test_fail_closed_for_unknown_baseline(self):
        with self.assertRaisesRegex(ValueError, "SHA drift"):
            patch(self.v13.replace(b"iframe", b"broken", 1))

    def test_double_patching_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA drift"):
            patch(self.v14)

    def test_alternative_channels_exactly_once(self):
        self.assertEqual(self.v14.count(PHONE.encode()), 1)
        self.assertEqual(self.v14.count(MAIL.encode()), 1)
        text = self.v14.decode("utf8")
        self.assertIn("open.href = formUrl", text)
        self.assertIn("open.rel = 'noopener noreferrer'", text)
        self.assertIn("formStep.insertBefore(fallback, frame);", text)

    def test_both_real_bitrix_forms_preserved(self):
        script=self.v14.decode("utf8")
        for marker in ("crm_form_fhi3n", "crm_form_ep5fd"):
            self.assertEqual(script.count(marker), 1)

    def test_no_analytics_or_success_claim_added(self):
        added = REPLACEMENT.lower()
        self.assertNotIn("ym(",added)
        self.assertNotIn("fetch(",added)
        self.assertNotIn("formaccepted",added)
        self.assertNotIn("заявка отправлена",added)
        self.assertNotIn("qwen",self.v14.decode("utf8").lower())
        self.assertIn("Если Битрикс24 недоступен",REPLACEMENT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
