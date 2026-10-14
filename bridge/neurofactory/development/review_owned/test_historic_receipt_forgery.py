"""Independent REVIEW counterexamples for historical Stage5 GitHub receipts.

PASS means an unsafe property is reproduced, NOT an approval for merging.
The historic module is not confirmed to be the production publisher. We
only mock read-only GitHub metadata in a fresh isolated Python process.
"""
import base64
import hashlib
import json
import unittest
from unittest import mock

import stage5_git_receipts as old_receipt

REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-public-lab-20261012"
TASK="NF-DEV-05-Q097"
TARGET="bridge/neurofactory/development/review_owned/never-published.py"
COMMIT="e"*40
SOURCE=b"def safe_function(value):\n    return str(value)\n"
DIGEST=hashlib.sha256(SOURCE).hexdigest()


def replay_receipt(role, body):
    path=old_receipt.receipt_path(TASK,role,TARGET)
    def fake_read(uri):
        if uri=="commits/"+COMMIT:
            return {"files":[{"filename":path}]}
        if uri=="compare/"+COMMIT+"..."+BRANCH:
            return {"status":"ahead"}
        if uri=="contents/"+path+"?ref="+COMMIT:
            return {"path":path,"content":base64.b64encode(body).decode("ascii")}
        raise AssertionError("Unknown read-only endpoint "+str(uri))
    with mock.patch.object(old_receipt,"_get",side_effect=fake_read):
        return old_receipt.verify(REPO,BRANCH,TARGET,COMMIT,DIGEST,
                                  task_id=TASK,role=role)


class HistoricReceiptThreatTests(unittest.TestCase):
    def test_forged_qwen3_review_text_is_accepted_by_historical_verifier(self):
        crafted=json.dumps({"task_id":TASK,"source_sha256":DIGEST,
                            "verdict":"REVIEW_OK","reviewer":"qwen3:4b"}).encode()
        # No Qwen3 process, no signed independent REVIEW owner, no
        # trustworthy GitHub attestation has occurred here.
        self.assertTrue(replay_receipt("reviewer", crafted))

    def test_duplicate_json_keys_allow_a_last_wins_approved_verdict(self):
        crafted=('{"task_id":"'+TASK+'","source_sha256":"'+DIGEST+
                 '","reviewer":"qwen3:4b","verdict":"REVIEW_BAD",'
                 '"verdict":"REVIEW_OK"}').encode()
        self.assertTrue(replay_receipt("reviewer",crafted))

    def test_invalid_reviewer_verdict_is_rejected_by_historical_check(self):
        crafted=json.dumps({"task_id":TASK,"source_sha256":DIGEST,
                            "verdict":"REVIEW_BAD","reviewer":"qwen3:4b"}).encode()
        with self.assertRaises(old_receipt.ReceiptError):
            replay_receipt("reviewer",crafted)

    def test_writer_content_bytes_are_still_checked(self):
        self.assertTrue(replay_receipt("writer",SOURCE))
        with self.assertRaises(old_receipt.ReceiptError):
            replay_receipt("writer",SOURCE+b"modified")

    def test_no_production_publishing_is_exercised(self):
        # Mocked _get only: the independent REVIEW never invokes PUT/POST.
        crafted=json.dumps({"task_id":TASK,"source_sha256":DIGEST,
                            "verdict":"REVIEW_OK","reviewer":"qwen3:4b"}).encode()
        with mock.patch.object(old_receipt.urllib.request,"urlopen") as network:
            self.assertTrue(replay_receipt("reviewer",crafted))
            network.assert_not_called()


if __name__=="__main__":
    unittest.main(verbosity=2)
