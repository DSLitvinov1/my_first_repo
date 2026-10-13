"""Offline receipt verifier tests: actual GitHub API shape, all network mocked."""
import base64,hashlib,json,unittest
from unittest import mock
import stage5_git_receipts as r
REPO="DSLitvinov1/my_first_repo"
BRANCH="neurofactory-public-lab-20261012"
TASK="NF-DEV-05-Q001"
TARGET="bridge/neurofactory/development/stage5_development_queue.py"
SHA="a"*40
SRC=b"def approved_change():\n    return True\n"
DIGEST=hashlib.sha256(SRC).hexdigest()

def api_result(role,wrong=False):
    path=r.receipt_path(TASK,role,TARGET)
    content=(json.dumps({"task_id":TASK,"source_sha256":DIGEST,
                          "verdict":"REVIEW_BAD" if wrong else "REVIEW_OK",
                          "reviewer":"qwen3:4b"}).encode()
            if role=="reviewer" else SRC)
    return path,content

class VerifiedReceiptTests(unittest.TestCase):
    def checker(self,role,wrong=False,unrelated=False,ancestor=True):
        path,payload=api_result(role,wrong)
        def fake(uri):
            if uri=="commits/"+SHA:
                changed=[{"filename":path}]
                if unrelated:changed.append({"filename":"another_project/file.py"})
                return {"files":changed}
            if uri.startswith("compare/"):
                return {"status":"ahead" if ancestor else "diverged"}
            if uri.startswith("contents/"):
                return {"path":path,"content":base64.b64encode(payload).decode()}
            raise AssertionError(uri)
        with mock.patch.object(r,"_get",side_effect=fake):
            return r.verify(REPO,BRANCH,TARGET,SHA,DIGEST,task_id=TASK,role=role)

    def test_distinct_writer_review_publisher_paths(self):
        self.assertNotEqual(r.receipt_path(TASK,"writer",TARGET),
                            r.receipt_path(TASK,"reviewer",TARGET))
        self.assertEqual(r.receipt_path(TASK,"publisher",TARGET),TARGET)

    def test_three_role_receipts_validated_independently(self):
        for role in ("writer","reviewer","publisher"):
            self.assertTrue(self.checker(role))

    def test_false_reviewer_verdict_refused(self):
        with self.assertRaises(r.ReceiptError):self.checker("reviewer",wrong=True)

    def test_other_project_in_commit_refused(self):
        with self.assertRaises(r.ReceiptError):self.checker("publisher",unrelated=True)

    def test_unreachable_commit_refused(self):
        with self.assertRaises(r.ReceiptError):self.checker("publisher",ancestor=False)

    def test_wrong_repo_path_and_role_refused(self):
        for target in ("bridge/other-project/a.py","../etc/passwd"):
            with self.assertRaises(r.ReceiptError):
                r.receipt_path(TASK,"publisher",target)
        with self.assertRaises(r.ReceiptError):r.receipt_path(TASK,"chat_sender",TARGET)
        with self.assertRaises(r.ReceiptError):
            r.verify("other/repo",BRANCH,TARGET,SHA,DIGEST,task_id=TASK,role="writer")

    def test_wrong_source_hash_refused(self):
        path,payload=api_result("writer")
        def fake(uri):
            if uri=="commits/"+SHA:return {"files":[{"filename":path}]}
            if uri.startswith("compare/"):return {"status":"ahead"}
            if uri.startswith("contents/"):return {"path":path,"content":base64.b64encode(payload).decode()}
            raise AssertionError(uri)
        with mock.patch.object(r,"_get",side_effect=fake):
            with self.assertRaises(r.ReceiptError):
                r.verify(REPO,BRANCH,TARGET,SHA,"f"*64,task_id=TASK,role="writer")
if __name__=="__main__":unittest.main(verbosity=2)
