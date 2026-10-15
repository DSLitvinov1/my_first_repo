"""Only test read-only trust limits for new CORE anchor metadata."""
import copy
import unittest
from mvp_core_anchor_boundary import AnchorBoundaryError, inspect_anchor

OLD = "f" * 40
NEW = "e" * 40
HASH = "a" * 64
TASK = "NF-DEV-05-Q001"

def result():
    return {"schema":"neurofactory.core.anchor_match.v1", "task_id":TASK,
            "anchor_sha256":HASH, "matches_supplied_external_digest":True,
            "external_origin_attested":False, "model_invoked":False,
            "review_approved":False, "published":False,
            "execution_allowed":False}

def review(sha=OLD, verdict="REJECT"):
    return {"audited_sha":sha,"review_commit":"c"*40,"verdict":verdict,
            "run_id":38660581761,"reviewer":"independent-review-actor"}

def examine(current=NEW, audited=None):
    return inspect_anchor(current,result(),expected_task_id=TASK,
                          expected_anchor_sha256=HASH,
                          review_observation=audited)

class CoreAnchorBoundaryTests(unittest.TestCase):
    def test_checksum_match_without_review_cannot_authorize(self):
        x = examine()
        self.assertTrue(x["local_checksum_match_reported"])
        self.assertFalse(x["external_anchor_provenance_verified"])
        self.assertFalse(x["publication_allowed"])
        self.assertEqual(x["integration_gate"],"BLOCKED")

    def test_historical_reject_is_not_new_sha_verdict(self):
        x = examine(audited=review())
        self.assertEqual(x["review_observation"],"OTHER_CORE_SHA_NOT_APPLICABLE")
        self.assertFalse(x["review_applies_to_core_sha"])
        self.assertFalse(x["live_execution_allowed"])

    def test_exact_reject_is_record_only_not_review_forgery(self):
        x = examine(current=OLD,audited=review())
        self.assertEqual(x["review_observation"],"REJECT_REPORTED_SOURCE_NOT_AUTHENTICATED")
        self.assertTrue(x["review_applies_to_core_sha"])
        self.assertFalse(x["independent_review_origin_verified"])

    def test_self_claimed_approve_does_not_enable_execution(self):
        x = examine(audited=review(NEW,"APPROVE"))
        self.assertEqual(x["review_observation"],"APPROVE_REPORTED_NOT_TRUSTED")
        self.assertFalse(x["publication_allowed"])
        self.assertFalse(x["live_execution_allowed"])

    def test_inconclusive_blocks(self):
        x=examine(audited=review(NEW,"INCONCLUSIVE"))
        self.assertEqual(x["review_observation"],"INCONCLUSIVE_REPORTED")
        self.assertEqual(x["integration_gate"],"BLOCKED")

    def test_malformed_sha_or_task_rejected(self):
        for sha,task,anchor in ((True,TASK,HASH),("main",TASK,HASH),
                                (NEW,"other-task",HASH),(NEW,TASK,"main")):
            with self.subTest(sha=sha,task=task),self.assertRaises(AnchorBoundaryError):
                inspect_anchor(sha,result(),expected_task_id=task,
                               expected_anchor_sha256=anchor)

    def test_wrong_reported_anchor_and_task_rejected(self):
        for field,value in (("anchor_sha256","b"*64),("task_id","NF-DEV-05-Q002"),
                            ("schema","not-core")):
            r=result();r[field]=value
            with self.subTest(field=field),self.assertRaises(AnchorBoundaryError):
                inspect_anchor(NEW,r,expected_task_id=TASK,expected_anchor_sha256=HASH)

    def test_forged_positive_authorization_fields_rejected(self):
        for key in ("external_origin_attested","model_invoked","review_approved",
                    "published","execution_allowed"):
            r=result();r[key]=True
            with self.subTest(key=key),self.assertRaises(AnchorBoundaryError):
                inspect_anchor(NEW,r,expected_task_id=TASK,expected_anchor_sha256=HASH)

    def test_false_checksum_match_rejected(self):
        r=result();r["matches_supplied_external_digest"]=False
        with self.assertRaises(AnchorBoundaryError):
            inspect_anchor(NEW,r,expected_task_id=TASK,expected_anchor_sha256=HASH)

    def test_forged_extra_security_field_rejected(self):
        r=result();r["independent_approve"]=True
        with self.assertRaises(AnchorBoundaryError):
            inspect_anchor(NEW,r,expected_task_id=TASK,expected_anchor_sha256=HASH)

    def test_fake_reviewer_schema_or_verdict_rejected(self):
        for key,value in (("verdict","REVIEW_OK"),("run_id",True),
                          ("reviewer","fake reviewer"),("review_commit","latest")):
            rec=review(NEW);rec[key]=value
            with self.subTest(key=key),self.assertRaises(AnchorBoundaryError):
                examine(audited=rec)

    def test_cannot_add_reported_signed_flag(self):
        rec=review(NEW);rec["signed"]=True
        with self.assertRaises(AnchorBoundaryError):
            examine(audited=rec)

    def test_inputs_untouched_and_all_gates_fail_closed(self):
        r=result();a=review(NEW,"APPROVE")
        r0,a0=copy.deepcopy(r),copy.deepcopy(a)
        result_obj=inspect_anchor(NEW,r,expected_task_id=TASK,
                                  expected_anchor_sha256=HASH,review_observation=a)
        self.assertEqual(r,r0)
        self.assertEqual(a,a0)
        for k in ("external_anchor_provenance_verified","independent_review_origin_verified",
                  "source_writer_isolated_from_same_uid","cross_host_lease_verified",
                  "real_qwen_proven","live_execution_allowed","automatic_retry_allowed",
                  "publication_allowed"):
            self.assertIs(result_obj[k],False)
        self.assertEqual(result_obj["handoff"],"PAUSED_BY_USER")

if __name__=="__main__":
    unittest.main()
