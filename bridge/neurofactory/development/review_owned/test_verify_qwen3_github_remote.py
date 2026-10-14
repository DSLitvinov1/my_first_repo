"""Negative tests for direct-read GitHub provenance, no real requests or models."""
import copy
import unittest
from unittest import mock

import verify_qwen3_github_evidence as attestation
from test_verify_qwen3_github_evidence import (
    ARTIFACT_ID, HEAD, RUN_ID, SOURCE, fixture, pack,
)


def staged_api():
    run, jobs, artifact, _ = fixture()
    return {
        "actions/runs/" + str(RUN_ID): run,
        "actions/runs/" + str(RUN_ID) + "/jobs?per_page=100": {
            "total_count": 1, "jobs": jobs,
        },
        "actions/runs/" + str(RUN_ID) + "/artifacts?per_page=100": {
            "total_count": 1, "artifacts": [artifact],
        },
    }


def check(data):
    _, _, _, files = fixture()
    with mock.patch.object(attestation, "_github_api_json",
                           side_effect=lambda path: data[path]) as source:
        verdict=attestation.inspect_trusted_github_artifact(
            RUN_ID, ARTIFACT_ID, pack(files), HEAD, SOURCE)
    return verdict, source.call_count


class TrustedAPIReviewTests(unittest.TestCase):
    def test_three_expected_fixed_github_lookups_only(self):
        verdict, count = check(staged_api())
        self.assertEqual(count, 3)
        self.assertTrue(verdict["github_api_retrieved_independently"])
        self.assertFalse(verdict["independent_review_owner_approved"])
        self.assertFalse(verdict["model_process_cryptographically_authenticated"])
        self.assertFalse(verdict["publisher_allowed"])

    def test_wrong_artifact_identity_fails_closed(self):
        api = staged_api()
        key="actions/runs/"+str(RUN_ID)+"/artifacts?per_page=100"
        api[key]["artifacts"][0]["id"]=ARTIFACT_ID+1
        with self.assertRaises(attestation.ReviewProofError):
            check(api)

    def test_partial_job_listing_fails_closed(self):
        api = staged_api()
        key="actions/runs/"+str(RUN_ID)+"/jobs?per_page=100"
        api[key]["total_count"] = 2
        with self.assertRaises(attestation.ReviewProofError):
            check(api)

    def test_partial_artifact_listing_fails_closed(self):
        api = staged_api()
        key="actions/runs/"+str(RUN_ID)+"/artifacts?per_page=100"
        api[key]["total_count"] = 101
        with self.assertRaises(attestation.ReviewProofError):
            check(api)

    def test_fake_external_metadata_source_rejected(self):
        api=staged_api()
        api["actions/runs/"+str(RUN_ID)]["head_sha"]="f"*40
        with self.assertRaises(attestation.ReviewProofError):
            check(api)

    def test_forged_callback_cannot_make_publisher_approved(self):
        api=staged_api()
        report, _=check(api)
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["merge_authorized"])
        self.assertFalse(report["independent_review_owner_approved"])

    def test_reject_invalid_run_and_artifact_ids_before_network(self):
        for run, artifact in ((True, ARTIFACT_ID), (-1, ARTIFACT_ID),
                              (RUN_ID, True), (RUN_ID, 0)):
            with self.subTest(run=run, artifact=artifact):
                with mock.patch.object(attestation, "_github_api_json") as net:
                    with self.assertRaises(attestation.ReviewProofError):
                        attestation.inspect_trusted_github_artifact(
                            run, artifact, b"", HEAD, SOURCE)
                    net.assert_not_called()

    def test_boolean_run_attempt_does_not_equal_a_trusted_first_run(self):
        api=staged_api()
        api["actions/runs/"+str(RUN_ID)]["run_attempt"]=True
        with self.assertRaises(attestation.ReviewProofError):
            check(api)

    def test_http_redirect_to_another_host_is_refused(self):
        import io
        import os
        def forged_opener(*handlers):
            self.assertEqual(len(handlers), 1)
            handler=handlers[0]()
            with self.assertRaises(attestation.ReviewProofError):
                handler.redirect_request(None,None,302,"Found",{},
                                         "https://attacker.invalid/steal")
            class ReadOnlyOpener:
                def open(self, request, timeout=20):
                    self_request=request
                    self.assertTrue(self_request.full_url.startswith(
                        "https://api.github.com/repos/DSLitvinov1/my_first_repo/"))
                    return io.BytesIO(b'{"verified":true}')
            return ReadOnlyOpener()
        with mock.patch.object(attestation.urllib.request,"build_opener",
                               side_effect=forged_opener), mock.patch.dict(
                                   os.environ,{"GITHUB_TOKEN":"fake-read-only-token"}):
            result=attestation._github_api_json("actions/runs/42")
        self.assertTrue(result["verified"])

    def test_api_cannot_be_redirected_to_untrusted_host(self):
        for path in ("https://attacker.invalid/x",
                     "../actions/runs/3", "actions/runs/1/../secret",
                     "actions/runs/1/jobs?per_page=999"):
            with self.subTest(path=path):
                with self.assertRaises(attestation.ReviewProofError):
                    attestation._github_api_json(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
