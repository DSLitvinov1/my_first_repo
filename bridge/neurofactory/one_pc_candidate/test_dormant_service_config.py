"""NEW isolated dormant SCM config gate regressions, no prior matrix reruns."""
from __future__ import annotations
import json
import unittest
from windows_setup.neurofactory_dormant_service import (
    validate_config, DormantServiceDenied, NAME, REVIEW_BLOCKED,
)

class DormantServiceConfigTests(unittest.TestCase):
    def setUp(self):
        self.good={
            "schema":"nf.windows.dormant_host_provision.v1",
            "service_name":NAME,"source_sha40":"a9bb3724c2a0636803987496e26b51af3276f55c",
            "mode":REVIEW_BLOCKED,"real_host_execution_allowed":False,
            "core_queue_allowed":False,"network_listener_allowed":False,
            "production_release_approved":False,
            "independent_review_approved":False,
            "owner_key_installed":False,"external_witness_verified":False,
        }
    def raw(self,v):
        return json.dumps(v,sort_keys=True,separators=(",",":")).encode("ascii")
    def denied(self,obj):
        with self.assertRaises(DormantServiceDenied):
            validate_config(self.raw(obj))
    def test_exact_inert_config(self):
        self.assertEqual(validate_config(self.raw(self.good)),self.good)
    def test_each_authority_flag_cannot_enable(self):
        for key in ("real_host_execution_allowed","core_queue_allowed",
                    "network_listener_allowed","production_release_approved",
                    "independent_review_approved","owner_key_installed",
                    "external_witness_verified"):
            with self.subTest(key=key): self.denied({**self.good,key:True})
    def test_config_cannot_claim_live_production_mode(self):
        self.denied({**self.good,"mode":"PRODUCTION_RELEASED"})
    def test_config_cannot_switch_service_identity(self):
        self.denied({**self.good,"service_name":"NeurofactoryCoreAdmissionCI"})
    def test_config_requires_exact_sha(self):
        self.denied({**self.good,"source_sha40":"a"*39})
    def test_extra_field_or_missing_field_denied(self):
        self.denied({**self.good,"allow_override":True})
        d=dict(self.good);d.pop("core_queue_allowed")
        self.denied(d)
    def test_duplicate_privileged_fields_denied(self):
        raw=self.raw(self.good)
        malicious=raw[:-1]+b',"core_queue_allowed":true}'
        with self.assertRaises(DormantServiceDenied):
            validate_config(malicious)
    def test_invalid_or_oversized_utf8_denied(self):
        for raw in (b"bad",b"x"*1401,b"\xff"*300):
            with self.subTest(raw=raw[:8]), self.assertRaises(DormantServiceDenied):
                validate_config(raw)
if __name__=="__main__":unittest.main()
