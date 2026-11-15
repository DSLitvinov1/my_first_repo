"""Static safety regression for the optional owner Playwright MCP config.

This test does not start a browser or grant any browser/OS permissions.
"""
import json
from pathlib import Path
import unittest
from urllib.parse import urlsplit
from playwright_access_policy import expected_config_origins, classify, PlaywrightAccessDenied

CONFIG = Path(__file__).with_name("playwright_owner_mcp.json")

class PlaywrightMcpConfigTests(unittest.TestCase):
    def setUp(self):
        self.cfg=json.loads(CONFIG.read_text(encoding="utf-8"))
    def test_extension_user_controlled_only(self):
        self.assertIs(self.cfg.get("extension"),True)
        self.assertIs(self.cfg.get("saveSession"),False)
        self.assertIs(self.cfg.get("allowUnrestrictedFileAccess"),False)
        self.assertEqual(self.cfg.get("server",{}).get("host"),"127.0.0.1")
        self.assertNotIn("cdpEndpoint",self.cfg.get("browser",{}))
        self.assertNotIn("port",self.cfg.get("server",{}))
        self.assertNotIn("secrets",self.cfg)
        self.assertNotIn("initScript",self.cfg.get("browser",{}))
        self.assertNotIn("initPage",self.cfg.get("browser",{}))
    def test_all_approved_owner_domains_present(self):
        hosts=set(self.cfg["network"]["allowedOrigins"])
        for origin in expected_config_origins("oleg-legal"):
            self.assertIn(origin,hosts)
    def test_no_insecure_network_origins(self):
        hosts=self.cfg["network"]["allowedOrigins"]
        self.assertEqual(len(hosts),len(set(hosts)))
        self.assertTrue(hosts)
        for origin in hosts:
            u=urlsplit(origin)
            self.assertEqual(u.scheme,"https")
            self.assertNotIn("*",origin)
            self.assertIsNone(u.query or None)
            self.assertIsNone(u.fragment or None)
            self.assertEqual(origin,f"https://{u.hostname}")
    def test_config_is_not_an_authorization_grant(self):
        # Only the local ONE approval flow or extension tab selection grants
        # actual access. Public JSON file may never grant mutation by itself.
        for origin in expected_config_origins("oleg-legal"):
            decision=classify("oleg-legal",origin+"/","submit")
            self.assertTrue(decision.requires_local_owner_approval)
            self.assertEqual(decision.state,"PENDING_LOCAL_OWNER_APPROVAL")
    def test_unpaired_origin_refused(self):
        with self.assertRaises(PlaywrightAccessDenied):
            classify("oleg-legal","https://totally-unknown.example/","snapshot")

if __name__ == "__main__":
    unittest.main()
