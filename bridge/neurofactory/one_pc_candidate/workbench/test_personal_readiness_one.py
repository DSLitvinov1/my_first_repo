"""Private-use readiness report: no accounts, secrets or host details exposed."""
import unittest
from personal_readiness_one import assess_private_readiness

class PersonalReadinessTests(unittest.TestCase):
    def test_defaults_are_explicitly_not_ready(self):
        result = assess_private_readiness()
        self.assertEqual(result["mode"], "personal_single_owner")
        self.assertFalse(result["read_only_web_task_ready"])
        self.assertFalse(result["external_write_verified"])
        self.assertEqual(len(result["checks"]), 5)
        self.assertTrue(result["next"])

    def test_private_use_omits_commercial_work_but_not_security(self):
        r = assess_private_readiness()
        self.assertIn("публичный сервер", r["not_required_for_private_use"])
        self.assertIn("контроль доступа и секретов", r["still_required"])
        self.assertIn("подтверждение внешних изменений", r["still_required"])

    def test_browser_and_model_are_jointly_required(self):
        for browser, qwen, expected in [
            ({}, {}, False),
            ({"configured":True}, {}, False),
            ({}, {"configured":True}, False),
            ({"configured":True}, {"configured":True}, True),
        ]:
            with self.subTest(browser=browser, qwen=qwen):
                r = assess_private_readiness(browser=browser,qwen=qwen)
                self.assertEqual(r["read_only_web_task_ready"],expected)

    def test_windows_needs_windows_and_explicit_grant(self):
        base={"configured":True,"allowed_apps":["notepad.exe"]}
        r = assess_private_readiness(desktop=base,platform="posix")
        self.assertFalse(r["desktop_test_ready"])
        self.assertTrue(assess_private_readiness(
            desktop=base, platform="nt")["desktop_test_ready"])
        self.assertFalse(assess_private_readiness(
            desktop={"configured":False},platform="nt")["desktop_test_ready"])

    def test_google_and_bitrix_are_not_automatically_verified(self):
        r = assess_private_readiness(
            google={"configured":True,"connected_scopes":["tasks"]},
            bitrix_connected=True,
            services={"configured":{"google.tasks":True,"bitrix.tasks":True}},
            platform="nt")
        self.assertFalse(r["external_write_verified"])
        self.assertEqual(r["checks"][3]["status"],"needs_live_test")
        self.assertEqual(r["checks"][4]["status"],"needs_live_test")

    def test_adapter_without_account_scope_is_not_connected(self):
        r=assess_private_readiness(
            google={"configured":True,"connected_scopes":[]},
            bitrix_connected=False,
            services={"configured":{"google.tasks":True,"bitrix.tasks":True}})
        self.assertEqual(r["checks"][3]["status"],"needs_setup")
        self.assertEqual(r["checks"][4]["status"],"needs_setup")

    def test_result_does_not_include_sensitive_input_strings(self):
        secret="super-secret-user-token-TEST"
        r=assess_private_readiness(
            browser={"configured":True,"allowed_hosts":[secret]},
            desktop={"configured":True,"allowed_apps":[secret]},
            qwen={"configured":True,"model":secret},
            google={"connected_scopes":["tasks"],"access_token":secret},
            services={"configured":{"google.tasks":True}})
        self.assertNotIn(secret,str(r))
        self.assertNotIn("access_token",str(r))

    def test_readiness_http_is_local_token_protected(self):
        import json
        import socket
        import tempfile
        import threading
        from pathlib import Path
        from http.server import ThreadingHTTPServer
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen
        from work_core import WorkStore
        from work_server import make_handler

        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            store=WorkStore(root/"projects",root/"data")
            with socket.socket() as free:
                free.bind(("127.0.0.1",0))
                port=free.getsockname()[1]
            token="private-readiness-http-test-owner"
            server=ThreadingHTTPServer(
                ("127.0.0.1",port),
                make_handler(store,Path(__file__).resolve().parent,token,port))
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                url="http://127.0.0.1:"+str(port)+"/api/private/readiness"
                with self.assertRaises(HTTPError) as result:
                    urlopen(url,timeout=3)
                self.assertEqual(result.exception.code,400)
                req=Request(url,headers={"X-NF-Work-Token":token})
                with urlopen(req,timeout=3) as response:
                    self.assertEqual(response.status,200)
                    report=json.load(response)
                self.assertEqual(report["mode"],"personal_single_owner")
                self.assertFalse(report["external_write_verified"])
                self.assertEqual(len(report["checks"]),5)
                self.assertNotIn(token,json.dumps(report))
            finally:
                server.shutdown()
                server.server_close()

    def test_malformed_connector_states_fail_closed(self):
        r=assess_private_readiness(
            browser="ready",desktop=["yes"],qwen={"configured":"true"},
            google={"connected_scopes":"tasks"},
            services={"configured":["google.tasks"]},
            bitrix_connected=1,platform="mystery")
        self.assertFalse(r["read_only_web_task_ready"])
        self.assertFalse(r["desktop_test_ready"])
        self.assertEqual(r["ready_count"],0)


if __name__ == "__main__":
    unittest.main()
