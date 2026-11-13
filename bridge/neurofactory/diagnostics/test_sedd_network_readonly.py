import socket
import unittest
from unittest.mock import patch

import sedd_network_readonly as m


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return None


class ReadonlyDiagnosticsTest(unittest.TestCase):
    def test_approved_targets_are_static(self):
        self.assertEqual([host for _, host, _ in m.TARGETS], ["digit.nso.ru", "cm.nso.ru"])
        self.assertEqual(m.TARGETS[1][2], (80, 443, 8080))

    def test_dns_does_not_disclose_addresses(self):
        result = m.dns_check("cm.nso.ru", resolver=lambda *a, **kw: [("secret",)])
        self.assertEqual(result, {"status": "resolved"})
        self.assertNotIn("secret", str(result))

    def test_dns_fail(self):
        def fail(*a, **kw):
            raise socket.gaierror(-2, "no name")
        self.assertEqual(m.dns_check("cm.nso.ru", fail)["status"], "dns_failure")

    def test_tcp_success(self):
        result = m.tcp_check("cm.nso.ru", 8080, connector=lambda *a, **kw: FakeConnection())
        self.assertEqual(result["status"], "tcp_connected")

    def test_tcp_timeout(self):
        def timeout(*a, **kw):
            raise TimeoutError("sensitive exception string")
        result = m.tcp_check("cm.nso.ru", 8080, connector=timeout)
        self.assertEqual(result, {"port": 8080, "status": "timeout"})
        self.assertNotIn("sensitive exception string", str(result))

    def test_tcp_refused(self):
        def denied(*a, **kw):
            raise ConnectionRefusedError("nope")
        self.assertEqual(m.tcp_check("cm.nso.ru", 443, connector=denied)["status"], "refused")

    def test_full_run_no_secret_fields(self):
        with patch.object(m, "dns_check", return_value={"status": "resolved"}), \
                patch.object(m, "tcp_check", side_effect=lambda h, p: {"port": p, "status": "timeout"}):
            result = m.run_diagnostics()
        self.assertEqual(len(result["hosts"]), 2)
        self.assertNotIn("password", str(result).lower())
        self.assertEqual(sum(len(x["ports"]) for x in result["hosts"]), 4)


if __name__ == "__main__":
    unittest.main()
