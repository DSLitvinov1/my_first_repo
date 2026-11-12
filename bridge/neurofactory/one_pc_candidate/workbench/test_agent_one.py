"""Focused tests for read-only agent run durability and rejection boundaries."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer
import json
import socket
import threading
from work_server import make_handler

from work_core import WorkStore, WorkDenied
from agent_one import AgentOne, AuditHTML, validated_url, public_dns, fetch_public_html


class AgentOneTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.store = WorkStore(base / "projects", base / "data")
        self.project = self.store.create_project("Сайты клиента", "empty")["id"]

    def test_real_html_structure_and_warnings(self):
        html = ('<!doctype html><html><head><title>Юридическая помощь</title>'
                '<meta name="robots" content="noindex,nofollow">'
                '<meta name="description" content="Заявка">'
                '</head><body><h1>Консультация</h1><a href="/x">Подробнее</a>'
                '<form hidden aria-disabled="true" id="lead-form">'
                '<input name="phone" type="tel" required>'
                '<input name="consent" type="checkbox" required>'
                '</form></body></html>')
        page = AuditHTML()
        page.feed(html)
        obj = page.report("https://example.org/", {})
        self.assertEqual(obj["title"], "Юридическая помощь")
        self.assertEqual(obj["form_count"], 1)
        self.assertEqual(obj["forms"][0]["fields"][0]["name"], "phone")
        self.assertIn("SEARCH_INDEX_BLOCKED", obj["warnings"])
        self.assertIn("HIDDEN_FORM_PRESENT", obj["warnings"])
        self.assertEqual(obj["link_count"], 1)

    def test_public_url_rules_and_private_dns(self):
        self.assertEqual(validated_url("https://example.org"), "https://example.org/")
        for url in ("http://example.org", "https://localhost/",
                    "https://127.0.0.1/", "https://user:password@example.org/",
                    "https://example.org:8443", "file:///etc/passwd",
                    "https://example.org/#fragment", "https://127.0.0.1.nip.io\\evil"):
            with self.subTest(url=url), self.assertRaises(WorkDenied):
                validated_url(url)
        with patch("agent_one.socket.getaddrinfo", return_value=[
            (2, 1, 6, "", ("127.0.0.1", 443))
        ]):
            with self.assertRaisesRegex(WorkDenied, "PRIVATE_NETWORK"):
                public_dns("example.org")
        with patch("agent_one.public_dns", return_value="93.184.216.34"):
            with patch("agent_one.PinnedHTTPSConnection") as connection:
                connection.return_value.getresponse.return_value.status = 302
                with self.assertRaisesRegex(WorkDenied, "REDIRECT"):
                    fetch_public_html("https://example.org/")
                connection.assert_called_once_with("example.org", "93.184.216.34")

    def test_durable_two_site_workflow_and_no_replay(self):
        seen = []
        def fake(url):
            seen.append(url)
            return {"url": url, "warnings": ["SEARCH_INDEX_BLOCKED"]}
        agent = AgentOne(self.store, fetcher=fake)
        run = agent.create_audit(self.project,
                                 ["https://potrebpravo.ru/", "https://semya-yurist.ru/"])
        self.assertEqual(run["state"], "READY")
        report = agent.execute(run["id"], self.project)
        self.assertEqual(report["state"], "DONE")
        self.assertEqual(len(seen), 2)
        self.assertEqual(len([x for x in report["steps"] if x["state"]=="DONE"]), 2)
        agent2 = AgentOne(self.store, fetcher=fake)
        self.assertEqual(agent2.get_run(run["id"], self.project)["state"], "DONE")
        with self.assertRaisesRegex(WorkDenied, "REPLAY_REFUSED"):
            agent2.execute(run["id"], self.project)
        self.assertEqual(len(seen), 2)

    def test_partial_failure_preserves_successes(self):
        def fake(url):
            if "semya" in url:
                raise URLError("network down")
            return {"url": url}
        agent = AgentOne(self.store, fetcher=fake)
        run = agent.create_audit(self.project,
                                 ["https://potrebpravo.ru/", "https://semya-yurist.ru/"])
        after = agent.execute(run["id"], self.project)
        self.assertEqual(after["state"], "PARTIAL")
        self.assertEqual(after["steps"][0]["state"], "DONE")
        self.assertEqual(after["steps"][1]["error"], "AUDIT_TOOL_FAILED")
        self.assertEqual(len(agent.runs(self.project)), 1)

    def test_interrupted_run_is_fenced_after_recovery(self):
        agent = AgentOne(self.store, fetcher=lambda url: {})
        run = agent.create_audit(self.project, ["https://example.org"])
        with self.store.db() as c:
            c.execute("UPDATE one_runs SET state='RUNNING' WHERE id=?", (run["id"],))
            c.execute("UPDATE one_steps SET state='RUNNING' WHERE run_id=?", (run["id"],))
            c.commit()
        recovered = AgentOne(self.store)
        self.assertEqual(recovered.get_run(run["id"], self.project)["state"],
                         "UNKNOWN_NO_RETRY")
        with self.assertRaisesRegex(WorkDenied, "REPLAY_REFUSED"):
            recovered.execute(run["id"], self.project)

    def test_concurrent_external_audits_are_denied(self):
        entered, release = threading.Event(), threading.Event()
        def slow(url):
            entered.set()
            self.assertTrue(release.wait(timeout=4))
            return {"url": url}
        agent = AgentOne(self.store, fetcher=slow)
        first = agent.create_audit(self.project, ["https://example.org/"])
        second = agent.create_audit(self.project, ["https://example.net/"])
        thread = threading.Thread(target=agent.execute,
                                  args=(first["id"], self.project), daemon=True)
        thread.start()
        try:
            self.assertTrue(entered.wait(timeout=3))
            with self.assertRaisesRegex(WorkDenied, "BUSY_ONE_RUN"):
                agent.execute(second["id"], self.project)
            self.assertEqual(agent.get_run(second["id"], self.project)["state"], "READY")
        finally:
            release.set()
            thread.join(timeout=4)
        self.assertEqual(agent.get_run(first["id"], self.project)["state"], "DONE")

    def test_invalid_no_record_and_project_isolation(self):
        agent = AgentOne(self.store, fetcher=lambda url: {})
        for urls in ([], ["http://example.org/"],
                     ["https://example.org/"]*2,
                     ["https://example.org/"]*5):
            with self.assertRaises(WorkDenied):
                agent.create_audit(self.project, urls)
        self.assertEqual(agent.runs(self.project), [])
        run = agent.create_audit(self.project, ["https://example.org/"])
        other = self.store.create_project("Другой проект", "empty")["id"]
        with self.assertRaisesRegex(WorkDenied, "NOT_FOUND"):
            agent.get_run(run["id"], other)
        self.assertFalse(agent.capabilities()["model_can_execute_tools"])



class OneApiTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = WorkStore(root / "projects", root / "data")
        self.project = self.store.create_project("API тест", "empty")["id"]
        self.seen = []
        def fetch(url):
            self.seen.append(url)
            return {"url": url, "warnings": ["SEARCH_INDEX_BLOCKED"],
                    "title": "Mock test", "description": "description",
                    "robots": "noindex", "x_robots_tag": "", "h1": ["Test"],
                    "form_count": 0, "forms": [], "link_count": 0}
        agent = AgentOne(self.store, fetcher=fetch)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0))
            self.port = sock.getsockname()[1]
        self.token = "test-only-strong-verified-token"
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", self.port),
            make_handler(self.store, Path(__file__).parent, self.token,
                         self.port, agent=agent))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, path, method="GET", payload=None, token=None, origin=None):
        headers = {"Host": "127.0.0.1:" + str(self.port)}
        data = None
        if method != "GET":
            headers.update({
                "Content-Type": "application/json",
                "X-NF-Work-Token": self.token if token is None else token,
                "Origin": "http://127.0.0.1:" + str(self.port) if origin is None else origin})
            data = json.dumps(payload).encode("utf-8")
        req = Request("http://127.0.0.1:"+str(self.port)+path,
                      headers=headers,data=data,method=method)
        try:
            with urlopen(req,timeout=5) as r:
                return r.status,json.loads(r.read())
        except HTTPError as e:
            return e.code,json.loads(e.read())

    def test_real_http_capability_and_authenticated_site_audit(self):
        code,cap = self.call("/api/agent/capabilities")
        self.assertEqual(code,200)
        self.assertFalse(cap["model_can_execute_tools"])
        url = "/api/agent/audits"
        payload = {"project_id": self.project, "urls": ["https://example.org/"]}
        denied,_=self.call(url,"POST",payload,token="forged")
        self.assertEqual(denied,400)
        denied,_=self.call(url,"POST",payload,origin="https://other.invalid")
        self.assertEqual(denied,400)
        self.assertEqual(self.seen,[])
        status,run = self.call(url,"POST",payload)
        self.assertEqual(status,201)
        self.assertEqual(run["state"],"DONE")
        self.assertEqual(self.seen, ["https://example.org/"])
        status,history=self.call("/api/agent/runs?project_id="+self.project)
        self.assertEqual(status,200)
        self.assertEqual(history["runs"][0]["id"], run["id"])
        denied,_=self.call("/api/agent/runs")
        self.assertEqual(denied,400)
        denied,_=self.call("/api/execute","POST",{})
        self.assertEqual(denied,400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
