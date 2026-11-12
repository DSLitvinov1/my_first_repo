"""NEIROZAVOD ONE v0.2: bounded, durable, READ-ONLY website audit adapter.

This module deliberately does NOT grant model output shell, browser-write, Google,
customer CRM, files, CORE9 or protected HOST capabilities. Those require separate
reviewed connectors with per-operation grants.
"""
from __future__ import annotations

from html.parser import HTMLParser
from http.client import HTTPSConnection, HTTPException
from ssl import SSLError
import ipaddress
import json
import re
import socket
import sqlite3
import threading
import time
from urllib import parse
import uuid

from work_core import WorkDenied

MAX_HTML = 512 * 1024
MAX_SITES = 4
MAX_TEXT = 180
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{1,251})[a-z0-9]$")
AUDIT_TOOLS = ("site.audit",)


def validated_url(value):
    if not isinstance(value, str) or not 12 <= len(value) <= 400:
        raise WorkDenied("AUDIT_URL_INVALID")
    try:
        url = parse.urlsplit(value.strip())
        host = (url.hostname or "").encode("idna").decode("ascii").lower()
        port = url.port
    except (ValueError, UnicodeError):
        raise WorkDenied("AUDIT_URL_INVALID")
    if (url.scheme != "https" or not host or not HOST_RE.fullmatch(host)
            or ".." in host or "." not in host or host.endswith(".local")
            or url.username is not None or url.password is not None
            or port not in (None, 443) or url.fragment
            or len(url.path) > 180 or len(url.query) > 100
            or "\\" in value or any(ord(x) < 33 for x in value)):
        raise WorkDenied("AUDIT_URL_REFUSED")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise WorkDenied("AUDIT_IP_LITERAL_REFUSED")
    return parse.urlunsplit(("https", host, url.path or "/", url.query, ""))


def public_dns(host):
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise WorkDenied("AUDIT_DNS_FAILED")
    if not answers:
        raise WorkDenied("AUDIT_DNS_FAILED")
    checked = []
    for answer in answers:
        ip = ipaddress.ip_address(answer[4][0].split("%", 1)[0])
        if not ip.is_global:
            raise WorkDenied("AUDIT_PRIVATE_NETWORK_REFUSED")
        checked.append(str(ip))
    # Pin the validated address: a second DNS lookup must never redirect the
    # actual TCP connection to loopback/private infrastructure.
    return checked[0]


class AuditHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = ""
        self.robots = ""
        self.canonical = ""
        self.h1 = []
        self.forms = []
        self.links = 0
        self._capture = None
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._capture = "title"
        elif tag == "h1":
            self._capture = "h1"
            self.h1.append("")
        elif tag == "meta":
            name = (a.get("name") or "").lower()
            if name == "description":
                self.description = (a.get("content") or "")[:MAX_TEXT]
            elif name == "robots":
                self.robots = (a.get("content") or "")[:MAX_TEXT]
        elif tag == "link" and (a.get("rel") or "").lower() == "canonical":
            self.canonical = (a.get("href") or "")[:400]
        elif tag == "a" and a.get("href"):
            self.links += 1
        elif tag == "form":
            self._form = {
                "id": (a.get("id") or "")[:60],
                "method": (a.get("method") or "get").lower()[:10],
                "action": (a.get("action") or "")[:140],
                "hidden": ("hidden" in a or a.get("aria-disabled") == "true"),
                "fields": [],
            }
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = (a.get("name") or a.get("id") or "")[:60]
            if name and len(self._form["fields"]) < 30:
                self._form["fields"].append({
                    "name": name, "type": (a.get("type") or tag)[:24],
                    "required": ("required" in a),
                })

    def handle_endtag(self, tag):
        if tag in ("title", "h1"):
            self._capture = None
        elif tag == "form":
            self._form = None

    def handle_data(self, text):
        if self._capture == "title":
            self.title = (self.title + text)[:MAX_TEXT]
        elif self._capture == "h1" and self.h1:
            self.h1[-1] = (self.h1[-1] + text)[:MAX_TEXT]

    def report(self, url, headers):
        robot_headers = headers.get("x-robots-tag", "")[:MAX_TEXT]
        warnings = []
        if "noindex" in (self.robots + " " + robot_headers).lower():
            warnings.append("SEARCH_INDEX_BLOCKED")
        if not self.description:
            warnings.append("META_DESCRIPTION_MISSING")
        if len(self.h1) != 1:
            warnings.append("H1_COUNT_" + str(len(self.h1)))
        if any(f["hidden"] for f in self.forms):
            warnings.append("HIDDEN_FORM_PRESENT")
        return {
            "url": url, "title": self.title.strip(),
            "description": self.description, "robots": self.robots,
            "x_robots_tag": robot_headers, "canonical": self.canonical,
            "h1": [x.strip() for x in self.h1[:12]],
            "form_count": len(self.forms), "forms": self.forms[:25],
            "link_count": self.links, "warnings": warnings,
            "scope": "single_html_document_no_js_execution",
        }


class PinnedHTTPSConnection(HTTPSConnection):
    """TLS hostname verification against the origin, TCP to audited public IP."""
    def __init__(self, hostname, public_ip):
        super().__init__(hostname, port=443, timeout=10)
        self.public_ip = public_ip

    def connect(self):
        plain = socket.create_connection((self.public_ip, self.port),
                                         timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(plain,
                                                  server_hostname=self.host)
        except BaseException:
            plain.close()
            raise


def fetch_public_html(url):
    target = validated_url(url)
    parts = parse.urlsplit(target)
    host = parts.hostname
    pinned_ip = public_dns(host)
    conn = PinnedHTTPSConnection(host, pinned_ip)
    path = parts.path + (("?" + parts.query) if parts.query else "")
    try:
        conn.request("GET", path, headers={
            "Host": host,
            "User-Agent": "NeirozavodWorkOne/0.2 (read-only audit)",
            "Accept": "text/html",
            "Accept-Encoding": "identity",
        })
        response = conn.getresponse()
        if response.status != 200:
            # Intentionally do not follow redirects; redirected targets may
            # escape the exact public origin approved by the owner.
            raise WorkDenied("AUDIT_HTTP_NOT_OK_OR_REDIRECT")
        mime = response.headers.get_content_type().lower()
        if mime not in ("text/html", "application/xhtml+xml"):
            raise WorkDenied("AUDIT_NOT_HTML")
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise WorkDenied("AUDIT_ENCODING_REFUSED")
        raw = response.read(MAX_HTML + 1)
        if len(raw) > MAX_HTML:
            raise WorkDenied("AUDIT_BODY_TOO_LARGE")
        charset = response.headers.get_content_charset() or "utf-8"
        if charset.lower() not in ("utf-8", "windows-1251", "iso-8859-1"):
            raise WorkDenied("AUDIT_CHARSET_UNSUPPORTED")
        page = AuditHTML()
        page.feed(raw.decode(charset, errors="replace"))
        return page.report(target, {k.lower(): v for k, v in response.headers.items()})
    except WorkDenied:
        raise
    except (HTTPException, TimeoutError, OSError, SSLError, UnicodeError):
        raise WorkDenied("AUDIT_NETWORK_UNAVAILABLE")
    finally:
        conn.close()


class AgentOne:
    """Durable, manually triggered read-only task runner. No model authority."""

    def __init__(self, store, fetcher=None):
        self.store = store
        self.fetcher = fetcher or fetch_public_html
        self.lock = threading.RLock()
        self.run_slot = threading.BoundedSemaphore(1)
        with self.store.db() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS one_runs (
                id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                state TEXT NOT NULL, created INTEGER NOT NULL,
                updated INTEGER NOT NULL, error TEXT
            );
            CREATE TABLE IF NOT EXISTS one_steps (
                run_id TEXT NOT NULL REFERENCES one_runs(id),
                position INTEGER NOT NULL, tool TEXT NOT NULL,
                argument TEXT NOT NULL, state TEXT NOT NULL,
                result_json TEXT, error TEXT,
                PRIMARY KEY(run_id,position)
            );
            CREATE INDEX IF NOT EXISTS one_runs_project
                ON one_runs(project_id,created);
            """)
            c.execute("UPDATE one_runs SET state='UNKNOWN_NO_RETRY',"
                      "error='INTERRUPTED_EXTERNAL_ACTION' WHERE state='RUNNING'")
            c.execute("UPDATE one_steps SET state='UNKNOWN_NO_RETRY',"
                      "error='INTERRUPTED_EXTERNAL_ACTION' WHERE state='RUNNING'")
            c.commit()

    def capabilities(self):
        return {
            "implemented": ["workspace.projects", "workspace.edit_with_approval",
                            "qwen.inert_draft_existing", "site.audit"],
            "not_connected": ["browser.interactive", "desktop.remote_actions",
                              "google.accounts", "tinyfish.remote",
                              "core9.host.autonomous_grants", "external_crm.write"],
            "network_policy": "public_https_only_no_redirect",
            "model_can_execute_tools": False,
        }

    def create_audit(self, project_id, urls):
        self.store.project(project_id)
        if (not isinstance(urls, list) or not 1 <= len(urls) <= MAX_SITES
                or len(set(map(str, urls))) != len(urls)):
            raise WorkDenied("AUDIT_SITE_COUNT_REFUSED")
        targets = [validated_url(url) for url in urls]
        if len(set(targets)) != len(targets):
            raise WorkDenied("AUDIT_DUPLICATE_URL")
        with self.lock, self.store.db() as c:
            ident = uuid.uuid4().hex
            now = int(time.time())
            c.execute("INSERT INTO one_runs VALUES (?,?,?,?,?,NULL)",
                      (ident, project_id, "READY", now, now))
            for pos, url in enumerate(targets):
                c.execute("INSERT INTO one_steps VALUES (?,?,?,?,?,?,NULL)",
                          (ident, pos, "site.audit", url, "PENDING", None))
            self.store.event(c, "ONE_AUDIT_CREATED", project_id,
                             {"run_id": ident, "sites": len(targets)})
            c.commit()
        return self.get_run(ident, project_id)

    def get_run(self, ident, project_id):
        self.store.project(project_id)
        with self.store.db() as c:
            r = c.execute("SELECT * FROM one_runs WHERE id=? AND project_id=?",
                          (ident, project_id)).fetchone()
            if r is None:
                raise WorkDenied("AGENT_RUN_NOT_FOUND")
            steps = c.execute("SELECT position,tool,argument,state,result_json,error "
                              "FROM one_steps WHERE run_id=? ORDER BY position",
                              (ident,)).fetchall()
        return {"id": r["id"], "project_id": r["project_id"],
                "state": r["state"], "error": r["error"],
                "created": r["created"], "updated": r["updated"],
                "steps": [
                    {"tool": s["tool"], "target": s["argument"],
                     "state": s["state"], "error": s["error"],
                     "result": json.loads(s["result_json"]) if s["result_json"] else None}
                    for s in steps]}

    def runs(self, project_id):
        self.store.project(project_id)
        with self.store.db() as c:
            ids = [x[0] for x in c.execute(
                "SELECT id FROM one_runs WHERE project_id=? ORDER BY created DESC,id DESC LIMIT 15",
                (project_id,))]
        return [self.get_run(x, project_id) for x in ids]

    def execute(self, run_id, project_id):
        """Single concurrent external audit; no uncontrolled site fan-out."""
        if not self.run_slot.acquire(blocking=False):
            raise WorkDenied("AGENT_BUSY_ONE_RUN_AT_A_TIME")
        try:
            return self._execute_once(run_id, project_id)
        finally:
            self.run_slot.release()

    def _execute_once(self, run_id, project_id):
        """Execute once. Individual sites are checkpointed; no automatic retries."""
        with self.lock, self.store.db() as c:
            r = c.execute("SELECT * FROM one_runs WHERE id=? AND project_id=?",
                          (run_id, project_id)).fetchone()
            if r is None or r["state"] != "READY":
                raise WorkDenied("AGENT_REPLAY_REFUSED")
            c.execute("UPDATE one_runs SET state='RUNNING',updated=? WHERE id=?",
                      (int(time.time()), run_id))
            c.commit()
        run = self.get_run(run_id, project_id)
        for pos, step in enumerate(run["steps"]):
            with self.store.db() as c:
                c.execute("UPDATE one_steps SET state='RUNNING' WHERE run_id=? AND position=?",
                          (run_id, pos))
                c.commit()
            try:
                report = self.fetcher(step["target"])
                if not isinstance(report, dict):
                    raise WorkDenied("AGENT_BAD_TOOL_RESULT")
                encoded = json.dumps(report, ensure_ascii=False)
                if len(encoded.encode("utf-8")) > 64 * 1024:
                    raise WorkDenied("AGENT_TOOL_RESULT_TOO_LARGE")
                state, err = "DONE", None
            except Exception:
                encoded, state, err = None, "FAILED", "AUDIT_TOOL_FAILED"
            with self.store.db() as c:
                c.execute("UPDATE one_steps SET state=?,result_json=?,error=? "
                          "WHERE run_id=? AND position=?",
                          (state, encoded, err, run_id, pos))
                c.commit()
        with self.store.db() as c:
            failed = c.execute("SELECT count(*) FROM one_steps WHERE run_id=? AND state!='DONE'",
                               (run_id,)).fetchone()[0]
            state = "PARTIAL" if failed else "DONE"
            c.execute("UPDATE one_runs SET state=?,updated=?,error=? WHERE id=?",
                      (state, int(time.time()), "SITE_AUDIT_PARTIAL" if failed else None, run_id))
            self.store.event(c, "ONE_AUDIT_" + state, project_id,
                             {"run_id": run_id, "failed": failed})
            c.commit()
        return self.get_run(run_id, project_id)
