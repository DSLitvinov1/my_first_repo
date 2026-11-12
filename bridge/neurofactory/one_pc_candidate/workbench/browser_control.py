"""Work ONE: per-project, owner-initiated browser mouse actions.

A Chrome child process gets a fresh, ephemeral profile bound to ONE approved
public HTTPS hostname and pinned IP. Never use with an elevated OS account.
Production deployments additionally need OS egress isolation for Chromium.
"""
from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit

from agent_one import validated_url
from work_core import WorkDenied

BROWSER_TIMEOUT = 24
BROWSER_LIFETIME = 10 * 60
ALLOWED_OPS = {"move", "click", "scroll", "back", "frame", "inspect"}
MAX_HOSTS = 8


class BrowserController:
    def __init__(self, store, assets: Path, allowed_hosts=(), executable=None,
                 node="node"):
        self.store = store
        self.assets = assets
        self.executable = Path(executable) if executable else None
        self.node = node
        self.lock = threading.RLock()
        hosts = tuple(str(h).strip().lower() for h in allowed_hosts if str(h).strip())
        if len(hosts) > MAX_HOSTS:
            raise WorkDenied("BROWSER_HOST_LIST_TOO_LARGE")
        for host in hosts:
            if urlsplit(validated_url("https://" + host + "/")).hostname != host:
                raise WorkDenied("BROWSER_ALLOWED_HOST_INVALID")
        self.allowed_hosts = frozenset(hosts)
        self.proc = None
        self.messages = None
        self.serial = 0
        self.session = None

    def capabilities(self):
        return {"configured": bool(self.allowed_hosts and self.executable),
                "allowed_hosts": sorted(self.allowed_hosts),
                "actions": ["open", "move", "click", "scroll", "back", "frame", "close"],
                "permission": "owner_click_only",
                "mode": "ephemeral_browser_read_only_no_form_submit",
                "desktop_mouse": False,
                "requires_os_egress_sandbox_for_production": True}

    def status(self, project=None):
        with self.lock:
            info = self.capabilities()
            info["session"] = None
            if self.session and (project is None or self.session["project"] == project):
                info["session"] = {"id": self.session["id"],
                                   "host": self.session["host"],
                                   "opened": self.session["opened"]}
            return info

    def _close_process(self):
        p = self.proc
        self.proc = None
        self.messages = None
        self.session = None
        if not p:
            return
        try:
            p.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            p.terminate()
            p.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                p.kill()
            except OSError:
                pass

    def _start(self):
        if self.proc:
            raise WorkDenied("BROWSER_ALREADY_RUNNING")
        if not self.executable or not self.executable.is_file():
            raise WorkDenied("BROWSER_EXECUTABLE_NOT_CONFIGURED")
        worker = self.assets / "browser_worker.cjs"
        if not worker.is_file():
            raise WorkDenied("BROWSER_WORKER_NOT_INSTALLED")
        try:
            p = subprocess.Popen(
                [self.node, str(worker)], cwd=str(self.assets),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                bufsize=1, close_fds=True)
        except OSError:
            raise WorkDenied("BROWSER_NODE_UNAVAILABLE")
        self.proc = p
        self.messages = queue.Queue(maxsize=3)
        mailbox = self.messages

        def reader():
            try:
                for line in p.stdout:
                    if len(line) > 1300000:
                        break
                    try:
                        value = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    try:
                        mailbox.put_nowait(value)
                    except queue.Full:
                        break
            finally:
                try:
                    mailbox.put_nowait({"_closed": True})
                except queue.Full:
                    pass
        threading.Thread(target=reader, daemon=True,
                         name="nf-one-chrome-reader").start()

    def _rpc(self, data):
        if not self.proc or not self.messages:
            raise WorkDenied("BROWSER_NOT_RUNNING")
        self.serial += 1
        ident = self.serial
        try:
            self.proc.stdin.write(json.dumps({"id": ident, **data},
                                             ensure_ascii=False) + "\n")
            self.proc.stdin.flush()
            reply = self.messages.get(timeout=BROWSER_TIMEOUT)
        except (OSError, ValueError, queue.Empty):
            self._close_process()
            raise WorkDenied("BROWSER_RESULT_UNKNOWN_NO_RETRY")
        if isinstance(reply, dict) and reply.get("_closed"):
            self._close_process()
            raise WorkDenied("BROWSER_WORKER_EXITED")
        if not isinstance(reply, dict) or reply.get("id") != ident:
            self._close_process()
            raise WorkDenied("BROWSER_PROTOCOL_UNKNOWN_NO_RETRY")
        if reply.get("ok") is not True:
            error = reply.get("error", "BROWSER_COMMAND_FAILED")
            if data.get("op") == "open":
                self._close_process()
            raise WorkDenied(str(error)[:120])
        result = reply.get("result")
        if not isinstance(result, dict):
            self._close_process()
            raise WorkDenied("BROWSER_PROTOCOL_RESULT_INVALID")
        return result

    def _event(self, project, name, details):
        with self.store.db() as c:
            self.store.event(c, name, project, details)
            c.commit()

    def _validate_session(self, project, ident):
        self.store.project(project)
        if not self.session or self.session["project"] != project:
            raise WorkDenied("BROWSER_PROJECT_SESSION_REFUSED")
        if ident != self.session["id"]:
            raise WorkDenied("BROWSER_SESSION_TOKEN_MISMATCH")
        if time.monotonic() - self.session["opened"] > BROWSER_LIFETIME:
            self._close_process()
            raise WorkDenied("BROWSER_SESSION_EXPIRED")
        if not self.proc or self.proc.poll() is not None:
            self._close_process()
            raise WorkDenied("BROWSER_PROCESS_STOPPED")
        return self.session

    def open(self, project, url):
        self.store.project(project)
        target = validated_url(url)
        host = urlsplit(target).hostname
        if host not in self.allowed_hosts:
            raise WorkDenied("BROWSER_HOST_NOT_APPROVED")
        with self.lock:
            if self.session or self.proc:
                raise WorkDenied("BROWSER_CLOSE_CURRENT_SESSION_FIRST")
            # Reject *any* private/loopback answer and pin the same IPv4 address
            # the browser will actually contact.
            try:
                answers = socket.getaddrinfo(host, 443, family=socket.AF_INET,
                                            type=socket.SOCK_STREAM)
            except OSError:
                raise WorkDenied("BROWSER_DNS_LOOKUP_FAILED")
            addresses = []
            for item in answers:
                ip = ipaddress.ip_address(item[4][0])
                if not ip.is_global:
                    raise WorkDenied("BROWSER_PRIVATE_NETWORK_REFUSED")
                addresses.append(str(ip))
            if not addresses:
                raise WorkDenied("BROWSER_PUBLIC_IPV4_REQUIRED")
            self._start()
            try:
                data = self._rpc({"op": "open", "url": target, "ip": addresses[0],
                                  "executablePath": str(self.executable)})
                ident = secrets.token_hex(16)
                self.session = {"id": ident, "project": project, "host": host,
                                "opened": time.monotonic()}
                self._event(project, "BROWSER_OPENED",
                            {"host": host, "session": ident})
                return {"session_id": ident, "frame": data}
            except Exception:
                self._close_process()
                raise

    def action(self, project, ident, operation, **kwargs):
        if operation not in ALLOWED_OPS:
            raise WorkDenied("BROWSER_OPERATION_REFUSED")
        with self.lock:
            self._validate_session(project, ident)
            params = {"op": operation}
            if operation in ("move", "click"):
                if set(kwargs) != {"x", "y"}:
                    raise WorkDenied("BROWSER_COORDINATES_REQUIRED")
                for key in ("x", "y"):
                    x = kwargs[key]
                    if isinstance(x, bool) or not isinstance(x, int):
                        raise WorkDenied("BROWSER_COORDINATES_INVALID")
                if not 0 <= kwargs["x"] < 1100 or not 0 <= kwargs["y"] < 720:
                    raise WorkDenied("BROWSER_COORDINATES_OUT_OF_BOUNDS")
                params.update(x=kwargs["x"], y=kwargs["y"])
            elif operation == "scroll":
                if set(kwargs) != {"delta"} or type(kwargs["delta"]) is not int \
                        or kwargs["delta"] == 0 or abs(kwargs["delta"]) > 1200:
                    raise WorkDenied("BROWSER_SCROLL_INVALID")
                params["delta"] = kwargs["delta"]
            elif kwargs:
                raise WorkDenied("BROWSER_UNEXPECTED_ARGUMENTS")
            try:
                result = self._rpc(params)
            except WorkDenied as e:
                if "UNKNOWN" in str(e):
                    self._event(project, "BROWSER_UNKNOWN_NO_RETRY",
                                {"operation": operation})
                raise
            if operation != "move":
                self._event(project, "BROWSER_" + operation.upper(),
                            {"host": self.session["host"], "operation": operation})
            return {"session_id": ident, "frame": result}

    def close(self, project, ident):
        with self.lock:
            self._validate_session(project, ident)
            host = self.session["host"]
            self._close_process()
            self._event(project, "BROWSER_CLOSED", {"host": host})
            return {"closed": True}
