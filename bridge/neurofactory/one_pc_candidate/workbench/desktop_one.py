"""NEIROZAVOD ONE Windows interactive-desktop adapter.

Disabled unless explicitly enabled with an app allow-list. The privileged
CORE9/HOST service must NEVER run this worker. It is a separate user-session
PowerShell process and cannot spawn arbitrary programs. No model tool grant.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import re
import secrets
import subprocess
import threading
import time

from work_core import WorkDenied

APP_RE = re.compile(r"^[a-z0-9_.-]{2,70}\.exe$")
MAX_TEXT = 500
MAX_LIFETIME = 600
RPC_TIMEOUT = 8


class DesktopOne:
    def __init__(self, store, assets, *, enabled=False, allowed_apps=(),
                 worker_start=None):
        self.store = store
        self.assets = Path(assets)
        self.enabled = enabled
        self.lock = threading.RLock()
        self.apps = frozenset(str(x).strip().lower() for x in allowed_apps if str(x).strip())
        if len(self.apps) > 12 or any(not APP_RE.fullmatch(x) for x in self.apps):
            raise WorkDenied("DESKTOP_APP_ALLOWLIST_INVALID")
        if enabled and not self.apps:
            raise WorkDenied("DESKTOP_ALLOWLIST_REQUIRED")
        self.proc = None
        self.queue = None
        self.session = None
        self.seq = 0
        self.worker_start = worker_start

    def capabilities(self):
        return {
            "supported_os": "windows",
            "configured": bool(self.enabled and self.apps and os.name == "nt"),
            "allowed_apps": sorted(self.apps),
            "actions": ["inspect", "frame", "move", "click", "type", "close"],
            "global_mouse_keyboard": True,
            "process_policy": "interactive_user_session_only_exact_foreground_window",
            "model_allowed": False,
            "no_os_sandbox": True,
            "requires_physical_user_approval": True,
        }

    def _worker(self):
        if not self.enabled or not self.apps:
            raise WorkDenied("DESKTOP_NOT_ENABLED")
        if os.name != "nt":
            raise WorkDenied("DESKTOP_WINDOWS_ONLY")
        worker = self.assets / "desktop_worker.ps1"
        if not worker.is_file() or worker.is_symlink():
            raise WorkDenied("DESKTOP_WORKER_NOT_FOUND")
        if self.worker_start is None:
            powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
                "System32/WindowsPowerShell/v1.0/powershell.exe")
            if not powershell.is_file():
                raise WorkDenied("DESKTOP_POWERSHELL_NOT_FOUND")
            self.proc = subprocess.Popen([
                str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", str(worker)],
                cwd=str(self.assets),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, encoding="utf-8",
                text=True, bufsize=1, close_fds=True,
                creationflags=0x08000000,
            )
        else:
            self.proc = self.worker_start()
        self.queue = queue.Queue(maxsize=2)
        mailbox = self.queue
        proc = self.proc

        def read():
            try:
                for line in proc.stdout:
                    if len(line) > 850000:
                        break
                    try:
                        reply = json.loads(line)
                    except (ValueError, TypeError):
                        break
                    try:
                        mailbox.put_nowait(reply)
                    except queue.Full:
                        break
            finally:
                try:
                    mailbox.put_nowait({"_closed": True})
                except queue.Full:
                    pass
        threading.Thread(target=read, name="nf-one-desktop-replies",
                         daemon=True).start()

    def _close(self):
        proc = self.proc
        self.proc = self.queue = self.session = None
        if not proc:
            return
        try:
            proc.stdin.close()
        except (ValueError, OSError):
            pass
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass

    def _rpc(self, action):
        if not self.proc or not self.queue:
            raise WorkDenied("DESKTOP_WORKER_STOPPED")
        self.seq += 1
        ident = self.seq
        try:
            self.proc.stdin.write(json.dumps({"id": ident, **action},
                                              ensure_ascii=False) + "\n")
            self.proc.stdin.flush()
            reply = self.queue.get(timeout=RPC_TIMEOUT)
        except (OSError, ValueError, queue.Empty):
            self._close()
            raise WorkDenied("DESKTOP_ACTION_UNKNOWN_NO_RETRY")
        if reply.get("id") != ident or reply.get("_closed"):
            self._close()
            raise WorkDenied("DESKTOP_REPLY_UNKNOWN_NO_RETRY")
        if reply.get("ok") is not True:
            err = str(reply.get("error", "DESKTOP_ACTION_REFUSED"))[:90]
            if not re.fullmatch(r"DESKTOP_[A-Z_]+", err):
                err = "DESKTOP_ACTION_REFUSED"
            raise WorkDenied(err)
        if not isinstance(reply.get("result"), dict):
            self._close()
            raise WorkDenied("DESKTOP_INVALID_REPLY")
        return reply["result"]

    def _audit(self, project, event, data):
        with self.store.db() as c:
            self.store.event(c, event, project, data)
            c.commit()

    def status(self, project=None):
        with self.lock:
            details = self.capabilities()
            details["session"] = None
            if self.session and (project is None or self.session["project"] == project):
                details["session"] = {
                    "id": self.session["id"], "app": self.session["app"],
                    "since": self.session["created"],
                }
            return details

    def windows(self, project):
        """List only whitelisted apps in current interactive session."""
        self.store.project(project)
        with self.lock:
            if self.session:
                raise WorkDenied("DESKTOP_CLOSE_SESSION_BEFORE_LIST")
            if not self.proc:
                self._worker()
            data=self._rpc({"op":"list"})
            windows=data.get("windows")
            if not isinstance(windows,list) or len(windows)>100:
                self._close()
                raise WorkDenied("DESKTOP_WINDOW_ENUMERATION_INVALID")
            return [
                {k:x[k] for k in ("app","pid","handle","width","height")}
                for x in windows if isinstance(x,dict) and x.get("app") in self.apps
                and all(k in x for k in ("pid","handle","width","height"))
            ][:25]

    def attach(self, project, app, pid, handle):
        """Attach an allowed window chosen by owner. No process spawning."""
        self.store.project(project)
        if (type(app) is not str or app not in self.apps or
                type(pid) is not int or pid<=0 or
                type(handle) is not int or handle<=0):
            raise WorkDenied("DESKTOP_ATTACH_REFUSED")
        with self.lock:
            if self.session:
                raise WorkDenied("DESKTOP_CLOSE_CURRENT_SESSION")
            if not self.proc:
                self._worker()
            info=self._rpc({"op":"attach","app":app,"pid":pid,"handle":handle})
            if (info.get("app")!=app or info.get("pid")!=pid or
                    info.get("handle")!=handle):
                raise WorkDenied("DESKTOP_ATTACH_MISMATCH")
            sid=secrets.token_hex(16)
            self.session={"id":sid,"project":project,"app":app,
                          "pid":pid,"handle":handle,"created":time.monotonic()}
            self._audit(project,"DESKTOP_ATTACHED",{"app":app})
            return {"session_id":sid,"app":app,
                    "width":info["width"],"height":info["height"]}

    def open(self, project):
        self.store.project(project)
        with self.lock:
            if self.session or self.proc:
                raise WorkDenied("DESKTOP_SESSION_ALREADY_OPEN")
            self._worker()
            try:
                info = self._rpc({"op": "inspect"})
                app = info.get("app")
                pid = info.get("pid")
                handle = info.get("handle")
                if (app not in self.apps or type(pid) is not int or pid <= 0 or
                        type(handle) is not int or handle <= 0):
                    raise WorkDenied("DESKTOP_FOREGROUND_APP_NOT_APPROVED")
                ident = secrets.token_hex(16)
                self.session = {
                    "id": ident, "project": project, "app": app, "pid": pid,
                    "handle": handle, "created": time.monotonic(),
                }
                self._audit(project, "DESKTOP_OPENED", {"app": app})
                return {"session_id": ident, "app": app,
                        "width": info["width"], "height": info["height"]}
            except Exception:
                self._close()
                raise

    def action(self, project, session_id, op, **kwargs):
        self.store.project(project)
        with self.lock:
            if (not self.session or self.session["project"] != project or
                    self.session["id"] != session_id):
                raise WorkDenied("DESKTOP_SESSION_REFUSED")
            if time.monotonic()-self.session["created"] > MAX_LIFETIME:
                self._close()
                raise WorkDenied("DESKTOP_SESSION_EXPIRED")
            if op not in {"frame", "move", "click", "type"}:
                raise WorkDenied("DESKTOP_OPERATION_NOT_ALLOWED")
            params = {"op": op, "app": self.session["app"],
                      "pid": self.session["pid"],
                      "handle": self.session["handle"]}
            if op in {"move", "click"}:
                if set(kwargs) != {"x", "y"} or any(type(kwargs[k]) is not int
                     or kwargs[k] < 0 or kwargs[k] > 4096 for k in ("x", "y")):
                    raise WorkDenied("DESKTOP_POINT_INVALID")
                params.update(kwargs)
            elif op == "type":
                value = kwargs.get("text")
                if (set(kwargs) != {"text"} or type(value) is not str
                        or not 1 <= len(value) <= MAX_TEXT
                        or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                    raise WorkDenied("DESKTOP_TEXT_REFUSED")
                params["text"] = value
            elif kwargs:
                raise WorkDenied("DESKTOP_UNEXPECTED_ARGUMENTS")
            try:
                data = self._rpc(params)
            except WorkDenied as e:
                if "UNKNOWN" in str(e):
                    self._audit(project, "DESKTOP_UNKNOWN_NO_RETRY",
                                {"action": op})
                raise
            self._audit(project, "DESKTOP_"+op.upper(),
                        {"app": self.session["app"], "action": op})
            # Never log text, screenshots, window title, or user data.
            return {"session_id": session_id, "result": data}

    def close(self, project, session_id):
        self.store.project(project)
        with self.lock:
            if (not self.session or self.session["project"] != project or
                    self.session["id"] != session_id):
                raise WorkDenied("DESKTOP_SESSION_REFUSED")
            app = self.session["app"]
            self._close()
            self._audit(project, "DESKTOP_CLOSED", {"app": app})
            return {"closed": True}
