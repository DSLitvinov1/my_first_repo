"""One explicitly approved, bounded natural-language desktop task per window.

This executor does not interpret arbitrary model prose or emit screenshots/text
to logs. A deterministic grammar permits non-destructive UI operations only.
Actions stay attached to one previously owner-selected allowed Windows window.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import threading
import time

from desktop_one import MAX_TEXT, RISKY_FIELD, RISKY_LABEL
from work_core import WorkDenied

MAX_SCRIPT = 2400
MAX_STEPS = 8
PLAN_TTL = 120
SAFE_KEYS = {
    "esc": "escape", "escape": "escape", "tab": "tab",
    "shift+tab": "shift_tab", "ctrl+f": "ctrl_f",
    "вверх": "up", "вниз": "down", "влево": "left", "вправо": "right",
    "pageup": "pageup", "pagedown": "pagedown", "home": "home", "end": "end",
}
Q = r'[«"]([^»"]{1,100})[»"]'


def _label(value):
    label = value.strip()
    if (not label or len(label) > 100 or any(ord(c) < 32 for c in label)
            or RISKY_LABEL.search(label) or RISKY_FIELD.search(label)):
        raise WorkDenied("DESKTOP_SENSITIVE_TARGET_REFUSED")
    return label


def parse_safe_desktop_script(script):
    """Parse owner-visible instructions, NEVER execute during parsing."""
    if (type(script) is not str or not 1 <= len(script) <= MAX_SCRIPT
            or any(ord(c) < 32 and c not in "\n\r" for c in script)):
        raise WorkDenied("DESKTOP_SCRIPT_INVALID")
    lines = [s.strip() for s in script.replace("\r\n", "\n").split("\n") if s.strip()]
    if not 1 <= len(lines) <= MAX_STEPS:
        raise WorkDenied("DESKTOP_SCRIPT_STEP_COUNT_REFUSED")
    result = []
    for raw in lines:
        line = raw.strip().rstrip(".!").strip()
        if re.fullmatch(r"(?i)сделай снимок(?: окна| экрана)?", line):
            result.append({"op": "frame"})
            continue
        if re.fullmatch(r"(?i)(?:посмотри|осмотри|изучи)(?: окно| интерфейс)", line):
            result.append({"op": "observe"})
            continue
        m = re.fullmatch(r"(?i)(?:проверь наличие|найди элемент|убедись что есть)\\s+" + Q, line)
        if m:
            result.append({"op": "expect_label", "label": _label(m[1])})
            continue
        m = re.fullmatch(r"(?i)прокрути\s+(вверх|вниз)(?:\s+на\s+([123])\s+шага?)?", line)
        if m:
            result.append({"op": "scroll", "direction": "up" if m[1].lower() == "вверх" else "down",
                           "steps": int(m[2] or 1)})
            continue
        m = re.fullmatch(r"(?i)нажми\s+(?:кнопку\s+|вкладку\s+|пункт\s+меню\s+)?" + Q, line)
        if m:
            result.append({"op": "click_label", "label": _label(m[1])})
            continue
        m = re.fullmatch(r"(?i)введи\s+в\s+поле\s+" + Q + r"\s+текст\s+[«\"]([^»\"]{1,500})[»\"]", line)
        if m:
            label = _label(m[1])
            value = m[2]
            if not value or len(value) > MAX_TEXT or any(ord(c) < 32 for c in value):
                raise WorkDenied("DESKTOP_TEXT_REFUSED")
            result.append({"op": "type_label", "label": label, "text": value})
            continue
        # Focused text input is useful when a legacy desktop application
        # exposes no accessible field name. The desktop worker still verifies
        # the owner window, process, editable control and non-password state.
        m = re.fullmatch(r'(?i)напечатай\s+[«"]([^»"]{1,500})[»"]', line)
        if m:
            value = m[1]
            if not value or len(value) > MAX_TEXT or any(ord(c) < 32 for c in value):
                raise WorkDenied("DESKTOP_TEXT_REFUSED")
            result.append({"op": "type", "text": value})
            continue
        m = re.fullmatch(r"(?i)нажми\s+(esc|escape|tab|shift\+tab|ctrl\+f|вверх|вниз|влево|вправо|pageup|pagedown|home|end)", line)
        if m:
            result.append({"op": "key", "key": SAFE_KEYS[m[1].lower()]})
            continue
        raise WorkDenied("DESKTOP_COMMAND_NOT_ALLOWED")
    return result


class DesktopScriptOne:
    def __init__(self, desktop):
        self.desktop = desktop
        self.lock = threading.RLock()
        self.plans = {}

    def _purge(self):
        now = time.monotonic()
        for key, value in list(self.plans.items()):
            if now - value["created"] > 600 and value["state"] != "RUNNING":
                self.plans.pop(key, None)

    def prepare(self, project, session_id, script):
        self.desktop.store.project(project)
        # Validate a live owner-selected window; do not silently attach one.
        info = self.desktop.status(project)["session"]
        if not info or info["id"] != session_id:
            raise WorkDenied("DESKTOP_SCRIPT_WINDOW_NOT_SELECTED")
        steps = parse_safe_desktop_script(script)
        with self.lock:
            self._purge()
            if len(self.plans) >= 8:
                raise WorkDenied("DESKTOP_TOO_MANY_RECENT_PLANS")
            ident = secrets.token_hex(16)
            self.plans[ident] = {
                "project": project, "session": session_id,
                "digest": hashlib.sha256(script.encode("utf8")).hexdigest(),
                "steps": steps, "created": time.monotonic(),
                "state": "READY", "completed": 0, "error": "",
            }
        # Never include the contents of editable fields in status or audit.
        return {"id": ident, "state": "READY", "step_count": len(steps),
                "operations": [x["op"] for x in steps],
                "requires_owner_confirmation": True, "no_auto_retry": True}

    def start(self, project, session_id, ident, script):
        if type(script) is not str or type(ident) is not str:
            raise WorkDenied("DESKTOP_SCRIPT_APPROVAL_INVALID")
        digest = hashlib.sha256(script.encode("utf8")).hexdigest()
        with self.lock:
            plan = self.plans.get(ident)
            if (not plan or plan["project"] != project or
                    plan["session"] != session_id or plan["state"] != "READY" or
                    plan["digest"] != digest or
                    time.monotonic() - plan["created"] > PLAN_TTL):
                raise WorkDenied("DESKTOP_SCRIPT_APPROVAL_INVALID")
            current = self.desktop.status(project)["session"]
            if not current or current["id"] != session_id:
                raise WorkDenied("DESKTOP_SCRIPT_SESSION_CHANGED")
            if any(x["state"] == "RUNNING" for x in self.plans.values()):
                raise WorkDenied("DESKTOP_SCRIPT_BUSY")
            plan["state"] = "RUNNING"

        def execute():
            try:
                for op in plan["steps"]:
                    action = dict(op)
                    self.desktop.action(project, session_id, action.pop("op"), **action)
                    with self.lock:
                        plan["completed"] += 1
                    # Avoid racing the next UIA operation before UI settles.
                    time.sleep(.18)
                with self.lock:
                    plan["state"] = "DONE"
            except Exception as e:
                reason = str(e)
                if not re.fullmatch(r"DESKTOP_[A-Z_]+", reason):
                    reason = "DESKTOP_ACTION_UNKNOWN_NO_RETRY"
                with self.lock:
                    plan["state"] = "STOPPED"
                    plan["error"] = reason
            finally:
                # Do not retain the owner-supplied text after running.
                with self.lock:
                    plan["steps"] = []
                    plan["digest"] = ""
        threading.Thread(target=execute, daemon=True, name="one-desktop-safe-task").start()
        return {"id": ident, "state": "RUNNING", "no_auto_retry": True}

    def get(self, project, ident):
        self.desktop.store.project(project)
        with self.lock:
            plan = self.plans.get(ident)
            if not plan or plan["project"] != project:
                raise WorkDenied("DESKTOP_SCRIPT_NOT_FOUND")
            return {"id": ident, "state": plan["state"],
                    "completed": plan["completed"], "error": plan["error"],
                    "no_auto_retry": True}
