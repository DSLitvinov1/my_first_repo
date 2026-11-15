"""MCP/stdio adapter for an explicitly approved interactive Windows ONE desktop.

Security boundaries:
* It does not use Playwright to control Windows (Playwright remains separate).
* It runs as the actual non-elevated Windows user, never SYSTEM/admin.
* It can attach only a pre-approved app from DesktopOne's allow-list.
* Every attach and action batch requires Windows-local consent.
* No shell, file access, process launching, clipboard, password, cookies, or
  secret data is exposed to the MCP client.
* All UI actions use the existing ONE DesktopScriptOne grammar/worker, not
  unchecked model-generated commands. No silent retries after uncertain calls.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

MAX_LINE = 32768
PROJECT_RE = re.compile(r"^[0-9a-f]{32}$")
APPS_RE = re.compile(r"^[a-z0-9_.-]{2,70}\.exe$")
MAX_SCRIPT_SIZE = 2400


class OwnerRefused(ValueError):
    pass


def _strict_json(text: str) -> dict[str, Any]:
    def no_dups(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise OwnerRefused("DUPLICATE_KEY")
            result[key] = value
        return result
    value = json.loads(text, object_pairs_hook=no_dups)
    if type(value) is not dict:
        raise OwnerRefused("INVALID_REQUEST")
    return value


def windows_owner_consent(title: str, detail: str) -> bool:
    if os.name != "nt":
        return False
    if len(detail) > MAX_SCRIPT_SIZE + 180:
        return False
    # Non-elevated owner session is mandatory; never run in a service.
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return False
        session_id = ctypes.c_ulong(0)
        process_id = ctypes.windll.kernel32.GetCurrentProcessId()
        if not ctypes.windll.kernel32.ProcessIdToSessionId(process_id, ctypes.byref(session_id)):
            return False
        if session_id.value == 0:
            return False
        # MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST
        answer = ctypes.windll.user32.MessageBoxW(
            0, detail, title, 0x00000004 | 0x00000030 | 0x00000100 | 0x00040000)
        return answer == 6  # IDYES; default button is No
    except (OSError, AttributeError, ValueError):
        return False


TOOLS = [
    {
        "name": "one_desktop_status",
        "description": "Check the authorized Windows desktop adapter capabilities. Does not read files or secrets.",
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    {
        "name": "one_desktop_windows",
        "description": "List visible windows from the owner-configured executable allow-list. No window titles or field values.",
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    {
        "name": "one_desktop_attach",
        "description": "Attach a pre-approved Windows window (requires an explicit local yes/no approval dialog).",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "required": ["app", "pid", "handle"],
            "properties": {"app": {"type": "string"}, "pid": {"type": "integer", "minimum": 1}, "handle": {"type": "integer", "minimum": 1}},
        },
    },
    {
        "name": "one_desktop_observe",
        "description": "Observe only safe navigation labels in the locally approved window; no values, screenshots or passwords.",
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    {
        "name": "one_desktop_execute",
        "description": "Run one bounded ONE Russian UI script; requires a new explicit local yes/no approval dialog. No destructive actions or shell.",
        "inputSchema": {"type": "object", "additionalProperties": False,
                        "required": ["script"], "properties": {"script": {"type": "string", "minLength": 1, "maxLength": MAX_SCRIPT_SIZE}}},
    },
    {
        "name": "one_desktop_action_status",
        "description": "Read back an earlier approved action by one-time plan ID; no retries.",
        "inputSchema": {"type": "object", "additionalProperties": False,
                        "required": ["id"], "properties": {"id": {"type": "string", "pattern": "^[0-9a-f]{32}$"}}},
    },
    {
        "name": "one_desktop_detach",
        "description": "Stop controlling the selected window; does not close the user's application.",
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
]


class OneDesktopOwnerMcp:
    def __init__(self, desktop, scripts, project: str, consent=windows_owner_consent):
        if type(project) is not str or not PROJECT_RE.fullmatch(project):
            raise OwnerRefused("PROJECT_INVALID")
        self.desktop = desktop
        self.scripts = scripts
        self.project = project
        self.consent = consent
        self.desktop.store.project(project)  # no auto-create/switch projects
        self.session_id = None
        self.allowed_apps = frozenset(desktop.apps)
        self.windows_seen = {}  # only exact windows from most recent enumeration

    def _owner_session(self):
        if self.session_id is None:
            raise OwnerRefused("WINDOW_NOT_APPROVED")
        current = self.desktop.status(self.project).get("session")
        if not current or current.get("id") != self.session_id:
            self.session_id = None
            raise OwnerRefused("WINDOW_CHANGED")
        return self.session_id

    def call(self, name: str, args: dict) -> dict:
        if type(args) is not dict:
            raise OwnerRefused("ARGUMENTS_INVALID")
        allowed = {tool["name"] for tool in TOOLS}
        if name not in allowed:
            raise OwnerRefused("UNKNOWN_TOOL")
        if name in ("one_desktop_status", "one_desktop_windows", "one_desktop_observe",
                    "one_desktop_detach") and args:
            raise OwnerRefused("EXTRA_ARGUMENTS")
        if name == "one_desktop_status":
            capabilities = self.desktop.capabilities()
            # Never treat a model-requested boolean as a permission grant.
            return {"enabled":bool(capabilities.get("configured")),
                    "os":"windows", "mode":"OWNER_APPROVAL_REQUIRED",
                    "apps":sorted(self.allowed_apps),
                    "selected_window":bool(self.session_id),
                    "playwright_separate":True,
                    "desktop_privilege":"CURRENT_NON_ELEVATED_USER_ONLY"}
        if name == "one_desktop_windows":
            if self.session_id:
                raise OwnerRefused("DETACH_BEFORE_LIST")
            windows = self.desktop.windows(self.project)
            self.windows_seen = {
                (x["app"],x["pid"],x["handle"]):x for x in windows
                if (type(x) is dict and x.get("app") in self.allowed_apps
                    and type(x.get("pid")) is int and type(x.get("handle")) is int)
            }
            return {"windows":[{k:v[k] for k in ("app","pid","handle","width","height")}
                               for v in self.windows_seen.values()]}
        if name == "one_desktop_attach":
            if set(args) != {"app","pid","handle"} or type(args.get("app")) is not str or \
                 type(args.get("pid")) is not int or type(args.get("handle")) is not int:
                raise OwnerRefused("ATTACH_ARGUMENTS_INVALID")
            key = (args["app"],args["pid"],args["handle"])
            if self.session_id is not None or key not in self.windows_seen:
                raise OwnerRefused("WINDOW_NOT_WHITELISTED_OR_ENUMERATED")
            if not self.consent("ONE Agent — разрешить управление окном",
                    f"Приложение: {args['app']}\nPID: {args['pid']}\n\n"
                    "Разрешить просмотр безопасных элементов этого окна?\n"
                    "Подтверждайте только если сами открыли это окно."):
                raise OwnerRefused("LOCAL_OWNER_REFUSED")
            result = self.desktop.attach(self.project,*key)
            self.session_id = result["session_id"]
            self.windows_seen = {}
            return {"attached":True,"app":args["app"]}
        if name == "one_desktop_observe":
            sid=self._owner_session()
            from desktop_goal_one import safe_navigation_labels
            found=self.desktop.action(self.project,sid,"observe")
            return {"navigation_labels":safe_navigation_labels(found["result"].get("controls",[])),
                    "note":"Values, window titles, secrets and screenshots are not sent to the MCP client"}
        if name == "one_desktop_execute":
            sid=self._owner_session()
            script=args.get("script")
            if set(args)!={"script"} or type(script) is not str or len(script)>MAX_SCRIPT_SIZE:
                raise OwnerRefused("SCRIPT_INVALID")
            from desktop_script_one import parse_safe_desktop_script
            steps=parse_safe_desktop_script(script)  # validate BEFORE consent
            # No uncontrolled browser automation or interaction with desktop UAC.
            if not self.consent("ONE Agent — выполнить действия",
                    "Разрешить ОДИН сценарий в текущем выбранном окне?\n\n"
                    +script+"\n\nДействия: "+str(len(steps))+".\n"
                    "Отказ — по умолчанию. Повтор без подтверждения запрещён."):
                raise OwnerRefused("LOCAL_OWNER_REFUSED")
            plan=self.scripts.prepare(self.project,sid,script)
            return self.scripts.start(self.project,sid,plan["id"],script)
        if name == "one_desktop_action_status":
            if set(args)!={"id"} or type(args.get("id")) is not str or not PROJECT_RE.fullmatch(args["id"]):
                raise OwnerRefused("STATUS_ID_INVALID")
            self._owner_session()
            return self.scripts.get(self.project,args["id"])
        if name == "one_desktop_detach":
            sid=self._owner_session()
            result=self.desktop.close(self.project,sid)
            self.session_id=None
            return result
        raise OwnerRefused("UNKNOWN_TOOL")


def _response(ident, result=None, error=None):
    payload={"jsonrpc":"2.0","id":ident}
    if error is not None:
        payload["error"]={"code":-32600,"message":error}
    else:
        payload["result"]=result
    return payload


def process(message: dict, agent: OneDesktopOwnerMcp):
    method=message.get("method")
    ident=message.get("id")
    if method == "notifications/initialized":
        return None
    if ident is None:
        return None  # ignore non-request notifications
    if type(method) is not str or message.get("jsonrpc") != "2.0":
        return _response(ident,error="INVALID_JSONRPC")
    if method == "initialize":
        return _response(ident,{
            "protocolVersion":"2024-11-05",
            "capabilities":{"tools":{"listChanged":False}},
            "serverInfo":{"name":"neirozavod-one-desktop-owner","version":"0.1.0"},
        })
    if method == "ping":
        return _response(ident,{})
    if method == "tools/list":
        return _response(ident,{"tools":TOOLS})
    if method == "tools/call":
        params=message.get("params")
        if type(params) is not dict or set(params)!={"name","arguments"}:
            return _response(ident,error="TOOL_INPUT_INVALID")
        try:
            result=agent.call(params["name"],params["arguments"])
            raw=json.dumps(result,ensure_ascii=False,separators=(",",":"))
            if len(raw)>12000:
                raise OwnerRefused("TOOL_RESULT_TOO_LARGE")
            return _response(ident,{"content":[{"type":"text","text":raw}],"isError":False})
        except (OwnerRefused,ValueError) as exc:
            reason=str(exc)
            # Do not leak user data, paths, screenshots or exceptions into MCP.
            if not re.fullmatch(r"[A-Z_]{3,80}",reason):
                reason="OWNER_OPERATION_REFUSED"
            return _response(ident,{"content":[{"type":"text","text":reason}],"isError":True})
        except Exception:
            return _response(ident,{"content":[{"type":"text","text":"OWNER_OPERATION_FAILED_NO_RETRY"}],"isError":True})
    return _response(ident,error="METHOD_NOT_FOUND")


def serve_stdio(agent: OneDesktopOwnerMcp, inp=None, out=None):
    inp = inp or sys.stdin
    out = out or sys.stdout
    for line in inp:
        if len(line)>MAX_LINE:
            break  # fail closed on abusive input, never echo request content
        try:
            message=_strict_json(line)
            answer=process(message,agent)
            if answer is not None:
                out.write(json.dumps(answer,ensure_ascii=False,separators=(",",":"))+"\n")
                out.flush()
        except (ValueError,UnicodeError):
            # Parse errors are not echoed; sensitive input might be present.
            out.write(json.dumps(_response(None,error="INVALID_JSON"))+"\n")
            out.flush()


def main():
    ap=argparse.ArgumentParser(description="Owner-controlled Windows UIA MCP bridge for ONE")
    ap.add_argument("--root",type=Path,required=True)
    ap.add_argument("--data",type=Path,required=True)
    ap.add_argument("--project",required=True)
    ap.add_argument("--apps",required=True)
    args=ap.parse_args()
    if os.name!="nt":
        raise SystemExit("INTERACTIVE_WINDOWS_ONLY")
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            raise SystemExit("ADMIN_SESSION_REFUSED")
    except (OSError,AttributeError):
        raise SystemExit("INTERACTIVE_USER_REQUIRED")
    apps=[x.strip().lower() for x in args.apps.split(",") if x.strip()]
    if not apps or len(apps)>12 or any(not APPS_RE.fullmatch(x) for x in apps):
        raise SystemExit("EXPLICIT_APP_ALLOWLIST_REQUIRED")
    from work_core import WorkStore
    from desktop_one import DesktopOne
    from desktop_script_one import DesktopScriptOne
    data=WorkStore(args.root.resolve(),args.data.resolve())
    project=args.project
    if project=="auto":
        # Safe only when exactly one user-created ONE project exists.
        with data.db() as conn:
            candidates=[row[0] for row in conn.execute("SELECT id FROM projects LIMIT 2")]
        if len(candidates)!=1:
            raise SystemExit("EXACT_PROJECT_ID_REQUIRED")
        project=candidates[0]
    desktop=DesktopOne(data,Path(__file__).resolve().parent,enabled=True,allowed_apps=apps)
    agent=OneDesktopOwnerMcp(desktop,DesktopScriptOne(desktop),project)
    try:
        serve_stdio(agent)
    finally:
        desktop._close()  # closes control session, not the user application


if __name__ == "__main__":
    main()
