"""Optional ChatGPT -> private GitHub issue -> local ONE bridge.

ChatGPT already has an authorized GitHub connector. Commands are stored in an
owner-controlled PRIVATE repository; ONE polls outbound over verified HTTPS.
No listening public port, cookies, shell, unrestricted desktop or model authority.
Remote desktop scripts are staged only, never executed without local approval.
"""
from __future__ import annotations

import hashlib
from http.client import HTTPException
import json
import re
import threading
import time
from urllib.parse import quote

from agent_one import public_dns, PinnedHTTPSConnection, validated_url
from work_core import WorkDenied

BRIDGE_SCHEMA = "one.chatgpt.command.v1"
BRIDGE_LABEL = "[ONE-COMMAND]"
BRIDGE_OPS = frozenset(("status", "site.audit", "desktop.observe", "desktop.prepare"))
REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9-]{1,39}$")
HEX_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_ISSUES = 30
COMMAND_TTL = 3600
MAX_BODY = 3200


def no_duplicate_keys(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise WorkDenied("CHATGPT_DUPLICATE_JSON_KEY")
        out[k] = v
    return out


def verify_command(issue, owner, now=None):
    """Return strictly bounded owner-authored command, not executable LLM output."""
    now = int(now if now is not None else time.time())
    if (type(issue) is not dict or issue.get("state") != "open" or
            "pull_request" in issue or
            type(issue.get("number")) is not int or issue["number"] <= 0 or
            type(issue.get("id")) is not int or issue["id"] <= 0 or
            issue.get("user", {}).get("login") != owner or
            type(issue.get("title")) is not str or
            not issue["title"].startswith(BRIDGE_LABEL)):
        raise WorkDenied("CHATGPT_ISSUE_NOT_OWNER_COMMAND")
    body = issue.get("body")
    if type(body) is not str or not 2 <= len(body) <= MAX_BODY:
        raise WorkDenied("CHATGPT_BODY_REFUSED")
    try:
        cmd = json.loads(body, object_pairs_hook=no_duplicate_keys)
    except (ValueError, TypeError):
        raise WorkDenied("CHATGPT_JSON_REFUSED")
    expected = {"schema", "request_id", "issued_at", "project_id",
                "operation", "params"}
    if type(cmd) is not dict or set(cmd) != expected or cmd["schema"] != BRIDGE_SCHEMA:
        raise WorkDenied("CHATGPT_COMMAND_SCHEMA_REFUSED")
    if (type(cmd["request_id"]) is not str or
            not HEX_RE.fullmatch(cmd["request_id"]) or
            type(cmd["project_id"]) is not str or
            not HEX_RE.fullmatch(cmd["project_id"]) or
            type(cmd["issued_at"]) is not int or
            not now - COMMAND_TTL <= cmd["issued_at"] <= now + 120):
        raise WorkDenied("CHATGPT_COMMAND_EXPIRED_OR_INVALID")
    op, params = cmd["operation"], cmd["params"]
    if op not in BRIDGE_OPS or type(params) is not dict:
        raise WorkDenied("CHATGPT_OPERATION_REFUSED")
    if op in ("status", "desktop.observe") and params:
        raise WorkDenied("CHATGPT_PARAMS_REFUSED")
    if op == "site.audit":
        if (set(params) != {"urls"} or type(params["urls"]) is not list or
                not 1 <= len(params["urls"]) <= 4 or
                len(set(map(str,params["urls"]))) != len(params["urls"])):
            raise WorkDenied("CHATGPT_AUDIT_PARAMS_REFUSED")
        for url in params["urls"]:
            validated_url(url)
    if op == "desktop.prepare":
        script = params.get("script")
        if set(params) != {"script"} or type(script) is not str or not 1 <= len(script) <= 2400:
            raise WorkDenied("CHATGPT_DESKTOP_SCRIPT_REFUSED")
        from desktop_script_one import parse_safe_desktop_script
        parse_safe_desktop_script(script)
    return cmd


class GithubIssueTransport:
    """One fixed API host, no URL-controlled hostnames or redirects."""
    HOST = "api.github.com"

    def __init__(self, token, repo, owner):
        if (type(token) is not str or not 20 <= len(token) <= 255 or
                any(ord(c) < 33 or ord(c) > 126 for c in token) or
                type(repo) is not str or not REPO_RE.fullmatch(repo) or
                type(owner) is not str or not LOGIN_RE.fullmatch(owner) or
                repo.split("/", 1)[0].lower() != owner.lower()):
            raise WorkDenied("CHATGPT_BRIDGE_CONFIG_REFUSED")
        self.token, self.repo, self.owner = token, repo, owner
        self.base = "/repos/" + quote(repo.split("/")[0],safe="") + "/" + quote(repo.split("/")[1],safe="")

    def request(self, method, endpoint, body=None):
        if (method not in ("GET", "POST") or type(endpoint) is not str or
                not endpoint.startswith(self.base) or
                "://" in endpoint or ".." in endpoint or "\\" in endpoint or
                len(endpoint) > 270):
            raise WorkDenied("CHATGPT_API_TARGET_REFUSED")
        payload = None
        if body is not None:
            if method != "POST" or type(body) is not dict:
                raise WorkDenied("CHATGPT_API_BODY_REFUSED")
            payload = json.dumps(body,separators=(",",":"),ensure_ascii=False).encode("utf8")
            if len(payload) > 5000:
                raise WorkDenied("CHATGPT_API_BODY_TOO_LARGE")
        ip = public_dns(self.HOST)
        conn = PinnedHTTPSConnection(self.HOST, ip)
        try:
            conn.request(method,endpoint,body=payload,headers={
                "Host": self.HOST,
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "NeirozavodWorkONE-OwnerBridge/1.0"})
            response=conn.getresponse()
            if (response.status not in (200,201) or
                    response.headers.get_content_type() not in ("application/json","text/json")):
                raise WorkDenied("CHATGPT_GITHUB_ACCESS_REFUSED")
            raw=response.read(240001)
            if len(raw)>240000:
                raise WorkDenied("CHATGPT_GITHUB_RESPONSE_TOO_LARGE")
            return json.loads(raw.decode("utf8"),object_pairs_hook=no_duplicate_keys)
        except WorkDenied:
            raise
        except (OSError, TimeoutError, HTTPException, ValueError, UnicodeError):
            raise WorkDenied("CHATGPT_GITHUB_NETWORK_UNAVAILABLE")
        finally:
            conn.close()

    def verify_private_repo(self):
        data=self.request("GET",self.base)
        if (type(data) is not dict or data.get("private") is not True or
                data.get("full_name","").lower() != self.repo.lower() or
                data.get("owner",{}).get("login","").lower() != self.owner.lower()):
            raise WorkDenied("CHATGPT_PRIVATE_REPOSITORY_REQUIRED")
        return True

    def issues(self):
        data=self.request("GET",self.base+"/issues?state=open&per_page="+str(MAX_ISSUES))
        if type(data) is not list or len(data)>MAX_ISSUES:
            raise WorkDenied("CHATGPT_ISSUES_RESPONSE_REFUSED")
        return data

    def comment(self, number, receipt):
        if type(number) is not int or number <= 0 or type(receipt) is not dict:
            raise WorkDenied("CHATGPT_COMMENT_REFUSED")
        safe = json.dumps(receipt,separators=(",",":"),ensure_ascii=False)
        if len(safe)>1500:
            raise WorkDenied("CHATGPT_RECEIPT_TOO_LARGE")
        self.request("POST",self.base+"/issues/"+str(number)+"/comments",
                     {"body":"ONE Agent receipt: "+safe})


class ChatGPTBridgeOne:
    def __init__(self, store, agent, desktop, scripts, vault, transport=None,
                 now=None):
        self.store, self.agent, self.desktop = store, agent, desktop
        self.scripts, self.vault, self.transport = scripts, vault, transport
        self.now = now or time.time
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.worker = None
        self.repo = None
        self.owner = None
        self.last_poll = None
        self.last_error = None
        self.pending = {}
        self.running = {}
        with self.store.db() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS one_chatgpt_commands (
                issue_id INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
                project_id TEXT NOT NULL, operation TEXT NOT NULL,
                state TEXT NOT NULL, created INTEGER NOT NULL,
                updated INTEGER NOT NULL, receipt TEXT
            );
            """)
            c.execute("UPDATE one_chatgpt_commands SET state='UNKNOWN_NO_RETRY',"
                      "updated=? WHERE state='RUNNING'",(int(self.now()),))
            c.commit()

    def status(self):
        with self.lock:
            return {"connected":self.transport is not None,
                    "repository":self.repo,
                    "state":"PAIRED" if self.transport else "NOT_CONNECTED",
                    "last_poll":self.last_poll,
                    "last_error":self.last_error,
                    "pending_approvals":len(self.pending),
                    "running_approved":len(self.running),
                    "operations":sorted(BRIDGE_OPS),
                    "outbound_only":True,
                    "unattended_desktop_actions":False}

    def connect(self, repo, owner, access_token):
        if not self.vault.ready():
            raise WorkDenied("CHATGPT_OWNER_WINDOWS_REQUIRED")
        api=GithubIssueTransport(access_token,repo,owner)
        api.verify_private_repo()
        with self.lock:
            self.vault.put("github","issuebridge",{
                "repository":repo,"owner":owner,"token":access_token})
            self.transport=api
            self.repo=repo
            self.owner=owner
            self.last_error=None
        self.start()
        return self.status()

    def restore(self):
        if not self.vault.ready():
            return
        try:
            record=self.vault.get("github","issuebridge")
            if not record:
                return
            api=GithubIssueTransport(record["token"],record["repository"],record["owner"])
            api.verify_private_repo()
            with self.lock:
                self.transport=api;self.repo=api.repo;self.owner=api.owner
            self.start()
        except (WorkDenied,ValueError,KeyError):
            self.last_error="CHATGPT_BRIDGE_RECONNECT_REQUIRED"

    def disconnect(self):
        with self.lock:
            self.stop_event.set()
            self.transport=None
            self.repo=self.owner=None
            self.pending.clear()
            self.running.clear()
            if self.vault.ready():
                self.vault.delete("github","issuebridge")
        return self.status()

    def start(self):
        with self.lock:
            if (self.worker is not None and self.worker.is_alive() and
                    not self.stop_event.is_set()):
                return
            # Independent lifecycle token prevents a disconnected old worker
            # from resuming if the user pairs another repository.
            self.stop_event=threading.Event()
            event=self.stop_event
            self.worker=threading.Thread(target=self._loop,args=(event,),
                                         daemon=True,
                                         name="one-chatgpt-private-issue-bridge")
            self.worker.start()

    def _loop(self,event):
        while not event.is_set():
            try:
                self.poll_once(event)
            except Exception:
                self.last_error="CHATGPT_BRIDGE_POLL_FAILED"
            event.wait(20)

    def _journal(self, issue_id, cmd):
        with self.store.db() as c:
            try:
                c.execute("INSERT INTO one_chatgpt_commands VALUES (?,?,?,?,?,?,?,NULL)",
                          (issue_id,cmd["request_id"],cmd["project_id"],
                           cmd["operation"],"RUNNING",int(self.now()),int(self.now())))
                c.commit()
                return True
            except Exception:
                # Prior request, including half-completed action: never replay.
                return False

    def _finish(self, issue_id, state, receipt):
        serialized=json.dumps(receipt,ensure_ascii=False)
        with self.store.db() as c:
            c.execute("UPDATE one_chatgpt_commands SET state=?,updated=?,receipt=? WHERE issue_id=?",
                      (state,int(self.now()),serialized,issue_id))
            c.commit()

    def pending_approvals(self):
        with self.lock:
            return [{"issue_id":x,"project_id":v["project"],"script":v["script"],
                     "operation":"desktop.prepare","step_count":v["step_count"]}
                    for x,v in self.pending.items()]

    def approve(self, project, issue_id):
        if type(issue_id) is not int or issue_id <= 0:
            raise WorkDenied("CHATGPT_APPROVAL_INVALID")
        with self.lock:
            item=self.pending.get(issue_id)
            if not item or item["project"] != project:
                raise WorkDenied("CHATGPT_APPROVAL_NOT_FOUND")
            self.pending.pop(issue_id)
        result=self.scripts.start(project,item["session"],item["plan_id"],item["script"])
        with self.lock:
            self.running[issue_id]={"project":project,"plan_id":item["plan_id"],
                                    "request_id":item["request_id"],
                                    "number":item["number"]}
        return {"issue_id":issue_id,"state":"RUNNING","owner_approved":True,
                "plan_id":item["plan_id"]}

    def reject(self, project, issue_id):
        if type(issue_id) is not int or issue_id <= 0:
            raise WorkDenied("CHATGPT_APPROVAL_INVALID")
        with self.lock:
            item=self.pending.get(issue_id)
            if not item or item["project"] != project:
                raise WorkDenied("CHATGPT_APPROVAL_NOT_FOUND")
            self.pending.pop(issue_id)
        return {"issue_id":issue_id,"state":"REJECTED_BY_OWNER"}

    def _execute(self, cmd, issue_id, issue_number):
        project=cmd["project_id"]
        self.store.project(project)
        op=cmd["operation"]
        if op=="status":
            info=self.store.status()
            return {"state":"DONE","operation":op,
                    "projects":len(info.get("projects",[])) if
                       type(info.get("projects")) is list else None}
        if op=="site.audit":
            run=self.agent.create_audit(project,cmd["params"]["urls"])
            final=self.agent.execute(run["id"],project)
            return {"state":final["state"],"operation":op,"run_id":run["id"],
                    "pages":len(final["steps"]),
                    "passed":sum(x["state"]=="DONE" for x in final["steps"])}
        active=self.desktop.status(project).get("session")
        if not active:
            raise WorkDenied("CHATGPT_OWNER_DESKTOP_WINDOW_REQUIRED")
        if op=="desktop.observe":
            result=self.desktop.action(project,active["id"],"observe")["result"]
            return {"state":"DONE","operation":op,
                    "app":active["app"],"visible_controls":len(result["controls"])}
        if op=="desktop.prepare":
            script=cmd["params"]["script"]
            plan=self.scripts.prepare(project,active["id"],script)
            with self.lock:
                self.pending[issue_id]={"project":project,"session":active["id"],
                    "plan_id":plan["id"],"script":script,"step_count":plan["step_count"],
                    "number":issue_number,"request_id":cmd["request_id"]}
            return {"state":"NEEDS_LOCAL_OWNER_APPROVAL","operation":op,
                    "steps":plan["step_count"]}
        raise WorkDenied("CHATGPT_OPERATION_REFUSED")

    def _check_running(self, api):
        with self.lock:
            executions=list(self.running.items())
        for issue_id,item in executions:
            try:
                state=self.scripts.get(item["project"],item["plan_id"])
            except WorkDenied:
                state={"state":"STOPPED","completed":0}
            if state["state"]=="RUNNING":
                continue
            receipt={"schema":"one.chatgpt.receipt.v1",
                     "request_id":item["request_id"],
                     "operation":"desktop.prepare",
                     "state":"DONE" if state["state"]=="DONE" else "STOPPED",
                     "completed":state.get("completed",0),
                     "owner_approved":True}
            self._finish(issue_id,receipt["state"],receipt)
            with self.lock:
                self.running.pop(issue_id,None)
            try:
                api.comment(item["number"],receipt)
            except Exception:
                self.last_error="CHATGPT_RECEIPT_DELIVERY_UNKNOWN_NO_RETRY"
            break

    def poll_once(self, event=None):
        with self.lock:
            api=self.transport
            owner=self.owner
        if not api:
            raise WorkDenied("CHATGPT_BRIDGE_NOT_CONNECTED")
        if event is not None and event.is_set():
            return None
        self._check_running(api)
        issues=api.issues()
        self.last_poll=int(self.now())
        for issue in sorted(issues,key=lambda x: x.get("id",0))[:MAX_ISSUES]:
            if event is not None and event.is_set():
                return None
            with self.lock:
                if self.transport is not api:
                    return None
            try:
                cmd=verify_command(issue,owner,self.now())
            except WorkDenied:
                continue
            issue_id=issue["id"]
            if not self._journal(issue_id,cmd):
                continue
            try:
                result=self._execute(cmd,issue_id,issue["number"])
                state=result["state"]
                receipt={"schema":"one.chatgpt.receipt.v1",
                         "request_id":cmd["request_id"],**result}
            except Exception as exc:
                reason=str(exc)
                if not (reason.startswith(("CHATGPT_","DESKTOP_","AUDIT_","AGENT_")) and
                        len(reason)<=90 and re.fullmatch("[A-Z_]+",reason)):
                    reason="CHATGPT_EXECUTION_FAILED"
                receipt={"schema":"one.chatgpt.receipt.v1",
                         "request_id":cmd["request_id"],"state":"STOPPED",
                         "operation":cmd["operation"],"error":reason}
                state="STOPPED"
            self._finish(issue_id,state,receipt)
            try:
                api.comment(issue["number"],receipt)
            except Exception:
                self.last_error="CHATGPT_RECEIPT_DELIVERY_UNKNOWN_NO_RETRY"
            return receipt
        return None
