"""Work ONE service connectors and approved, verified record mutations.

Adapters are real HTTP clients but DISABLED until the owner separately connects
credentials. The existing ChatGPT connectors cannot be silently transplanted.
Only allowlisted API methods and explicitly approved fields are supported.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import quote, urlencode, urlsplit

from agent_one import public_dns, PinnedHTTPSConnection
from work_core import WorkDenied

MAX_RESPONSE = 96 * 1024
TITLE_LIMIT = 180
ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,160}$")
PORTAL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,60}\.bitrix24\.(?:ru|com|eu|by|kz)$")
ACTIONS = frozenset({
    "google.tasks.create", "google.tasks.update",
    "bitrix.tasks.create", "bitrix.tasks.update",
})


def _dedupe(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise WorkDenied("SERVICE_DUPLICATE_JSON_FIELD")
        out[k] = v
    return out


def check_text(value, maximum=TITLE_LIMIT):
    if (type(value) is not str or not 1 <= len(value.strip()) <= maximum or
            any(ord(c) < 32 and c not in "\n" for c in value)):
        raise WorkDenied("SERVICE_TEXT_INVALID")
    return value.strip()


def valid_id(value):
    if type(value) is not str or (
            value!="@default" and not ID_RE.fullmatch(value)):
        raise WorkDenied("SERVICE_ID_INVALID")
    return value


class SafeServiceTransport:
    """Exact fixed HTTPS host, public pinned DNS/IP, no proxy, no redirects."""
    def __init__(self, allowed_hosts=()):
        self.hosts = frozenset(allowed_hosts)

    def call(self, host, method, path, token, payload=None, query=None, auth_style="bearer"):
        if (host not in self.hosts or not host or type(path) is not str
                or not path.startswith("/") or "://" in path or
                "?" in path or "#" in path or "\\" in path or
                method not in ("GET", "POST", "PATCH") or
                not isinstance(token, str) or not 8 <= len(token) <= 4096):
            raise WorkDenied("SERVICE_HTTP_TARGET_REFUSED")
        if auth_style not in ("bearer", "bitrix"):
            raise WorkDenied("SERVICE_AUTH_STYLE_REFUSED")
        if query:
            if type(query) is not dict or len(query) > 5:
                raise WorkDenied("SERVICE_QUERY_REFUSED")
            path += "?" + urlencode(query)
        body = None
        headers = {
            "Accept": "application/json", "Content-Type": "application/json",
            "User-Agent": "NeirozavodWorkOne/0.6 (explicit owner grant)",
        }
        if auth_style == "bitrix":
            payload = {**(payload or {}), "auth": token}
            # With Bitrix OAuth, auth is in the JSON body according to REST docs.
            if method == "GET":
                method = "POST"
        else:
            headers["Authorization"] = "Bearer " + token
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False,
                              separators=(",", ":")).encode("utf-8")
            if len(body) > 24 * 1024:
                raise WorkDenied("SERVICE_REQUEST_TOO_LARGE")
        ip = public_dns(host)
        connection = PinnedHTTPSConnection(host, ip)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            if response.status < 200 or response.status >= 300:
                raise WorkDenied("SERVICE_HTTP_NOT_SUCCESS")
            if response.headers.get_content_type() not in (
                    "application/json", "text/json"):
                raise WorkDenied("SERVICE_CONTENT_TYPE_REFUSED")
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise WorkDenied("SERVICE_RESPONSE_TOO_LARGE")
            decoded = json.loads(data.decode("utf-8"), object_pairs_hook=_dedupe)
            if type(decoded) is not dict:
                raise WorkDenied("SERVICE_RESPONSE_NOT_OBJECT")
            return decoded
        except WorkDenied:
            raise
        except (OSError, TimeoutError, UnicodeError, ValueError, TypeError):
            raise WorkDenied("SERVICE_UNKNOWN_AFTER_NETWORK_ATTEMPT")
        finally:
            connection.close()


class GoogleWorkspaceAdapter:
    """Google Tasks writes; Drive/Gmail/Calendar list reads if scopes granted."""
    hosts = frozenset(("tasks.googleapis.com", "www.googleapis.com",
                       "gmail.googleapis.com"))

    def __init__(self, token_loader, transport=None):
        self.load = token_loader
        self.transport = transport or SafeServiceTransport(self.hosts)

    def _call(self, host, method, path, scope, payload=None, query=None):
        token = self.load("google", scope)
        if not token:
            raise WorkDenied("GOOGLE_NOT_CONNECTED_OR_SCOPE_MISSING")
        return self.transport.call(host,method,path,token,payload,query)

    def ready(self):
        return bool(self.load("google","tasks"))

    def read_task(self, list_id, task_id):
        return self._call("tasks.googleapis.com", "GET",
            "/tasks/v1/lists/"+quote(valid_id(list_id),safe="")+
            "/tasks/"+quote(valid_id(task_id),safe=""),"tasks")

    def list_tasks(self, list_id, limit=20):
        if type(limit) is not int or not 1 <= limit <= 50:
            raise WorkDenied("GOOGLE_TASKS_LIMIT_REFUSED")
        return self._call("tasks.googleapis.com", "GET",
            "/tasks/v1/lists/"+quote(valid_id(list_id),safe="")+"/tasks",
            "tasks",query={"maxResults":limit})

    def list_drive_files(self):
        return self._call("www.googleapis.com","GET","/drive/v3/files",
            "drive.metadata.readonly",query={
                "pageSize":20,
                "fields":"nextPageToken,files(id,name,mimeType,modifiedTime)",
            })

    def list_calendar_events(self):
        return self._call("www.googleapis.com","GET",
            "/calendar/v3/calendars/primary/events","calendar.readonly",
            query={"maxResults":20,"singleEvents":"true",
                   "orderBy":"startTime"})

    def list_gmail_messages(self):
        return self._call("gmail.googleapis.com","GET",
            "/gmail/v1/users/me/messages","gmail.readonly",
            query={"maxResults":20})

    def create(self, values):
        tasklist = valid_id(values["list_id"])
        payload = {"title": check_text(values["title"],1024),
                   "notes":check_text(values.get("notes") or "-",4000)}
        response=self._call("tasks.googleapis.com","POST",
            "/tasks/v1/lists/"+quote(tasklist,safe="")+"/tasks","tasks",payload)
        task_id=valid_id(response.get("id"))
        actual=self.read_task(tasklist,task_id)
        if actual.get("id") != task_id or actual.get("title") != payload["title"]:
            raise WorkDenied("SERVICE_READBACK_MISMATCH")
        return {"provider":"google.tasks","id":task_id,"verified":True}

    def update(self, values):
        list_id=valid_id(values["list_id"])
        task_id=valid_id(values["id"])
        title=check_text(values["title"],1024)
        before=self.read_task(list_id,task_id)
        if before.get("id") != task_id:
            raise WorkDenied("SERVICE_TARGET_NOT_FOUND")
        # The displayed previous title must still match the approved baseline.
        if before.get("title") != values["expected_title"]:
            raise WorkDenied("SERVICE_CONCURRENT_EDIT_REFUSED")
        endpoint="/tasks/v1/lists/"+quote(list_id,safe="")+"/tasks/"+quote(task_id,safe="")
        response=self._call("tasks.googleapis.com","PATCH",endpoint,"tasks",
                            {"title":title})
        if response.get("id") != task_id:
            raise WorkDenied("SERVICE_UPDATE_RESPONSE_INVALID")
        after=self.read_task(list_id,task_id)
        if after.get("title") != title:
            raise WorkDenied("SERVICE_READBACK_MISMATCH")
        return {"provider":"google.tasks","id":task_id,"verified":True}


class Bitrix24Adapter:
    def __init__(self, portal, token_loader, transport=None):
        if type(portal) is not str or not PORTAL_RE.fullmatch(portal):
            raise WorkDenied("BITRIX_PORTAL_HOST_INVALID")
        self.portal = portal
        self.load = token_loader
        self.transport = transport or SafeServiceTransport([portal])

    def ready(self):
        return bool(self.load("bitrix24","task"))

    def _call(self, method, fields):
        token=self.load("bitrix24","task")
        if not token:
            raise WorkDenied("BITRIX_NOT_CONNECTED")
        if method not in ("tasks.task.add","tasks.task.update",
                          "tasks.task.get","tasks.task.list"):
            raise WorkDenied("BITRIX_METHOD_REFUSED")
        # Official legacy Bitrix24 REST task endpoint with OAuth auth in body.
        data=self.transport.call(self.portal,"POST","/rest/"+method+".json",
                                 token,fields,auth_style="bitrix")
        if data.get("error"):
            raise WorkDenied("BITRIX_API_REFUSED")
        result=data.get("result")
        if type(result) is not dict:
            raise WorkDenied("BITRIX_RESPONSE_INVALID")
        return result

    def crm_get(self, entity, record_id):
        if entity not in ("deal","contact"):
            raise WorkDenied("BITRIX_CRM_ENTITY_REFUSED")
        token=self.load("bitrix24","task")
        # A dedicated CRM scope/token must be separately provisioned: task
        # OAuth token is insufficient; fail closed rather than escalate scopes.
        crm_token=self.load("bitrix24","crm")
        if not crm_token:
            raise WorkDenied("BITRIX_CRM_SCOPE_NOT_CONNECTED")
        data=self.transport.call(self.portal,"POST",
             "/rest/crm."+entity+".get.json",crm_token,
             {"id":int(valid_id(str(record_id)))},auth_style="bitrix")
        if data.get("error") or type(data.get("result")) is not dict:
            raise WorkDenied("BITRIX_CRM_READ_FAILED")
        return data["result"]

    def get(self, task_id):
        result=self._call("tasks.task.get",{"taskId":int(valid_id(str(task_id)))})
        task=result.get("task")
        if type(task) is not dict:
            raise WorkDenied("BITRIX_TASK_NOT_FOUND")
        return task

    @staticmethod
    def _title(task):
        return task.get("title",task.get("TITLE"))

    def create(self, values):
        title=check_text(values["title"])
        responsible=values["responsible_id"]
        if type(responsible) is not int or not 1 <= responsible <= 100000000:
            raise WorkDenied("BITRIX_RESPONSIBLE_INVALID")
        fields={"TITLE":title,"RESPONSIBLE_ID":responsible}
        if values.get("description"):
            fields["DESCRIPTION"]=check_text(values["description"],4000)
        result=self._call("tasks.task.add",{"fields":fields})
        task=result.get("task")
        task_id = task.get("id") if type(task) is dict else None
        task_id=valid_id(str(task_id))
        actual=self.get(task_id)
        if self._title(actual) != title:
            raise WorkDenied("SERVICE_READBACK_MISMATCH")
        return {"provider":"bitrix.tasks","id":task_id,"verified":True}

    def update(self, values):
        task_id=valid_id(values["id"])
        title=check_text(values["title"])
        actual=self.get(task_id)
        if self._title(actual) != values["expected_title"]:
            raise WorkDenied("SERVICE_CONCURRENT_EDIT_REFUSED")
        self._call("tasks.task.update",{"taskId":int(task_id),
                                        "fields":{"TITLE":title}})
        after=self.get(task_id)
        if self._title(after) != title:
            raise WorkDenied("SERVICE_READBACK_MISMATCH")
        return {"provider":"bitrix.tasks","id":task_id,"verified":True}


def approved_values(action, fields):
    if action not in ACTIONS or type(fields) is not dict:
        raise WorkDenied("SERVICE_ACTION_REFUSED")
    if action == "google.tasks.create":
        permitted={"list_id","title","notes"}
        required={"list_id","title"}
    elif action == "google.tasks.update":
        permitted=required={"list_id","id","title","expected_title"}
    elif action == "bitrix.tasks.create":
        permitted={"title","responsible_id","description"}
        required={"title","responsible_id"}
    else:
        permitted=required={"id","title","expected_title"}
    if set(fields)-permitted or required-set(fields):
        raise WorkDenied("SERVICE_FIELDS_REFUSED")
    clean=dict(fields)
    check_text(clean["title"],1024)
    for k in ("notes","description","expected_title"):
        if k in clean:
            check_text(clean[k],4000)
    for k in ("id","list_id"):
        if k in clean:
            valid_id(clean[k])
    if "responsible_id" in clean:
        if type(clean["responsible_id"]) is not int or not 1 <= clean["responsible_id"] <= 100000000:
            raise WorkDenied("BITRIX_RESPONSIBLE_INVALID")
    return clean


class ServiceOne:
    """2-phase owner-approved write, verified readback and no ambiguous retry."""
    def __init__(self, store, adapters=None):
        self.store=store
        self.adapters=adapters or {}
        self.lock=threading.RLock()
        self.pending={}
        self.slot=threading.BoundedSemaphore(1)
        with self.store.db() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS one_service_operations (
              id TEXT PRIMARY KEY, project TEXT NOT NULL, action TEXT NOT NULL,
              digest TEXT NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL,
              updated INTEGER NOT NULL, result_id TEXT, error TEXT
            );
            CREATE INDEX IF NOT EXISTS one_service_project ON
                one_service_operations(project,created);
            """)
            c.execute("UPDATE one_service_operations SET state='UNKNOWN_NO_RETRY',"
                      "error='INTERRUPTED_WRITE' WHERE state='RUNNING'")
            c.execute("UPDATE one_service_operations SET state='EXPIRED',"
                      "error='APPROVAL_NOT_RESUMABLE' WHERE state='READY'")
            c.commit()

    def status(self):
        return {
            "configured":{k:bool(k in self.adapters) for k in
                         ("google.tasks","bitrix.tasks")},
            "available_actions":sorted(ACTIONS),
            "requires_approval":True,
            "no_auto_retry_on_unknown":True,
            "google_other_read_capabilities":[
                "tasks.list","drive.files.list","gmail.messages.list",
                "calendar.events.list"],
        }

    @staticmethod
    def _digest(action, values):
        body=json.dumps({"action":action,"fields":values},sort_keys=True,
                        ensure_ascii=False,separators=(",",":")).encode("utf8")
        return hashlib.sha256(body).hexdigest()

    def prepare(self, project, action, fields):
        self.store.project(project)
        values=approved_values(action,fields)
        provider=action.split(".")[0]+".tasks"
        if provider not in self.adapters:
            raise WorkDenied("SERVICE_PROVIDER_NOT_CONNECTED")
        adapter=self.adapters[provider]
        if hasattr(adapter,"ready") and not adapter.ready():
            raise WorkDenied("SERVICE_PROVIDER_AUTHORIZATION_REQUIRED")
        digest=self._digest(action,values)
        with self.lock:
            for rid,v in list(self.pending.items()):
                if time.monotonic()-v["created"]>300:
                    del self.pending[rid]
            if len(self.pending)>=4:
                raise WorkDenied("SERVICE_TOO_MANY_PENDING")
            rid=secrets.token_hex(16)
            now=int(time.time())
            with self.store.db() as c:
                c.execute("INSERT INTO one_service_operations VALUES"
                          "(?,?,?,?,?,?,?,NULL,NULL)",
                          (rid,project,action,digest,"READY",now,now))
                self.store.event(c,"ONE_SERVICE_PREPARED",project,
                                 {"operation":rid,"action":action})
                c.commit()
            self.pending[rid]={"project":project,"action":action,
                               "fields":values,"digest":digest,
                               "created":time.monotonic()}
            # No sensitive values returned after preparation; UI already has draft.
            return {"id":rid,"action":action,"state":"READY",
                    "approval_expires_seconds":300}

    def commit(self, project, rid, action, fields):
        self.store.project(project)
        values=approved_values(action,fields)
        digest=self._digest(action,values)
        if not self.slot.acquire(blocking=False):
            raise WorkDenied("SERVICE_ONE_WRITE_AT_A_TIME")
        try:
            with self.lock:
                pending=self.pending.get(rid)
                if (not pending or pending["project"]!=project or
                    pending["action"]!=action or
                    not hmac.compare_digest(pending["digest"],digest) or
                    time.monotonic()-pending["created"]>300):
                    raise WorkDenied("SERVICE_APPROVAL_INVALID")
                with self.store.db() as c:
                    row=c.execute("SELECT state FROM one_service_operations"
                                  " WHERE id=? AND project=? AND digest=?",
                                  (rid,project,digest)).fetchone()
                    if not row or row["state"]!="READY":
                        raise WorkDenied("SERVICE_REPLAY_REFUSED")
                    c.execute("UPDATE one_service_operations SET state='RUNNING',"
                              "updated=? WHERE id=?", (int(time.time()),rid))
                    c.commit()
                del self.pending[rid]
            adapter=self.adapters[action.split(".")[0]+".tasks"]
            # Any exception after the write could mean it succeeded remotely.
            # Never issue an automatic retry, even if the readback timed out.
            outcome=None
            err=None
            try:
                method="create" if action.endswith("create") else "update"
                outcome=getattr(adapter,method)(values)
                if not outcome.get("verified") or not outcome.get("id"):
                    raise WorkDenied("SERVICE_NOT_VERIFIED")
            except Exception:
                err="SERVICE_UNKNOWN_NO_AUTO_RETRY"
            state="VERIFIED" if not err else "UNKNOWN_NO_RETRY"
            with self.store.db() as c:
                c.execute("UPDATE one_service_operations SET state=?,updated=?,"
                          "result_id=?,error=? WHERE id=?",
                          (state,int(time.time()),
                           str(outcome["id"]) if outcome else None,err,rid))
                self.store.event(c,"ONE_SERVICE_"+state,project,
                                 {"operation":rid,"action":action})
                c.commit()
            return {"id":rid,"state":state,"record_id":str(outcome["id"])
                    if outcome else None,"error":err}
        finally:
            self.slot.release()

    def read(self, project, resource, fields):
        """One bounded explicit read, never an arbitrary user-supplied URL."""
        self.store.project(project)
        if type(fields) is not dict:
            raise WorkDenied("SERVICE_READ_FIELDS_INVALID")
        if resource in (
          "google.tasks.list","google.drive.files.list",
          "google.gmail.messages.list","google.calendar.events.list"):
            adapter=self.adapters.get("google.tasks")
            if adapter is None:
                raise WorkDenied("GOOGLE_NOT_CONNECTED")
            if resource=="google.tasks.list":
                if set(fields)!={"list_id"}:
                    raise WorkDenied("SERVICE_READ_FIELDS_INVALID")
                result=adapter.list_tasks(fields["list_id"])
            else:
                if fields:
                    raise WorkDenied("SERVICE_READ_FIELDS_INVALID")
                method={
                    "google.drive.files.list":"list_drive_files",
                    "google.gmail.messages.list":"list_gmail_messages",
                    "google.calendar.events.list":"list_calendar_events",
                }[resource]
                result=getattr(adapter,method)()
        elif resource in ("bitrix.tasks.get", "bitrix.crm.deal.get",
                          "bitrix.crm.contact.get"):
            adapter=self.adapters.get("bitrix.tasks")
            if adapter is None or set(fields)!={"id"}:
                raise WorkDenied("BITRIX_READ_NOT_CONNECTED")
            rid=valid_id(str(fields["id"]))
            if resource=="bitrix.tasks.get":
                result=adapter.get(rid)
            else:
                result=adapter.crm_get(resource.split(".")[2],rid)
        else:
            raise WorkDenied("SERVICE_READ_ACTION_REFUSED")
        if not isinstance(result, dict):
            raise WorkDenied("SERVICE_READ_RESPONSE_INVALID")
        raw=json.dumps(result,ensure_ascii=False)
        if len(raw.encode("utf8"))>32000:
            raise WorkDenied("SERVICE_READ_TOO_LARGE")
        # Do not write any CRM contact or external data into logs or SQLite.
        return {"resource":resource,"data":result}

    def operations(self, project):
        self.store.project(project)
        with self.store.db() as c:
            entries=c.execute(
                "SELECT id,action,state,created,updated,result_id,error"
                " FROM one_service_operations WHERE project=?"
                " ORDER BY created DESC,id DESC LIMIT 30",(project,)).fetchall()
        return [dict(x) for x in entries]
