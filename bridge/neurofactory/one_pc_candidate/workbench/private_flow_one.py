"""One-owner read-only browser verification followed by one approved service write.

In-memory approvals vanish on restart. Browser and service retain their own
durable journals. Model outputs cannot call this module directly.
"""
from hashlib import sha256
import hmac
import json
import secrets
import threading
import time

from service_one import approved_values
from workflow_one import parse_scenario
from work_core import WorkDenied

READ = frozenset(("open", "check_text", "frame", "scroll"))
TTL = 600

def digest(script, action, fields):
    raw=json.dumps({"script":script,"action":action,"fields":fields},
                   ensure_ascii=False,sort_keys=True,separators=(",",":"))
    return sha256(raw.encode("utf-8")).hexdigest()

class PrivateFlowOne:
    """Separate approvals are required for browser read and external write."""
    def __init__(self, store, workflow, services):
        self.store,self.workflow,self.services=store,workflow,services
        self.lock=threading.RLock()
        self.flows={}

    def _verify(self, project, script, action, fields):
        self.store.project(project)
        steps=parse_scenario(script,self.workflow.browser.allowed_hosts)
        if len(steps)>8 or any(x["op"] not in READ for x in steps):
            raise WorkDenied("PRIVATE_FLOW_READ_ONLY_REQUIRED")
        values=approved_values(action,fields)
        return steps,values,digest(script,action,values)

    def _get(self, project, rid):
        self.store.project(project)
        x=self.flows.get(rid)
        if not x or x["project"]!=project:
            raise WorkDenied("PRIVATE_FLOW_NOT_FOUND")
        if time.monotonic()-x["created"]>TTL and x["state"] not in (
                "VERIFIED","UNKNOWN_NO_RETRY","FAILED","EXPIRED"):
            x["state"]="EXPIRED"
        return x

    def prepare(self, project, script, action, fields):
        steps,values,check=self._verify(project,script,action,fields)
        with self.lock:
            for k,x in list(self.flows.items()):
                if time.monotonic()-x["created"]>TTL:
                    del self.flows[k]
            if len(self.flows)>=4:
                raise WorkDenied("PRIVATE_FLOW_TOO_MANY")
            rid=secrets.token_hex(16)
            self.flows[rid]={"project":project,"digest":check,
                             "created":time.monotonic(),"state":"PREPARED",
                             "browser_run":None}
        return {"id":rid,"state":"PREPARED","browser_steps":len(steps),
                "service_action":action,"write_requires_separate_confirmation":True}

    def start(self, project, rid, script, action, fields):
        steps,values,check=self._verify(project,script,action,fields)
        with self.lock:
            x=self._get(project,rid)
            if x["state"]!="PREPARED" or not hmac.compare_digest(check,x["digest"]):
                raise WorkDenied("PRIVATE_FLOW_APPROVAL_INVALID")
            x["state"]="UNKNOWN_NO_RETRY"
            try:
                plan=self.workflow.prepare(project,script)
                x["browser_run"]=plan["run_id"]
                self.workflow.start(project,plan["run_id"],script)
            except Exception:
                raise WorkDenied("PRIVATE_FLOW_BROWSER_START_UNKNOWN")
            x["state"]="READING"
        return {"id":rid,"state":"READING"}

    def status(self, project, rid):
        with self.lock:
            x=self._get(project,rid)
            if x["state"]=="READING":
                try:
                    current=self.workflow.get(project,x["browser_run"])["state"]
                    if current=="DONE":
                        x["state"]="AWAITING_WRITE"
                    elif current in ("FAILED","UNKNOWN_NO_RETRY","EXPIRED"):
                        x["state"]="FAILED" if current=="FAILED" else "UNKNOWN_NO_RETRY"
                except Exception:
                    x["state"]="UNKNOWN_NO_RETRY"
            return {"id":rid,"state":x["state"],
                    "write_confirmed":x["state"]=="VERIFIED"}

    def confirm(self, project, rid, script, action, fields):
        steps,values,check=self._verify(project,script,action,fields)
        with self.lock:
            x=self._get(project,rid)
            if self.status(project,rid)["state"]!="AWAITING_WRITE" or (
                    not hmac.compare_digest(check,x["digest"])):
                raise WorkDenied("PRIVATE_FLOW_WRITE_APPROVAL_INVALID")
            # Fence BEFORE invoking an external service, even if it times out.
            x["state"]="UNKNOWN_NO_RETRY"
            try:
                prepared=self.services.prepare(project,action,values)
                result=self.services.commit(project,prepared["id"],action,values)
                if result["state"]=="VERIFIED":
                    x["state"]="VERIFIED"
            except Exception:
                pass
            return {"id":rid,"state":x["state"],
                    "write_verified":x["state"]=="VERIFIED"}
