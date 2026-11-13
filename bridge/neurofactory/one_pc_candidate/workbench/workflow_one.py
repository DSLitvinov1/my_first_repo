"""Work ONE v0.5: durable, approval-gated multi-step browser scenarios.

One owned HTTPS origin, deterministic Russian step grammar, human-authorized
execution. The script including typed text is NEVER written to SQLite or logs.
The model cannot dispatch actions. A process restart invalidates in-flight runs.
"""
from __future__ import annotations

from hashlib import sha256
import hmac
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from agent_one import validated_url
from work_core import WorkDenied

MAX_SCRIPT = 6000
MAX_STEPS = 12
QUOTE = r"[«\"]([^»\"]{1,2000})[»\"]"
OPEN = re.compile(r"^(?:открой|открыть)\s+(https://\S+)$", re.I)
CLICK = re.compile(r"^(?:нажми|нажать)\s+" + QUOTE + r"$", re.I)
FILL = re.compile(r"^(?:напечатай|впиши|введи)\s+в\s+поле\s+" +
                  QUOTE + r"\s+" + QUOTE + r"$", re.I)
CHECK = re.compile(r"^(?:проверь|найди)\s+текст\s+" + QUOTE + r"$", re.I)
SCROLL = re.compile(r"^(?:прокрути|прокрутить)\s+(вверх|вниз)$", re.I)
SHOT = re.compile(r"^(?:сделай\s+снимок|снимок|скриншот)$", re.I)


def parse_scenario(script, approved_hosts):
    if (type(script) is not str or not 10 <= len(script) <= MAX_SCRIPT
            or any(ord(c) < 32 and c not in ("\n", "\r") for c in script)):
        raise WorkDenied("ONE_SCENARIO_INVALID")
    lines = [x.strip() for x in script.splitlines() if x.strip()]
    if not 1 <= len(lines) <= MAX_STEPS:
        raise WorkDenied("ONE_SCENARIO_STEP_COUNT")
    result = []
    for n, line in enumerate(lines):
        if n == 0:
            match = OPEN.fullmatch(line)
            if not match:
                raise WorkDenied("ONE_SCENARIO_FIRST_STEP_MUST_OPEN")
            url = validated_url(match.group(1))
            host = urlsplit(url).hostname
            if host not in approved_hosts:
                raise WorkDenied("ONE_SCENARIO_HOST_NOT_APPROVED")
            result.append({"op": "open", "url": url, "host": host,
                           "view": "Открыть " + host})
            continue
        if OPEN.fullmatch(line):
            raise WorkDenied("ONE_SCENARIO_SINGLE_HOST_ONLY")
        match = CLICK.fullmatch(line)
        if match and len(match.group(1)) <= 90:
            result.append({"op": "click_text", "label": match.group(1),
                           "view": "Нажать найденный элемент"})
            continue
        match = FILL.fullmatch(line)
        if match and len(match.group(1)) <= 90 and 1 <= len(match.group(2)) <= 2000:
            # BrowserController validates bytes and forbidden control codes.
            result.append({"op": "fill_label", "label": match.group(1),
                           "text": match.group(2), "view": "Напечатать в поле"})
            continue
        match = CHECK.fullmatch(line)
        if match and 1 <= len(match.group(1)) <= 180:
            result.append({"op": "check_text", "text": match.group(1),
                           "view": "Убедиться, что текст есть на странице"})
            continue
        match = SCROLL.fullmatch(line)
        if match:
            result.append({"op": "scroll", "delta": 550 if match.group(1).lower()=="вниз" else -550,
                           "view": "Прокрутить страницу"})
            continue
        if SHOT.fullmatch(line):
            result.append({"op": "frame", "view": "Сделать снимок результата"})
            continue
        raise WorkDenied("ONE_SCENARIO_UNKNOWN_STEP_" + str(n + 1))
    return result


class WorkflowOne:
    """One verified execution per approval, journal checkpoints, no model authority."""
    def __init__(self, store, browser):
        self.store, self.browser = store, browser
        self.lock = threading.RLock()
        self.slot = threading.BoundedSemaphore(1)
        self.prepared = {}
        self.images = {}
        with store.db() as c:
            c.executescript("""
              CREATE TABLE IF NOT EXISTS one_workflows (
                id TEXT PRIMARY KEY, project TEXT NOT NULL, digest TEXT NOT NULL,
                state TEXT NOT NULL, created INTEGER NOT NULL,
                updated INTEGER NOT NULL, error TEXT
              );
              CREATE TABLE IF NOT EXISTS one_workflow_steps (
                run_id TEXT NOT NULL, position INTEGER NOT NULL,
                op TEXT NOT NULL, state TEXT NOT NULL,
                PRIMARY KEY(run_id, position)
              );
              CREATE INDEX IF NOT EXISTS one_workflow_project
                ON one_workflows(project,created);
            """)
            c.execute("UPDATE one_workflows SET state='UNKNOWN_NO_RETRY',"
                      "error='INTERRUPTED_EXECUTION' WHERE state='RUNNING'")
            c.execute("UPDATE one_workflows SET state='EXPIRED',"
                      "error='APPROVAL_NOT_RESUMABLE' WHERE state='READY'")
            c.execute("UPDATE one_workflow_steps SET state='UNKNOWN_NO_RETRY'"
                      " WHERE state='RUNNING'")
            c.commit()

    def capabilities(self):
        return {"implemented": ["browser.screenshot","browser.mouse",
                                "browser.keyboard","browser.semantic_click",
                                "browser.semantic_fill","browser.scenario_journal"],
                "not_connected": ["desktop.global_input","desktop.window_automation",
                                  "google.oauth","tinyfish.remote","crm.write",
                                  "qwen.model_tool_calls","core9.host.tool_grants"],
                "permissions": "owner_previews_and_approves_each_scenario",
                "max_steps": MAX_STEPS, "model_can_execute_tools": False}

    def prepare(self, project, script):
        self.store.project(project)
        steps = parse_scenario(script, self.browser.allowed_hosts)
        now = int(time.time())
        with self.lock:
            for k,v in list(self.prepared.items()):
                if time.monotonic() - v["prepared_at"] > 300:
                    del self.prepared[k]
            if len(self.prepared) >= 4:
                raise WorkDenied("ONE_TOO_MANY_PENDING_APPROVALS")
            rid = secrets.token_hex(16)
            digest = sha256(script.encode("utf8")).hexdigest()
            with self.store.db() as c:
                c.execute("INSERT INTO one_workflows VALUES (?,?,?,?,?,?,NULL)",
                          (rid,project,digest,"READY",now,now))
                for pos,step in enumerate(steps):
                    c.execute("INSERT INTO one_workflow_steps VALUES (?,?,?,?)",
                              (rid,pos,step["op"],"READY"))
                self.store.event(c,"ONE_SCENARIO_PREPARED",project,
                                 {"run":rid,"steps":len(steps)})
                c.commit()
            self.prepared[rid] = {
                "project":project, "digest":digest, "prepared_at":time.monotonic()}
        return {"run_id":rid,"state":"READY",
                "steps":[{"position":n+1,"action":x["op"],"description":x["view"]}
                         for n,x in enumerate(steps)]}

    def get(self, project, run_id, with_image=False):
        self.store.project(project)
        with self.store.db() as c:
            r = c.execute("SELECT id,project,state,created,updated,error FROM one_workflows"
                          " WHERE id=? AND project=?", (run_id,project)).fetchone()
            if not r:
                raise WorkDenied("ONE_SCENARIO_NOT_FOUND")
            steps = c.execute("SELECT position,op,state FROM one_workflow_steps"
                              " WHERE run_id=? ORDER BY position", (run_id,)).fetchall()
        output = {"id":r["id"],"project_id":project,"state":r["state"],
                  "created":r["created"],"updated":r["updated"],"error":r["error"],
                  "steps":[{"number":s["position"]+1,"action":s["op"],"state":s["state"]}
                           for s in steps]}
        if with_image and run_id in self.images:
            output["frame"] = self.images[run_id]
        return output

    def runs(self, project):
        self.store.project(project)
        with self.store.db() as c:
            ids=[x[0] for x in c.execute(
                "SELECT id FROM one_workflows WHERE project=? ORDER BY created DESC,id DESC LIMIT 12",
                (project,))]
        return [self.get(project,x) for x in ids]

    def start(self, project, run_id, script):
        self.store.project(project)
        if type(run_id) is not str or not re.fullmatch(r"[a-f0-9]{32}",run_id):
            raise WorkDenied("ONE_INVALID_RUN_ID")
        # Reparse and revalidate on execution, never trust unverified proposal
        # or earlier text that may have been modified in the UI.
        steps = parse_scenario(script,self.browser.allowed_hosts)
        digest = sha256(script.encode("utf8")).hexdigest()
        if not self.slot.acquire(blocking=False):
            raise WorkDenied("ONE_SCENARIO_BUSY")
        try:
            with self.lock:
                item=self.prepared.get(run_id)
                if (not item or item["project"]!=project or
                    not hmac.compare_digest(item["digest"],digest) or
                    time.monotonic()-item["prepared_at"]>300):
                    raise WorkDenied("ONE_SCENARIO_APPROVAL_INVALID")
                with self.store.db() as c:
                    row = c.execute("SELECT state,digest FROM one_workflows"
                                    " WHERE id=? AND project=?", (run_id,project)).fetchone()
                    if not row or row["state"]!="READY" or row["digest"]!=digest:
                        raise WorkDenied("ONE_SCENARIO_REPLAY_REFUSED")
                    c.execute("UPDATE one_workflows SET state='RUNNING',updated=?"
                              " WHERE id=?", (int(time.time()),run_id))
                    c.commit()
                del self.prepared[run_id]
            thread=threading.Thread(target=self._run,
                                    args=(project,run_id,steps),
                                    name="nf-one-scenario-"+run_id[:8],daemon=True)
            thread.start()
            # A tiny scenario may finish before this HTTP request returns.
            # "ACCEPTED" is a truthful acknowledgement, not a claim the work
            # is still running or has already completed.
            return {"id":run_id,"project_id":project,"state":"ACCEPTED"}
        except BaseException:
            self.slot.release()
            raise

    def _run(self, project, run_id, steps):
        session = None
        error = None
        try:
            for pos,step in enumerate(steps):
                with self.store.db() as c:
                    c.execute("UPDATE one_workflow_steps SET state='RUNNING'"
                              " WHERE run_id=? AND position=?", (run_id,pos))
                    c.commit()
                if step["op"]=="open":
                    response=self.browser.open(project,step["url"])
                    session=response["session_id"]
                elif step["op"]=="click_text":
                    response=self.browser.action(project,session,"click_text",
                                                 label=step["label"])
                elif step["op"]=="fill_label":
                    response=self.browser.action(project,session,"fill_label",
                                                 label=step["label"],text=step["text"])
                elif step["op"]=="check_text":
                    response=self.browser.action(project,session,"check_text",
                                                 text=step["text"])
                elif step["op"]=="scroll":
                    response=self.browser.action(project,session,"scroll",
                                                 delta=step["delta"])
                elif step["op"]=="frame":
                    response=self.browser.action(project,session,"frame")
                else:
                    raise WorkDenied("ONE_UNKNOWN_TOOL")
                frame=response.get("frame")
                if isinstance(frame,dict) and isinstance(frame.get("image"),str):
                    if len(frame["image"]) <= 850000:
                        if run_id not in self.images and len(self.images)>=12:
                            self.images.pop(next(iter(self.images)))
                        self.images[run_id]={"image":frame["image"],
                                             "title":frame.get("title","")[:160]}
                with self.store.db() as c:
                    c.execute("UPDATE one_workflow_steps SET state='DONE'"
                              " WHERE run_id=? AND position=?", (run_id,pos))
                    c.commit()
        except Exception:
            # Never store untrusted page text, field values, or raw exceptions.
            error="ONE_STEP_FAILED_NO_AUTO_RETRY"
            with self.store.db() as c:
                c.execute("UPDATE one_workflow_steps SET state='FAILED'"
                          " WHERE run_id=? AND state='RUNNING'", (run_id,))
                c.commit()
        finally:
            if session:
                try:
                    self.browser.close(project,session)
                except Exception:
                    error="ONE_CLEANUP_UNCERTAIN_NO_RETRY"
            try:
                with self.store.db() as c:
                    state="FAILED" if error else "DONE"
                    c.execute("UPDATE one_workflows SET state=?,error=?,updated=? WHERE id=?",
                              (state,error,int(time.time()),run_id))
                    self.store.event(c,"ONE_SCENARIO_"+state,project,
                                     {"run":run_id,"steps":len(steps)})
                    c.commit()
            finally:
                self.slot.release()
