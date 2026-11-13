"""Qwen natural-language planner for ONE. Drafts ONLY, never tool execution.

The model output is untrusted: strict JSON schema -> existing deterministic
scenario validator -> owner reviews -> explicit execution as separate action.
Supports existing pinned Qwen draft provider or local Ollama (no paid API).
"""
from __future__ import annotations

from hashlib import sha256
import http.client
import json
import re
import secrets
import sqlite3
import threading
import time

from work_core import WorkDenied
from workflow_one import parse_scenario

SCHEMA = "nf.one.qwen.proposal.v1"
PLANNABLE = frozenset(("open","click_text","fill_label","check_text",
                       "scroll","frame"))
MODEL = "qwen3.5:9b"
MODEL_TIMEOUT = 120


def _unique(items):
    result={}
    for key,value in items:
        if key in result:
            raise WorkDenied("QWEN_DUPLICATE_FIELD")
        result[key]=value
    return result


def parse_proposal(raw, allowed_hosts):
    if type(raw) is not str or not 10 <= len(raw.encode("utf8")) <= 12000:
        raise WorkDenied("QWEN_MODEL_OUTPUT_INVALID")
    try:
        doc=json.loads(raw,object_pairs_hook=_unique)
    except (ValueError,TypeError):
        raise WorkDenied("QWEN_NOT_STRUCTURED_JSON")
    if (type(doc) is not dict or set(doc)!={"schema","steps"} or
            doc["schema"]!=SCHEMA or type(doc["steps"]) is not list or
            not 1 <= len(doc["steps"]) <= 12):
        raise WorkDenied("QWEN_SCHEMA_REFUSED")
    lines=[]
    for pos,step in enumerate(doc["steps"]):
        if type(step) is not dict or step.get("op") not in PLANNABLE:
            raise WorkDenied("QWEN_UNAUTHORIZED_ACTION")
        op=step["op"]
        if op=="open":
            if set(step)!={"op","url"}:
                raise WorkDenied("QWEN_OPEN_FIELDS_INVALID")
            lines.append("Открой "+str(step["url"]))
        elif op in ("click_text","check_text"):
            key="label" if op=="click_text" else "text"
            value=step.get(key)
            if set(step)!={"op",key} or type(value) is not str or len(value)>180:
                raise WorkDenied("QWEN_TEXT_STEP_INVALID")
            if any(x in value for x in ('«','»','"','\n','\r')):
                raise WorkDenied("QWEN_DELIMITER_REFUSED")
            lines.append(("Нажми " if op=="click_text" else "Проверь текст ")+
                         "«"+value+"»")
        elif op=="fill_label":
            if set(step)!={"op","label","text"}:
                raise WorkDenied("QWEN_FILL_FIELDS_INVALID")
            label,text=step["label"],step["text"]
            if type(label) is not str or type(text) is not str:
                raise WorkDenied("QWEN_FILL_INVALID")
            if any(x in (label+text) for x in ('«','»','"','\n','\r')):
                raise WorkDenied("QWEN_DELIMITER_REFUSED")
            lines.append("Напечатай в поле «"+label+"» «"+text+"»")
        elif op=="scroll":
            if set(step)!={"op","direction"} or step["direction"] not in ("up","down"):
                raise WorkDenied("QWEN_SCROLL_INVALID")
            lines.append("Прокрути "+("вверх" if step["direction"]=="up" else "вниз"))
        elif op=="frame":
            if set(step)!={"op"}:
                raise WorkDenied("QWEN_FRAME_FIELDS_INVALID")
            lines.append("Сделай снимок")
    script="\n".join(lines)
    parsed=parse_scenario(script,allowed_hosts)
    return {"script":script,"steps":len(parsed),
            "actions":[s["op"] for s in parsed]}


def prompt_for(user_goal, allowed_hosts):
    if type(user_goal) is not str or not 15 <= len(user_goal.strip()) <= 400:
        raise WorkDenied("QWEN_GOAL_INVALID")
    if not allowed_hosts:
        raise WorkDenied("QWEN_NO_APPROVED_HOST")
    if len(allowed_hosts)>8:
        raise WorkDenied("QWEN_TOO_MANY_HOSTS")
    hosts=", ".join(sorted(allowed_hosts))
    instruction=(
        "Твоя роль: только составить проект плана безопасного браузерного "
        "сценария по запросу владельца. Ничего не выполняй. Выведи ТОЛЬКО "
        "строгий JSON без Markdown и пояснений. Схема: "
        '{"schema":"nf.one.qwen.proposal.v1","steps":['
        '{"op":"open","url":"https://example.org/"},'
        '{"op":"click_text","label":"Услуги"},'
        '{"op":"check_text","text":"Услуги"},'
        '{"op":"frame"}]}.'
        " Можно также fill_label с label и text, scroll с direction up/down. "
        " Первый шаг — open. Макс 12 шагов. "
        " Нельзя: вход в аккаунты, ввод паролей, оплату, отправку форм, "
        " удаление, скачивание, администрирование, внешние домены, "
        " системные команды, переходы в другие приложения. "
        " Разрешённые домены: "+hosts+
        ". Если задачу нельзя выполнить безопасно, предложи только "
        " read-only навигацию и снимок. Задача владельца: "+user_goal.strip()
    )
    if len(instruction)>2500:
        raise WorkDenied("QWEN_GOAL_TOO_LONG")
    return instruction


class LocalOllamaQwen:
    def available(self):
        try:
            con=http.client.HTTPConnection("127.0.0.1",11434,timeout=2)
            try:
                con.request("GET","/api/tags")
                res=con.getresponse()
                if res.status!=200:return False
                raw=res.read(30001)
                if len(raw)>30000:return False
                tags=json.loads(raw.decode("utf8"))
                return any(x.get("name")==self.model for x in tags.get("models",[]))
            finally:
                con.close()
        except (OSError,ValueError,UnicodeError):
            return False

    def __init__(self, model=MODEL):
        if model != MODEL:
            raise WorkDenied("QWEN_MODEL_NOT_APPROVED")
        self.model=model

    def __call__(self, project, request):
        # Can only connect to fixed user-loopback port; no arbitrary URLs.
        connection=http.client.HTTPConnection("127.0.0.1",11434,timeout=MODEL_TIMEOUT)
        body=json.dumps({
            "model":self.model, "prompt":request, "stream":False,
            "format":"json", "options":{"temperature":0,"num_predict":1200},
        },ensure_ascii=False).encode("utf8")
        if len(body)>6000:
            raise WorkDenied("QWEN_REQUEST_TOO_LARGE")
        try:
            connection.request("POST","/api/generate",body=body,headers={
                "Content-Type":"application/json","Accept":"application/json"})
            response=connection.getresponse()
            if response.status!=200:
                raise WorkDenied("QWEN_LOCAL_MODEL_NOT_READY")
            data=response.read(16001)
            if len(data)>16000:
                raise WorkDenied("QWEN_OUTPUT_TOO_LARGE")
            result=json.loads(data.decode("utf8"))
            if (not isinstance(result,dict) or result.get("model","").split(":")[0]
                    != self.model.split(":")[0] or
                    type(result.get("response")) is not str):
                raise WorkDenied("QWEN_LOCAL_RESPONSE_INVALID")
            return {"status":"PROPOSED_UNVERIFIED","text":result["response"]}
        except WorkDenied:
            raise
        except (OSError,TimeoutError,ValueError,UnicodeError):
            raise WorkDenied("QWEN_RESULT_UNKNOWN_NO_RETRY")
        finally:
            connection.close()


class QwenPlannerOne:
    def __init__(self, store, browser, model_fn=None):
        self.store,self.browser=store,browser
        self.model_fn=model_fn
        self.lock=threading.RLock()
        self.pending={}
        with store.db() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS one_qwen_plans (
               id TEXT PRIMARY KEY, project TEXT NOT NULL,
               digest TEXT NOT NULL, state TEXT NOT NULL,
               created INTEGER NOT NULL,updated INTEGER NOT NULL,
               error TEXT
            );
            """)
            c.execute("UPDATE one_qwen_plans SET state='UNKNOWN_NO_RETRY',"
                      "error='MODEL_INTERRUPTED' WHERE state='GENERATING'")
            c.commit()

    def status(self):
        return {"configured":self.model_fn is not None,
                "mode":"qwen_drafts_only_no_tool_execution",
                "model":MODEL, "owner_approval_required":True,
                "no_auto_retry":True}

    def propose(self, project, goal):
        self.store.project(project)
        instruction=prompt_for(goal,self.browser.allowed_hosts)
        if not self.model_fn:
            raise WorkDenied("QWEN_PROVIDER_NOT_CONNECTED")
        rid=secrets.token_hex(16)
        with self.lock:
            if sum(1 for x in self.pending.values() if x["state"]=="GENERATING")>=1:
                raise WorkDenied("QWEN_ONE_PLAN_AT_A_TIME")
            now=int(time.time())
            with self.store.db() as c:
                c.execute("INSERT INTO one_qwen_plans VALUES (?,?,?,?,?,?,NULL)",
                          (rid,project,sha256(instruction.encode("utf8")).hexdigest(),
                           "GENERATING",now,now))
                self.store.event(c,"QWEN_PLAN_REQUESTED",project,{"run":rid})
                c.commit()
            self.pending[rid]={"project":project,"state":"GENERATING",
                               "created":time.monotonic()}
            threading.Thread(target=self._produce,args=(rid,project,instruction),
                name="nf-one-qwen-"+rid[:8],daemon=True).start()
        return {"id":rid,"state":"GENERATING"}

    def _produce(self, rid, project, instruction):
        try:
            reply=self.model_fn(project,instruction)
            if (type(reply) is not dict or reply.get("status")!="PROPOSED_UNVERIFIED"
                    or type(reply.get("text")) is not str):
                raise WorkDenied("QWEN_MODEL_NOT_VERIFIED")
            safe=parse_proposal(reply["text"],self.browser.allowed_hosts)
            result={"state":"PROPOSED","script":safe["script"],
                    "steps":safe["steps"],"model":MODEL}
            dbstate="PROPOSED"
        except Exception:
            result={"state":"UNKNOWN_NO_RETRY","error":"QWEN_PLAN_UNAVAILABLE_OR_REFUSED"}
            dbstate="UNKNOWN_NO_RETRY"
        with self.lock:
            if rid in self.pending:
                self.pending[rid].update(result)
            with self.store.db() as c:
                c.execute("UPDATE one_qwen_plans SET state=?,updated=?,error=? WHERE id=?",
                          (dbstate,int(time.time()),result.get("error"),rid))
                self.store.event(c,"QWEN_PLAN_"+dbstate,project,{"run":rid})
                c.commit()

    def get(self, project, rid):
        self.store.project(project)
        with self.store.db() as c:
            row=c.execute("SELECT state,error FROM one_qwen_plans WHERE id=? AND project=?",
                          (rid,project)).fetchone()
        if not row:
            raise WorkDenied("QWEN_PLAN_NOT_FOUND")
        with self.lock:
            if rid in self.pending and self.pending[rid]["project"]==project:
                entry=self.pending[rid]
                return {"id":rid,"state":entry["state"],**{
                    k:entry[k] for k in ("script","steps","model","error") if k in entry}}
        return {"id":rid,"state":row["state"],"error":row["error"]}
