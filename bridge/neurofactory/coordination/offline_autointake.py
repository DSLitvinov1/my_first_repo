"""Coordinator-only authenticated event intake into ADVISORY SQLite candidates.

No CORE enqueue, provider call, filesystem writes, model, real approval or job dispatch.
The caller must secure HMAC secrets, HTTPS termination and SQLite file/OS ownership.
Project registry is preconfigured advisory data, NEVER external owner authorization.
"""
import hashlib
import hmac
import json
import re
import sqlite3
import uuid

class IntakeRejected(ValueError):
    pass

_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
_EVENT = re.compile(r"[A-Za-z0-9_.:-]{1,150}\Z")
_KINDS = frozenset(("TASK_CREATED", "PROJECT_CREATED"))
_MODES = frozenset(("MANUAL", "SEMI_AUTOMATIC", "AUTOMATIC"))
_PROFILES = frozenset(("web", "telegram", "crm", "analysis", "general"))

def _reject_duplicates(pairs):
    value = {}
    for k,v in pairs:
        if k in value:
            raise IntakeRejected("duplicate JSON key")
        value[k]=v
    return value

def _json(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 32768:
        raise IntakeRejected("invalid signed payload length")
    try:
        x=json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates,
                     parse_constant=lambda v: (_ for _ in ()).throw(IntakeRejected("nonfinite JSON")))
    except (ValueError, UnicodeError, RecursionError) as e:
        raise IntakeRejected("malformed event JSON") from e
    if type(x) is not dict:
        raise IntakeRejected("event JSON must be an object")
    return x

def _str(v, pattern):
    return type(v) is str and pattern.fullmatch(v) is not None

def _text(v, *, limit=240):
    if type(v) is not str or not 1 <= len(v.encode("utf-8")) <= limit or any(ord(c)<32 or ord(c)==127 for c in v):
        raise IntakeRejected("unsafe event text")
    return v

def _signature(source, raw, headers, secrets):
    if (type(headers) is not dict or type(secrets) is not dict or
        source not in secrets or type(secrets[source]) is not bytes or
        not 32 <= len(secrets[source]) <= 4096):
        raise IntakeRejected("missing externally managed webhook secret")
    key = "X-Hub-Signature-256" if source=="github_issues" else "X-NF-Signature-256"
    value=headers.get(key)
    if type(value) is not str or not value.startswith("sha256=") or not _SHA64.fullmatch(value[7:]):
        raise IntakeRejected("missing HMAC-SHA256 authentication")
    expected=hmac.new(secrets[source],raw,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(value[7:],expected):
        raise IntakeRejected("invalid signed event")

def _parse(source, body, headers):
    if source=="github_issues":
        delivery=headers.get("X-GitHub-Delivery")
        try:
            if type(delivery) is not str or str(uuid.UUID(delivery)) != delivery.lower():
                raise ValueError()
        except ValueError as e:
            raise IntakeRejected("invalid GitHub delivery ID") from e
        if headers.get("X-GitHub-Event")!="issues" or body.get("action")!="opened":
            raise IntakeRejected("unsupported GitHub event")
        repo=body.get("repository")
        issue=body.get("issue")
        if type(repo) is not dict or type(issue) is not dict:
            raise IntakeRejected("missing issue/repository")
        full=repo.get("full_name")
        number=issue.get("number")
        if not _str(full,_REPO) or type(number) is not int or not 1 <= number <= 2147483647:
            raise IntakeRejected("invalid issue identity")
        if issue.get("state")!="open":
            raise IntakeRejected("issue is not open")
        title=_text(issue.get("title"))
        return {"repo":full,"event_id":f"github-issue:{full}:{number}",
                "delivery":f"github:{delivery}","kind":"TASK_CREATED",
                "description":title}
    if source not in ("authorized_api", "signed_import"):
        raise IntakeRejected("unsupported source")
    if set(body)!={"schema","event_id","kind","repository","project_id","description"} or (
        body["schema"]!="neurofactory.intake.event.v1" or
        not _str(body["event_id"],_EVENT) or body["kind"] not in _KINDS or
        not _str(body["repository"],_REPO) or not _str(body["project_id"],_PROJECT)):
        raise IntakeRejected("invalid signed event fields")
    description=_text(body["description"])
    delivery=headers.get("X-NF-Delivery")
    if not _str(delivery,_EVENT):
        raise IntakeRejected("missing delivery identifier")
    return {"repo":body["repository"],"event_id":f"{source}:{body['event_id']}",
            "delivery":f"{source}:{delivery}","kind":body["kind"],
            "description":description,"project_id":body["project_id"]}

def _registry(repo, registry, source, project_id=None):
    if type(registry) is not dict:
        raise IntakeRejected("missing administrative project registry")
    entry=registry.get(repo)
    if entry is None:
        return None
    if (type(entry) is not dict or set(entry)!={"project_id","owner_id","mode","profile","sources","preapproved"} or
        not _str(entry["project_id"],_PROJECT) or
        not _str(entry["owner_id"],_EVENT) or
        entry["mode"] not in _MODES or entry["profile"] not in _PROFILES or
        type(entry["sources"]) not in (tuple,list) or
        not all(type(v) is str and v in ("github_issues","authorized_api","signed_import") for v in entry["sources"]) or
        type(entry["preapproved"]) is not bool):
        raise IntakeRejected("invalid administrative project record")
    if source not in entry["sources"] or (project_id is not None and project_id != entry["project_id"]):
        raise IntakeRejected("event outside registered source/project scope")
    return entry

def init_advisory_store(conn):
    if not isinstance(conn,sqlite3.Connection):
        raise IntakeRejected("requires local advisory SQLite connection")
    conn.execute("""CREATE TABLE IF NOT EXISTS nf_coord_intake_v1 (
        event_key TEXT PRIMARY KEY,
        delivery_key TEXT UNIQUE NOT NULL,
        payload_sha256 TEXT NOT NULL,
        source TEXT NOT NULL,
        repository TEXT NOT NULL,
        project_id TEXT,
        kind TEXT NOT NULL,
        mode TEXT NOT NULL,
        profile TEXT NOT NULL,
        advisory_status TEXT NOT NULL,
        description TEXT NOT NULL,
        inserted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )""")

def ingest_signed_event(conn, *, source, raw, headers, secrets, project_registry):
    """Only registers an advisory event. Even automatic mode NEVER dispatches."""
    if source not in ("github_issues","authorized_api","signed_import"):
        raise IntakeRejected("unrecognized source")
    _signature(source,raw,headers,secrets)
    body=_json(raw)
    record=_parse(source,body,headers)
    entry=_registry(record["repo"],project_registry,source,record.get("project_id"))
    digest=hashlib.sha256(raw).hexdigest()
    if entry is None:
        status="PENDING_OWNER_APPROVAL"
        project_id=None
        mode="MANUAL"
        profile="general"
    else:
        project_id=entry["project_id"]
        mode=entry["mode"]
        profile=entry["profile"]
        status=("ADVISORY_READY_NO_EXECUTION" if entry["preapproved"]
                else "PENDING_OWNER_APPROVAL")
    init_advisory_store(conn)
    try:
        conn.execute("BEGIN IMMEDIATE")
        old=conn.execute("""SELECT delivery_key,payload_sha256 FROM nf_coord_intake_v1
                            WHERE event_key=?""",(record["event_id"],)).fetchone()
        if old is not None:
            if old!=(record["delivery"],digest):
                raise IntakeRejected("conflicting duplicate task or redelivery")
            conn.execute("COMMIT")
            return {"result":"DUPLICATE","event_key":record["event_id"],
                    "advisory_only":True,"execution_allowed":False}
        collision=conn.execute("""SELECT 1 FROM nf_coord_intake_v1
                                  WHERE delivery_key=?""",(record["delivery"],)).fetchone()
        if collision:
            raise IntakeRejected("delivery identifier reused for another event")
        conn.execute("""INSERT INTO nf_coord_intake_v1
            (event_key,delivery_key,payload_sha256,source,repository,project_id,
             kind,mode,profile,advisory_status,description)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (record["event_id"],record["delivery"],digest,source,record["repo"],
             project_id,record["kind"],mode,profile,status,record["description"]))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    return {"result":"REGISTERED","event_key":record["event_id"],
            "advisory_status":status,"project_id":project_id,"profile":profile,
            "mode":mode,"advisory_only":True,"execution_allowed":False,
            "queue_write_allowed":False,"paid_api_allowed":False,
            "publication_allowed":False,"handoff":"PAUSED_BY_USER"}
