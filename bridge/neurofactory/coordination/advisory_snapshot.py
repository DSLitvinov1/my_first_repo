"""Strict, bounded read-only projection for existing Neurofactory UI backend.

Untrusted caller-provided allowed_repositories is merely a VIEW FILTER.
It is NOT owner authorization. No edit, retry, merge, job dispatch or API use.
"""
import re
import sqlite3

class AdvisorySnapshotError(ValueError):
    pass

_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{2,39}\Z")
_ALLOWED_STATE = frozenset(("PENDING_OWNER_APPROVAL", "ADVISORY_READY_NO_EXECUTION"))
_ALLOWED_MODE = frozenset(("MANUAL", "SEMI_AUTOMATIC", "AUTOMATIC"))
_ALLOWED_PROFILE = frozenset(("web", "telegram", "crm", "analysis", "general"))
_ALLOWED_KIND = frozenset(("TASK_CREATED", "PROJECT_CREATED"))

def preview_advisory_cards(conn, *, allowed_repositories, limit=20,
                           before_rowid=None, project_id=None):
    """No implicit cross-repository wildcard. Cursor expires after DB migration."""
    if not isinstance(conn, sqlite3.Connection):
        raise AdvisorySnapshotError("SQLite advisory read connection required")
    if (type(limit) is not int or not 1 <= limit <= 50 or
        (before_rowid is not None and
         (type(before_rowid) is not int or not 1 <= before_rowid < 2**63)) or
        (project_id is not None and
         (type(project_id) is not str or _PROJECT.fullmatch(project_id) is None))):
        raise AdvisorySnapshotError("invalid bounded UI filter")
    if (type(allowed_repositories) not in (list, tuple) or
        not 1 <= len(allowed_repositories) <= 50 or
        not all(type(x) is str and _REPO.fullmatch(x) is not None
                for x in allowed_repositories) or
        len(set(allowed_repositories)) != len(allowed_repositories)):
        raise AdvisorySnapshotError("explicit nonempty repository view scope required")

    placeholders=",".join("?" for _ in allowed_repositories)
    where=["repository IN ("+placeholders+")"]
    params=list(allowed_repositories)
    if project_id is not None:
        where.append("project_id = ?")
        params.append(project_id)
    if before_rowid is not None:
        where.append("rowid < ?")
        params.append(before_rowid)
    sql=("SELECT rowid, event_key, repository, project_id, kind, mode, profile,"
         " advisory_status, description, inserted_at"
         " FROM nf_coord_intake_v1 WHERE "+" AND ".join(where)+
         " ORDER BY rowid DESC LIMIT ?")
    params.append(limit+1)
    try:
        rows=conn.execute(sql,params).fetchall()
    except sqlite3.Error as e:
        raise AdvisorySnapshotError("advisory store unavailable") from e
    cards=[]
    for row in rows[:limit]:
        rowid,event_key,repo,project,kind,mode,profile,status,description,created=row
        if (type(rowid) is not int or rowid <= 0 or
            type(repo) is not str or repo not in allowed_repositories or
            type(event_key) is not str or not 1 <= len(event_key) <= 300 or
            (project is not None and
             (type(project) is not str or _PROJECT.fullmatch(project) is None)) or
            kind not in _ALLOWED_KIND or mode not in _ALLOWED_MODE or
            profile not in _ALLOWED_PROFILE or status not in _ALLOWED_STATE or
            type(description) is not str or not 1 <= len(description.encode("utf-8")) <= 240 or
            any(ord(x)<32 or ord(x)==127 for x in description) or
            type(created) is not str or not 10 <= len(created) <= 40):
            raise AdvisorySnapshotError("corrupted advisory projection: STOP")
        cards.append({
            "event_key":event_key, "repository":repo, "project_id":project,
            "kind":kind, "mode":mode, "profile":profile,
            "advisory_status":status, "description":description,
            "created_at":created,
            "authentic_owner_approval_verified":False,
            "execution_allowed":False,
            "queue_write_allowed":False,
            "publication_allowed":False,
            "paid_api_allowed":False,
        })
    return {
        "schema":"neurofactory.coordination.advisory_cards.v1",
        "kind":"READ_ONLY_UNVERIFIED_UI_DATA",
        "cards":cards,
        "has_more":len(rows)>limit,
        "next_before_rowid":rows[limit-1][0] if len(rows)>limit else None,
        "live_execution_allowed":False,
        "approval_from_snapshot_allowed":False,
        "queue_write_allowed":False,
        "handoff":"PAUSED_BY_USER",
    }
