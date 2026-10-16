"""Explicitly started 127.0.0.1-only offline webhook gateway for advisory intake.

This is NOT a deployed listener, queue, HTTPS ingress, signer or publisher.
Only call start_local_gateway() in an explicitly authorized disposable workspace.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import os
import sqlite3
import stat

from offline_autointake import IntakeRejected, ingest_signed_event

_PATHS={
    "/intake/github/issues":"github_issues",
    "/intake/api/tasks":"authorized_api",
    "/intake/import":"signed_import",
}
_HEADERS=("X-Hub-Signature-256","X-NF-Signature-256",
          "X-GitHub-Event","X-GitHub-Delivery","X-NF-Delivery")

def start_local_gateway(*, db_path, secrets, project_registry):
    """Return unstarted-by-default local server; caller owns lifecycle/cleanup.

    HTTPS and trusted proxy authentication are NOT provided: do not expose
    beyond loopback or treat advisory registration as task execution approval.
    """
    p=Path(db_path)
    if not p.parent.is_dir() or p.is_symlink():
        raise IntakeRejected("missing protected advisory database directory")
    parent=p.parent.stat()
    if os.name=="posix" and (parent.st_mode & 0o077 or not stat.S_ISDIR(parent.st_mode)):
        raise IntakeRejected("local gateway needs private 0700 parent")
    if p.exists():
        s=p.lstat()
        if not stat.S_ISREG(s.st_mode) or (os.name=="posix" and s.st_mode & 0o077):
            raise IntakeRejected("existing advisory database is not private")
    else:
        flags=os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os,"O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd=os.open(p,flags,0o600)
        os.close(fd)
    if (type(secrets) is not dict or type(project_registry) is not dict or
        not secrets or any(type(v) is not bytes or len(v)<32 for v in secrets.values())):
        raise IntakeRejected("administrative signing config required")

    class Handler(BaseHTTPRequestHandler):
        server_version="NFIntakeOffline/1"
        sys_version=""
        def log_message(self, format, *args):
            # Do not leak signature headers or attacker-supplied event bodies.
            return
        def _response(self,status,body):
            encoded=json.dumps(body,separators=(",",":"),ensure_ascii=True).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(encoded)))
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.end_headers()
            self.wfile.write(encoded)
        def do_POST(self):
            source=_PATHS.get(self.path)
            if source is None:
                self._response(404,{"result":"NOT_FOUND"})
                return
            if (self.headers.get("Transfer-Encoding") is not None or
                self.headers.get("Content-Type")!="application/json"):
                self._response(415,{"result":"REJECTED"})
                return
            raw_length=self.headers.get("Content-Length")
            if type(raw_length) is not str or not raw_length.isascii() or not raw_length.isdigit():
                self._response(400,{"result":"REJECTED"})
                return
            length=int(raw_length)
            if not 1 <= length <= 32768:
                self._response(413,{"result":"REJECTED"})
                return
            header={}
            for key in _HEADERS:
                values=self.headers.get_all(key,[])
                if len(values)>1:
                    self._response(400,{"result":"REJECTED"})
                    return
                if values:
                    header[key]=values[0]
            try:
                data=self.rfile.read(length)
                if len(data)!=length:
                    raise IntakeRejected("incomplete body")
                with sqlite3.connect(str(p),timeout=4,isolation_level=None) as con:
                    r=ingest_signed_event(con,source=source,raw=data,headers=header,
                              secrets=secrets,project_registry=project_registry)
                self._response(202 if r["result"]=="REGISTERED" else 200,r)
            except (IntakeRejected,sqlite3.Error,UnicodeError):
                self._response(403,{"result":"REJECTED","execution_allowed":False})
        def do_GET(self):
            self._response(405,{"result":"NOT_ALLOWED"})
        def do_OPTIONS(self):
            self._response(405,{"result":"NOT_ALLOWED"})

    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    server.daemon_threads=True
    return server
