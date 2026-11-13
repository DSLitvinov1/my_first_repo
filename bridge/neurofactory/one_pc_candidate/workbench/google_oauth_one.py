"""Work ONE Google Desktop OAuth 2.0 (PKCE + random loopback listener).

Requires a Google Cloud OAuth "Desktop app" CLIENT ID configured explicitly by
the owner. Never opens account browsers automatically. Credentials are stored
using Windows DPAPI, not in Git/SQLite/console/HTTP response payloads.
"""
from __future__ import annotations

import base64
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import secrets
import threading
import time
from urllib.parse import urlencode, parse_qs, urlsplit

from agent_one import public_dns, PinnedHTTPSConnection
from work_core import WorkDenied
from credentials_one import UserVault

GOOGLE_HOST = "oauth2.googleapis.com"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
SCOPE_VALUES = {
    "tasks":"https://www.googleapis.com/auth/tasks",
    "drive.metadata.readonly":
        "https://www.googleapis.com/auth/drive.metadata.readonly",
    "gmail.readonly":"https://www.googleapis.com/auth/gmail.readonly",
    "calendar.readonly":"https://www.googleapis.com/auth/calendar.readonly",
}
CLIENT_RE=re.compile(r"^[0-9A-Za-z_.-]{6,190}\.apps\.googleusercontent\.com$")
TIMEOUT=180


def _urlencoded_token(form):
    payload=urlencode(form).encode("utf-8")
    host=GOOGLE_HOST
    public=public_dns(host)
    conn=PinnedHTTPSConnection(host,public)
    try:
        conn.request("POST","/token",body=payload,headers={
            "Content-Type":"application/x-www-form-urlencoded",
            "Accept":"application/json",
            "User-Agent":"NeirozavodWorkOne/0.6"})
        result=conn.getresponse()
        if result.status!=200 or result.headers.get_content_type()!="application/json":
            raise WorkDenied("GOOGLE_OAUTH_EXCHANGE_REFUSED")
        data=result.read(16001)
        if len(data)>16000:
            raise WorkDenied("GOOGLE_OAUTH_RESPONSE_TOO_LARGE")
        reply=json.loads(data.decode("utf8"))
        if not isinstance(reply,dict):
            raise WorkDenied("GOOGLE_OAUTH_BAD_RESPONSE")
        return reply
    except WorkDenied:
        raise
    except (OSError,ValueError,TimeoutError,UnicodeError):
        raise WorkDenied("GOOGLE_OAUTH_NETWORK_UNKNOWN")
    finally:
        conn.close()


class GoogleOAuthOne:
    def __init__(self, vault=None, client_id=None, client_secret=None,
                 exchanger=None):
        self.vault=vault or UserVault()
        self.client_id=client_id or ""
        self.client_secret=client_secret or ""
        if self.client_id and not CLIENT_RE.fullmatch(self.client_id):
            raise WorkDenied("GOOGLE_CLIENT_ID_INVALID")
        self.exchanger=exchanger or _urlencoded_token
        self.lock=threading.RLock()
        self.flow=None
        self.listener=None
        self.last_result={"state":"NOT_CONNECTED"}

    def capabilities(self):
        scopes=[]
        if self.vault.ready():
            for scope in SCOPE_VALUES:
                item=self.vault.get("google",scope)
                if item and item.get("scope")==SCOPE_VALUES[scope] and (
                    item.get("access_token") or item.get("refresh_token")):
                    scopes.append(scope)
        return {
            "configured":bool(self.client_id and self.vault.ready()),
            "grant_scopes":sorted(SCOPE_VALUES),
            "connected_scopes":scopes,
            "state":self.last_result["state"],
            "requires_user_consent":True,
        }

    def _exchange(self, form):
        if self.client_secret:
            form["client_secret"]=self.client_secret
        return self.exchanger(form)

    def begin(self, scope):
        if scope not in SCOPE_VALUES:
            raise WorkDenied("GOOGLE_OAUTH_SCOPE_REFUSED")
        if not self.client_id or not self.vault.ready():
            raise WorkDenied("GOOGLE_OAUTH_DESKTOP_CLIENT_NOT_CONFIGURED")
        with self.lock:
            if self.flow:
                raise WorkDenied("GOOGLE_OAUTH_ALREADY_PENDING")
            state=secrets.token_urlsafe(36)
            verifier=secrets.token_urlsafe(64)[:120]
            challenge=base64.urlsafe_b64encode(
                sha256(verifier.encode("ascii")).digest()
                ).decode("ascii").rstrip("=")
            parent=self
            class Callback(BaseHTTPRequestHandler):
                def do_GET(self):
                    url=urlsplit(self.path)
                    if url.path!="/oauth2/callback":
                        self.send_error(404)
                        return
                    q=parse_qs(url.query)
                    with parent.lock:
                        flow=parent.flow
                        matched=flow and len(q.get("state",[]))==1 and (
                            secrets.compare_digest(q["state"][0],flow["state"]))
                        if not matched or time.monotonic()-flow["created"]>TIMEOUT:
                            parent.last_result={"state":"REJECTED"}
                            self.send_error(400)
                            return
                        if q.get("error"):
                            parent.last_result={"state":"DENIED"}
                            parent.flow=None
                            body="Доступ не предоставлен. Можно закрыть эту вкладку."
                        elif len(q.get("code",[]))!=1:
                            parent.last_result={"state":"INVALID"}
                            parent.flow=None
                            self.send_error(400)
                            return
                        else:
                            body="Подтверждение принято. Вернитесь в Нейрозавод ONE."
                            parent.last_result={"state":"EXCHANGING"}
                            code=q["code"][0]
                            threading.Thread(target=parent._complete,
                                args=(flow,code),daemon=True,
                                name="one-google-oauth-complete").start()
                    raw=body.encode("utf8")
                    self.send_response(200)
                    self.send_header("Content-Type","text/plain; charset=utf-8")
                    self.send_header("Cache-Control","no-store")
                    self.send_header("Content-Length",str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                def log_message(self,*args):
                    pass

            listener=ThreadingHTTPServer(("127.0.0.1",0),Callback)
            listener.timeout=1.0
            port=listener.server_address[1]
            redirect=f"http://127.0.0.1:{port}/oauth2/callback"
            self.listener=listener
            self.flow={
                "state":state, "verifier":verifier, "redirect":redirect,
                "scope":scope, "created":time.monotonic(),
            }
            self.last_result={"state":"AWAITING_USER_CONSENT","scope":scope}
            def serve():
                deadline=time.monotonic()+TIMEOUT
                while self.flow and time.monotonic()<deadline:
                    listener.handle_request()
                if self.flow and time.monotonic()>=deadline:
                    with self.lock:
                        self.flow=None
                        self.last_result={"state":"EXPIRED"}
                listener.server_close()
            threading.Thread(target=serve,daemon=True,
                             name="one-google-oauth-listener").start()
            auth=AUTH_URL+"?"+urlencode({
                "client_id":self.client_id,
                "redirect_uri":redirect,
                "response_type":"code",
                "scope":SCOPE_VALUES[scope],
                "access_type":"offline",
                "prompt":"consent",
                "code_challenge":challenge,
                "code_challenge_method":"S256",
                "state":state,
            })
            return {"authorization_url":auth,
                    "scope":scope, "expires_seconds":TIMEOUT}

    def _complete(self, flow, code):
        try:
            reply=self._exchange({
                "client_id":self.client_id,
                "code":code, "code_verifier":flow["verifier"],
                "grant_type":"authorization_code",
                "redirect_uri":flow["redirect"],
            })
            access=reply.get("access_token")
            if (not isinstance(access,str) or not 8 <= len(access) <= 4096
                    or reply.get("token_type","Bearer").lower()!="bearer"):
                raise WorkDenied("GOOGLE_OAUTH_TOKEN_INVALID")
            expires=int(reply.get("expires_in",3600))
            if not 60<=expires<=86400:
                raise WorkDenied("GOOGLE_OAUTH_TTL_INVALID")
            refresh=reply.get("refresh_token")
            if refresh and (not isinstance(refresh,str) or len(refresh)>4096):
                raise WorkDenied("GOOGLE_OAUTH_REFRESH_INVALID")
            self.vault.put("google",flow["scope"],{
                "access_token":access,"refresh_token":refresh,
                "expires_at":time.time()+expires,
                "scope":SCOPE_VALUES[flow["scope"]],
            })
            outcome={"state":"CONNECTED","scope":flow["scope"]}
        except Exception:
            outcome={"state":"UNKNOWN_REQUIRES_RECONNECT"}
        with self.lock:
            self.last_result=outcome
            if self.flow and self.flow["state"]==flow["state"]:
                self.flow=None

    def token(self, provider, scope):
        if provider!="google" or scope not in SCOPE_VALUES:
            return None
        item=self.vault.get("google",scope)
        if not item:
            return None
        if item.get("scope")!=SCOPE_VALUES[scope]:
            return None
        if time.time()+70 < float(item.get("expires_at",0)):
            return item.get("access_token")
        refresh=item.get("refresh_token")
        if not refresh or not self.client_id:
            return None
        with self.lock:
            again=self.vault.get("google",scope)
            if time.time()+70 < float(again.get("expires_at",0)):
                return again.get("access_token")
            try:
                result=self._exchange({
                    "client_id":self.client_id,
                    "refresh_token":refresh,
                    "grant_type":"refresh_token",
                })
                access=result.get("access_token")
                ttl=int(result.get("expires_in",3600))
                if not isinstance(access,str) or not 8<=len(access)<=4096:
                    raise WorkDenied("GOOGLE_REFRESH_TOKEN_INVALID")
                self.vault.put("google",scope,{**item,"access_token":access,
                    "expires_at":time.time()+ttl})
                return access
            except Exception:
                return None

    def revoke_local(self, scope):
        if scope not in SCOPE_VALUES:
            raise WorkDenied("GOOGLE_SCOPE_INVALID")
        self.vault.delete("google",scope)
        return {"scope":scope,"local_credentials_removed":True,
                "remote_access_revoke_required":True}


class BitrixConnection:
    def __init__(self, vault):
        self.vault=vault

    def connect(self, portal, access_token):
        from service_one import PORTAL_RE
        if not isinstance(portal,str) or not PORTAL_RE.fullmatch(portal):
            raise WorkDenied("BITRIX_PORTAL_INVALID")
        if (not isinstance(access_token,str)
                or not 20<=len(access_token)<=4096
                or any(ord(x)<33 for x in access_token)):
            raise WorkDenied("BITRIX_TOKEN_INVALID")
        self.vault.put("bitrix24","task",{
            "portal":portal, "access_token":access_token})
        return {"connected":True,"portal":portal}

    def token(self, provider, scope):
        if provider!="bitrix24" or scope not in ("task","crm"):
            return None
        record=self.vault.get("bitrix24",scope)
        return record.get("access_token") if record else None

    def connect_crm(self, portal, access_token):
        from service_one import PORTAL_RE
        if not isinstance(portal,str) or not PORTAL_RE.fullmatch(portal):
            raise WorkDenied("BITRIX_PORTAL_INVALID")
        existing=self.portal()
        if existing and existing!=portal:
            raise WorkDenied("BITRIX_CRM_PORTAL_MISMATCH")
        if (not isinstance(access_token,str) or
                not 20<=len(access_token)<=4096 or
                any(ord(x)<33 for x in access_token)):
            raise WorkDenied("BITRIX_TOKEN_INVALID")
        self.vault.put("bitrix24","crm",{
            "portal":portal,"access_token":access_token})
        return {"connected":True,"portal":portal,"scope":"crm"}

    def token_crm(self):
        item=self.vault.get("bitrix24","crm")
        return item.get("access_token") if item else None

    def portal(self):
        record=self.vault.get("bitrix24","task")
        return record.get("portal") if record else None

    def disconnect_local(self):
        self.vault.delete("bitrix24","task")
        self.vault.delete("bitrix24","crm")
        return {"local_credentials_removed":True}
