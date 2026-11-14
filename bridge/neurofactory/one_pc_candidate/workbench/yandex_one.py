"""Owner-consented, read-only Yandex Metrica and Webmaster integration.

Manual OAuth tokens are stored only in the existing Windows-user DPAPI vault.
This adapter cannot create a goal, alter Webmaster, or operate Yandex Direct.
"""
from __future__ import annotations

from datetime import date, timedelta
import re
from urllib.parse import quote

from service_one import SafeServiceTransport
from work_core import WorkDenied

YANDEX_SCOPES = frozenset(("metrika.readonly", "webmaster.readonly"))
COUNTER_ID_RE = re.compile(r"^[1-9][0-9]{0,17}$")
MAX_HOSTS = 100


class YandexConnection:
    def __init__(self, vault):
        self.vault = vault

    def capabilities(self):
        connected = []
        if self.vault.ready():
            for scope in sorted(YANDEX_SCOPES):
                record = self.vault.get("yandex", scope)
                if record and isinstance(record.get("access_token"), str):
                    connected.append(scope)
        return {"configured":self.vault.ready(),
                "connected_scopes":connected,
                "grant_scopes":sorted(YANDEX_SCOPES),
                "requires_separate_yandex_oauth_consent":True}

    def connect(self, scope, access_token):
        if scope not in YANDEX_SCOPES:
            raise WorkDenied("YANDEX_SCOPE_REFUSED")
        if (type(access_token) is not str or not 20 <= len(access_token) <= 4096 or
                any(ord(c)<33 or ord(c)==127 for c in access_token)):
            raise WorkDenied("YANDEX_TOKEN_INVALID")
        self.vault.put("yandex", scope, {"access_token":access_token,
                                       "scope":scope})
        return {"connected":True, "scope":scope}

    def disconnect(self, scope):
        if scope not in YANDEX_SCOPES:
            raise WorkDenied("YANDEX_SCOPE_REFUSED")
        self.vault.delete("yandex",scope)
        return {"connected":False,"scope":scope,
                "remote_access_revoke_required":True}

    def token(self, provider, scope):
        if provider!="yandex" or scope not in YANDEX_SCOPES:
            return None
        record=self.vault.get("yandex",scope)
        if not record or record.get("scope")!=scope:
            return None
        return record.get("access_token")


class YandexReadOnlyAdapter:
    HOSTS=frozenset(("api-metrika.yandex.net",
                     "api.webmaster.yandex.net"))

    def __init__(self, token_loader, transport=None):
        self.load=token_loader
        self.transport=transport or SafeServiceTransport(self.HOSTS)

    def _call(self, host, path, scope, query=None):
        token=self.load("yandex",scope)
        if not token:
            raise WorkDenied("YANDEX_NOT_CONNECTED_OR_SCOPE_MISSING")
        return self.transport.call(host,"GET",path,token,query=query,
                                   auth_style="yandex")

    def metrika_counters(self):
        reply=self._call("api-metrika.yandex.net","/management/v1/counters",
                         "metrika.readonly",query={"per_page":50})
        counters=reply.get("counters")
        if type(counters) is not list or len(counters)>50:
            raise WorkDenied("YANDEX_METRIKA_RESPONSE_INVALID")
        cleaned=[]
        for item in counters:
            if type(item) is not dict or type(item.get("id")) is not int:
                raise WorkDenied("YANDEX_METRIKA_RESPONSE_INVALID")
            cleaned.append({"id":item["id"],
                            "name":str(item.get("name",""))[:160],
                            "site":str(item.get("site",""))[:240],
                            "permission":str(item.get("permission",""))[:32]})
        return {"counters":cleaned,"bounded":True}

    def metrika_visits(self, counter_id):
        if type(counter_id) is not str or not COUNTER_ID_RE.fullmatch(counter_id):
            raise WorkDenied("YANDEX_METRIKA_COUNTER_INVALID")
        allowed={str(x["id"]) for x in self.metrika_counters()["counters"]}
        if counter_id not in allowed:
            raise WorkDenied("YANDEX_METRIKA_COUNTER_NOT_AUTHORIZED")
        date2=date.today()-timedelta(days=1)
        date1=date2-timedelta(days=27)
        reply=self._call("api-metrika.yandex.net","/stat/v1/data",
                         "metrika.readonly",query={
                             "ids":counter_id,"metrics":"ym:s:visits,ym:s:users,ym:s:pageviews",
                             "date1":date1.isoformat(),"date2":date2.isoformat()})
        totals=reply.get("totals")
        if type(totals) is not list or len(totals)!=3 or any(
                type(n) not in (int,float) or n<0 for n in totals):
            raise WorkDenied("YANDEX_METRIKA_STAT_INVALID")
        return {"counter_id":counter_id,"date1":date1.isoformat(),
                "date2":date2.isoformat(),
                "visits":totals[0],"users":totals[1],"pageviews":totals[2]}

    def _webmaster_user(self):
        reply=self._call("api.webmaster.yandex.net","/v4/user",
                         "webmaster.readonly")
        user=reply.get("user_id")
        if type(user) is not int or not 1<=user<2**63:
            raise WorkDenied("YANDEX_WEBMASTER_USER_INVALID")
        return user

    def webmaster_hosts(self):
        uid=self._webmaster_user()
        reply=self._call("api.webmaster.yandex.net",
                         "/v4/user/"+str(uid)+"/hosts","webmaster.readonly")
        hosts=reply.get("hosts")
        if type(hosts) is not list or len(hosts)>MAX_HOSTS:
            raise WorkDenied("YANDEX_WEBMASTER_HOSTS_INVALID")
        cleaned=[]
        for item in hosts:
            if type(item) is not dict or type(item.get("host_id")) is not str:
                raise WorkDenied("YANDEX_WEBMASTER_HOSTS_INVALID")
            cleaned.append({"host_id":item["host_id"],
                            "url":str(item.get("ascii_host_url",""))[:240],
                            "verified":item.get("verified") is True})
        return {"hosts":cleaned}

    def webmaster_summary(self, host_id):
        if type(host_id) is not str or not 1<=len(host_id)<=240:
            raise WorkDenied("YANDEX_WEBMASTER_HOST_ID_INVALID")
        uid=self._webmaster_user()
        permitted=self.webmaster_hosts()["hosts"]
        if not any(h["host_id"]==host_id and h["verified"] for h in permitted):
            raise WorkDenied("YANDEX_WEBMASTER_HOST_NOT_AUTHORIZED")
        reply=self._call("api.webmaster.yandex.net",
                         "/v4/user/"+str(uid)+"/hosts/"+
                         quote(host_id,safe="")+"/summary",
                         "webmaster.readonly")
        return {"host_id":host_id,
                "sqi":reply.get("sqi"),
                "excluded_pages_count":reply.get("excluded_pages_count"),
                "searchable_pages_count":reply.get("searchable_pages_count"),
                "site_problems":reply.get("site_problems",{})}
