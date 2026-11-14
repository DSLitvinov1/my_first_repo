"""Yandex read-only integration: fixed endpoints, owner grant, no ad changes."""
from datetime import date
from pathlib import Path
import tempfile
import unittest

from service_one import ServiceOne, SafeServiceTransport
from work_core import WorkDenied, WorkStore
from yandex_one import YandexConnection, YandexReadOnlyAdapter


class FakeVault:
    def __init__(self):
        self.entries={}
    def ready(self):return True
    def get(self,provider,scope):return self.entries.get((provider,scope))
    def put(self,provider,scope,entry):self.entries[(provider,scope)]=dict(entry)
    def delete(self,provider,scope):self.entries.pop((provider,scope),None)


class FakeYandexTransport:
    def __init__(self):
        self.calls=[]
    def call(self,host,method,path,token,payload=None,query=None,
             auth_style="bearer"):
        assert auth_style=="yandex", auth_style
        assert token=="synthetic-token-readonly-owner", token
        self.calls.append((host,method,path,query))
        if host=="api-metrika.yandex.net":
            if path=="/management/v1/counters":
                return {"counters":[{"id":111,"name":"Сайт A",
                                     "site":"example.org","permission":"own"}]}
            if path=="/stat/v1/data":
                return {"totals":[42,35,61]}
        if host=="api.webmaster.yandex.net":
            if path=="/v4/user":
                return {"user_id":77}
            if path=="/v4/user/77/hosts":
                return {"hosts":[{"host_id":"https:example.org:443",
                                  "ascii_host_url":"https://example.org/",
                                  "verified":True},
                                 {"host_id":"https:other.org:443",
                                  "ascii_host_url":"https://other.org/",
                                  "verified":False}]}
            if path=="/v4/user/77/hosts/https%3Aexample.org%3A443/summary":
                return {"sqi":90,"excluded_pages_count":12,
                        "searchable_pages_count":120,"site_problems":{}}
        raise AssertionError("unexpected API path: "+path)


class YandexReadOnlyTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.store=WorkStore(root/"projects",root/"data")
        self.project=self.store.create_project("Яндекс SEO","empty")["id"]
        self.vault=FakeVault()
        self.conn=YandexConnection(self.vault)
        self.fake=FakeYandexTransport()
        self.adapter=YandexReadOnlyAdapter(self.conn.token,transport=self.fake)
        self.svc=ServiceOne(self.store,{"yandex.read":self.adapter})

    def test_owner_tokens_scoped_and_never_returned(self):
        with self.assertRaises(WorkDenied):
            self.conn.connect("direct.write","synthetic-token-readonly-owner")
        with self.assertRaises(WorkDenied):
            self.conn.connect("metrika.readonly","short")
        self.conn.connect("metrika.readonly","synthetic-token-readonly-owner")
        self.assertEqual(self.conn.capabilities()["connected_scopes"],["metrika.readonly"])
        self.assertNotIn("access_token",repr(self.conn.capabilities()))
        self.assertEqual(self.conn.token("yandex","webmaster.readonly"),None)
        self.assertEqual(self.conn.token("google","metrika.readonly"),None)
        self.conn.disconnect("metrika.readonly")
        self.assertEqual(self.conn.capabilities()["connected_scopes"],[])

    def test_metrika_scoped_counter_and_bounded_28day_visits(self):
        self.conn.connect("metrika.readonly","synthetic-token-readonly-owner")
        items=self.svc.read(self.project,"yandex.metrika.counters.list",{})["data"]
        self.assertEqual(items["counters"][0]["id"],111)
        report=self.svc.read(self.project,"yandex.metrika.visits",
                             {"counter_id":"111"})["data"]
        self.assertEqual(report["visits"],42)
        self.assertEqual(report["users"],35)
        self.assertEqual((date.fromisoformat(report["date2"])-
                          date.fromisoformat(report["date1"])).days,27)
        self.assertEqual(self.fake.calls[-1][1],"GET")
        self.assertEqual(self.fake.calls[-1][2],"/stat/v1/data")
        for bad in ("112","../1","0","111?payload","111\n"):
            prior=len(self.fake.calls)
            with self.subTest(bad=bad),self.assertRaises(WorkDenied):
                self.svc.read(self.project,"yandex.metrika.visits",
                              {"counter_id":bad})
            self.assertFalse(any(x[2]=="/stat/v1/data" for x in self.fake.calls[prior:]))

    def test_webmaster_owns_verified_host_only(self):
        self.conn.connect("webmaster.readonly","synthetic-token-readonly-owner")
        hosts=self.svc.read(self.project,"yandex.webmaster.hosts.list",{})["data"]
        self.assertEqual(len(hosts["hosts"]),2)
        result=self.svc.read(self.project,"yandex.webmaster.summary",
                             {"host_id":"https:example.org:443"})["data"]
        self.assertEqual(result["searchable_pages_count"],120)
        self.assertEqual(self.fake.calls[-1][1],"GET")
        for invalid in ("https:other.org:443","https:stranger.org:443","../foo", ""):
            before=len(self.fake.calls)
            with self.subTest(host=invalid),self.assertRaises(WorkDenied):
                self.svc.read(self.project,"yandex.webmaster.summary",
                              {"host_id":invalid})
            self.assertFalse(any(c[2].endswith("/summary")
                                  for c in self.fake.calls[before:]))

    def test_no_secret_or_user_account_data_in_logs(self):
        self.conn.connect("metrika.readonly","synthetic-token-readonly-owner")
        self.svc.read(self.project,"yandex.metrika.counters.list",{})
        content=" ".join(evt["detail"] for evt in self.store.events())
        self.assertNotIn("synthetic-token-readonly-owner",content)
        self.assertNotIn("Сайт A",content)
        with self.assertRaises(WorkDenied):
            self.svc.read(self.project,"yandex.metrika.counters.list",
                          {"ids":"111"})
        with self.assertRaisesRegex(WorkDenied,"SERVICE_READ_ACTION_REFUSED"):
            self.svc.read(self.project,"yandex.direct.campaigns.update",{})

    def test_missing_scope_denied_and_yandex_transport_dedicated_auth(self):
        with self.assertRaisesRegex(WorkDenied,"YANDEX_NOT_CONNECTED"):
            self.adapter.metrika_counters()
        transport=SafeServiceTransport(("api-metrika.yandex.net",))
        with self.assertRaises(WorkDenied):
            transport.call("example.org","GET","/management/v1/counters",
                           "synthetic-token-readonly-owner",
                           auth_style="yandex")


if __name__=="__main__":
    unittest.main(verbosity=2)
