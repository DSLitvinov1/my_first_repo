"""Read-only Google Search Console: owner-scoped properties, no implicit writes."""
from datetime import date
from pathlib import Path
import tempfile
import unittest

from google_oauth_one import SCOPE_VALUES
from service_one import GoogleWorkspaceAdapter, ServiceOne
from work_core import WorkDenied, WorkStore


class FakeSearchConsole:
    def __init__(self, sites=None, malformed=False):
        self.calls=[]
        self.sites=sites if sites is not None else [
            {"siteUrl":"sc-domain:example.org","permissionLevel":"siteOwner"},
            {"siteUrl":"https://sub.example.org/","permissionLevel":"siteFullUser"},
            {"siteUrl":"sc-domain:unverified.org",
             "permissionLevel":"siteUnverifiedUser"}]
        self.malformed=malformed

    def call(self, host, method, path, token, payload=None, query=None,
             auth_style="bearer"):
        self.calls.append((host,method,path,token,payload))
        if host!="www.googleapis.com" or token!="synthetic-test-token":
            raise AssertionError("Unexpected endpoint or credential")
        if method=="GET" and path=="/webmasters/v3/sites":
            return {"siteEntry":"wrong" if self.malformed else self.sites}
        if method=="POST" and path.endswith("/searchAnalytics/query"):
            if not payload or payload.get("dimensions")!=["query"]:
                raise AssertionError("Search Console report must be bounded")
            return {"rows":[{"keys":["купить дом"],"clicks":4,"impressions":52,
                             "ctr":0.0769,"position":8.5}]}
        raise AssertionError("Undeclared Search Console API action")


class SearchConsoleOneTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.store=WorkStore(root/"projects",root/"data")
        self.project=self.store.create_project("SEO тест", "empty")["id"]
        self.fake=FakeSearchConsole()
        self.adapter=GoogleWorkspaceAdapter(
            lambda provider,scope:
                "synthetic-test-token" if (provider,scope)==
                ("google","searchconsole.readonly") else None,
            transport=self.fake)
        self.service=ServiceOne(self.store,{"google.tasks":self.adapter})

    def test_scope_is_readonly_and_list_has_no_mutations(self):
        self.assertEqual(SCOPE_VALUES["searchconsole.readonly"],
                         "https://www.googleapis.com/auth/webmasters.readonly")
        result=self.service.read(self.project,
                                 "google.searchconsole.sites.list",{})
        self.assertEqual(result["data"]["siteEntry"][0]["siteUrl"],
                         "sc-domain:example.org")
        self.assertEqual([x[1] for x in self.fake.calls],["GET"])
        with self.assertRaisesRegex(WorkDenied,"SERVICE_READ_FIELDS_INVALID"):
            self.service.read(self.project,"google.searchconsole.sites.list",
                              {"site_url":"sc-domain:example.org"})

    def test_queries_bounded_to_owner_verified_property(self):
        result=self.service.read(self.project,"google.searchconsole.queries",
                                 {"site_url":"sc-domain:example.org"})
        data=result["data"]
        self.assertEqual(data["rows"][0]["keys"],["купить дом"])
        self.assertEqual((date.fromisoformat(data["endDate"])-
                          date.fromisoformat(data["startDate"])).days,27)
        self.assertEqual([x[1] for x in self.fake.calls],["GET","POST"])
        self.assertEqual(self.fake.calls[-1][2],
            "/webmasters/v3/sites/sc-domain%3Aexample.org/searchAnalytics/query")
        self.assertEqual(self.fake.calls[-1][4]["rowLimit"],25)
        events=" ".join(x["detail"] for x in self.store.events())
        self.assertNotIn("synthetic-test-token",events)
        self.assertNotIn("купить дом",events)

    def test_refuses_unverified_foreign_and_invalid_properties(self):
        for site in ("sc-domain:other.org","sc-domain:unverified.org",
                     "https://localhost/","../../secrets", "sc-domain:x\n", ""):
            before=len(self.fake.calls)
            with self.subTest(site=site), self.assertRaises(WorkDenied):
                self.service.read(self.project,"google.searchconsole.queries",
                                  {"site_url":site})
            self.assertFalse(any(x[1]=="POST" for x in self.fake.calls[before:]))
        with self.assertRaisesRegex(WorkDenied,"SERVICE_READ_FIELDS_INVALID"):
            self.service.read(self.project,"google.searchconsole.queries",{})
        other=self.store.create_project("Чужой проект","empty")["id"]
        self.store.project(other)
        with self.assertRaises(WorkDenied):
            self.service.read("x"*32,"google.searchconsole.sites.list",{})

    def test_missing_token_and_corrupt_site_list_fail_closed(self):
        empty=GoogleWorkspaceAdapter(lambda _p,_s: None,transport=self.fake)
        with self.assertRaisesRegex(WorkDenied,"NOT_CONNECTED"):
            empty.list_searchconsole_sites()
        self.assertEqual(self.fake.calls,[])
        self.fake.malformed=True
        with self.assertRaisesRegex(WorkDenied,"RESPONSE_INVALID"):
            self.adapter.searchconsole_queries("sc-domain:example.org")


if __name__=="__main__":
    unittest.main(verbosity=2)
