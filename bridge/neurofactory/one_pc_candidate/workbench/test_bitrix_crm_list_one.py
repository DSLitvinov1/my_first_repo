"""Read-only Bitrix24 lead/deal funnel pages with independent CRM scope."""
from pathlib import Path
import tempfile
import unittest

from service_one import Bitrix24Adapter,ServiceOne
from work_core import WorkDenied, WorkStore


class StubBitrixTransport:
    def __init__(self):
        self.calls=[]
        self.corrupt=False

    def call(self,host,method,path,token,payload=None,query=None,
             auth_style="bearer"):
        self.calls.append({"host":host,"method":method,"path":path,
                           "token":token,"payload":payload,
                           "auth_style":auth_style})
        if host!="example.bitrix24.ru" or method!="POST" or                 token!="owner-crm-scoped-token" or auth_style!="bitrix":
            raise AssertionError("Unexpected host, mutation or wrong token")
        if path=="/rest/crm.deal.list.json":
            if self.corrupt:
                return {"result":[{"ID":"1","TITLE":"sensitive"}]*51}
            return {"result":[{"ID":"5","TITLE":"Private person",
                               "STAGE_ID":"NEW","CATEGORY_ID":"0",
                               "SOURCE_ID":"WEB","DATE_CREATE":"2026-11-14"}],
                    "total":1}
        if path=="/rest/crm.lead.list.json":
            return {"result":[{"ID":"9","TITLE":"Never reveal me",
                               "STATUS_ID":"NEW","SOURCE_ID":"WEB",
                               "DATE_CREATE":"2026-11-14"}],
                    "total":1}
        raise AssertionError("Unexpected CRM action")


class BitrixCRMListTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.store=WorkStore(root/"projects",root/"data")
        self.project=self.store.create_project("CRM аудит","empty")["id"]
        self.fake=StubBitrixTransport()
        self.load=lambda provider,scope: (
            "owner-crm-scoped-token" if (provider,scope)==("bitrix24","crm")
            else None)
        self.adapter=Bitrix24Adapter("example.bitrix24.ru",self.load,
                                     transport=self.fake)
        self.svc=ServiceOne(self.store,{"bitrix.tasks":self.adapter})

    def test_recent_deals_and_leads_read_only_and_private(self):
        deals=self.svc.read(self.project,"bitrix.crm.deals.list",{})["data"]
        leads=self.svc.read(self.project,"bitrix.crm.leads.list",{})["data"]
        self.assertEqual(deals["records"][0]["STAGE_ID"],"NEW")
        self.assertEqual(leads["records"][0]["STATUS_ID"],"NEW")
        self.assertNotIn("TITLE",deals["records"][0])
        self.assertNotIn("Private person",str(deals))
        self.assertNotIn("Never reveal me",str(leads))
        self.assertTrue(deals["single_page"])
        self.assertEqual([x["path"] for x in self.fake.calls],
                         ["/rest/crm.deal.list.json","/rest/crm.lead.list.json"])
        for req in self.fake.calls:
            self.assertEqual(req["payload"]["start"],0)
            self.assertLessEqual(len(req["payload"]["select"]),5)
            self.assertNotIn("TITLE",req["payload"]["select"])
        logs=" ".join(evt["detail"] for evt in self.store.events())
        self.assertNotIn("owner-crm-scoped-token",logs)

    def test_scope_and_schema_gates(self):
        no_crm=Bitrix24Adapter("example.bitrix24.ru",
            lambda provider,scope: "task-only-token" if scope=="task" else None,
            transport=self.fake)
        with self.assertRaisesRegex(WorkDenied,"CRM_SCOPE_NOT_CONNECTED"):
            no_crm.crm_list("deal")
        with self.assertRaises(WorkDenied):
            self.adapter.crm_list("user")
        for resource,fields in (
            ("bitrix.crm.deals.list",{"id":"5"}),
            ("bitrix.crm.leads.list",{"start":50}),
            ("bitrix.crm.leads.delete",{}),
        ):
            with self.subTest(resource=resource),self.assertRaises(WorkDenied):
                self.svc.read(self.project,resource,fields)
        self.fake.corrupt=True
        with self.assertRaisesRegex(WorkDenied,"CRM_LIST_FAILED"):
            self.svc.read(self.project,"bitrix.crm.deals.list",{})
        # No user-supplied portal/URL can reach the adapter's internal API method.
        self.assertEqual(self.adapter.portal,"example.bitrix24.ru")


if __name__=="__main__":
    unittest.main(verbosity=2)
