from __future__ import annotations
import csv
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

FILE=Path(__file__).resolve().parents[1]/"code"/"conversion_router.py"
spec=importlib.util.spec_from_file_location("oleg_v64_conversion_router",FILE)
import sys
mod=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=mod
spec.loader.exec_module(mod)
NOW=int(datetime.now(timezone.utc).timestamp())
def good(site="potrebpravo.ru", deal=18, stage="Консультация проведена"):
    cfg=mod.CONFIG[site]
    return {
        "deal_id":deal, "site":site, "form_code":cfg["form"],
        "crm_source":cfg["source"],"client_id":"1700654321987654321",
        "analytics_consent_confirmed":True, "lead_consent_confirmed":True,
        "crm_stage":stage, "crm_stage_verified":True, "event_timestamp": NOW-1000
    }

class RouteTests(unittest.TestCase):
    def test_exact_routing_two_counters(self):
        rows=[good("potrebpravo.ru",18),good("semya-yurist.ru",16)]
        routed,summary=mod.route_records(rows,NOW)
        self.assertEqual([r.deal_id for r in routed[114249897]],[18])
        self.assertEqual([r.deal_id for r in routed[114251443]],[16])
        self.assertEqual(summary,{"eligible":2})
    def test_reject_other_site_or_form(self):
        a=good("potrebpravo.ru");a["form_code"]="crm_form_ep5fd"
        b=good("semya-yurist.ru");b["crm_source"]="Сайт — Защита прав потребителей"
        c=good("potrebpravo.ru");c["site"]="other.example"
        routed,reasons=mod.route_records([a,b,c],NOW)
        self.assertEqual(sum(map(len,routed.values())),0)
        self.assertEqual(reasons["form_site_mismatch"],1)
        self.assertEqual(reasons["crm_source_site_mismatch"],1)
        self.assertEqual(reasons["site_not_allowlisted"],1)
    def test_reject_no_consent_and_clientid(self):
        for field,value in (("analytics_consent_confirmed",False),("lead_consent_confirmed",False),
                            ("client_id",""),("client_id","123456<script>"),("client_id",123456),
                            ("crm_stage_verified",False)):
            rec=good();rec[field]=value
            _,reasons=mod.route_records([rec],NOW)
            self.assertEqual(reasons.get("eligible",0),0,(field,value))
    def test_status_and_timestamp_gate(self):
        for field,value in (("crm_stage","Новая"),("crm_stage","В работе"),("crm_stage",[]),
                            ("event_timestamp",NOW+20),("event_timestamp",NOW-22*86400),
                            ("deal_id",0)):
            rec=good();rec[field]=value
            _,reasons=mod.route_records([rec],NOW)
            self.assertEqual(reasons.get("eligible",0),0,(field,value))
    def test_reject_pii_and_limit(self):
        rec=good();rec["phone"]="+79998887766"
        _,reasons=mod.route_records([rec],NOW)
        self.assertEqual(reasons["unexpected_fields_PII_guard"],1)
        with self.assertRaises(mod.InvalidRecord):mod.route_records([good()]*501,NOW)
    def test_idempotency(self):
        a=good()
        routed,s=mod.route_records([a,a],NOW)
        self.assertEqual(len(routed[114249897]),1)
        self.assertEqual(s["duplicate_rejected"],1)
        routed2,s2=mod.route_records([a],NOW,{"114249897:18:oleg_crm_consultation_completed"})
        self.assertEqual(len(routed2[114249897]),0)
        self.assertEqual(s2["duplicate_rejected"],1)
    def test_no_cross_export_and_permissions(self):
        a=good("potrebpravo.ru",18)
        b=good("semya-yurist.ru",16,"Договор заключён")
        routed,_=mod.route_records([a,b],NOW)
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/"restricted"
            totals=mod.export_private_csv(directory,routed)
            self.assertEqual(totals,{"114249897":1,"114251443":1})
            self.assertEqual(directory.stat().st_mode&0o777,0o700)
            p=directory/"oleg_offline_114249897.csv"
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            with p.open(encoding="utf8") as f: rows=list(csv.DictReader(f))
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]["Target"],"oleg_crm_consultation_completed")
            self.assertEqual(set(rows[0]),set(mod.CSV_FIELDS))
            with self.assertRaises(mod.InvalidRecord):mod.export_private_csv(directory,routed)
    def test_no_upload_code(self):
        code=FILE.read_text(encoding="utf8")
        self.assertNotIn("requests.post(",code)
        self.assertNotIn("urllib.request",code)
        self.assertNotIn("http.client",code)

if __name__=="__main__":unittest.main(verbosity=2)
