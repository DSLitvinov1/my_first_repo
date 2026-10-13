"""Verified Actions usage, append-only identities, never invent a bill."""
import copy,json,pathlib,unittest
import stage5_usage_ledger as usage
ROOT=pathlib.Path(__file__).resolve().parent
LEDGER=json.loads((ROOT/"stage5-cost-ledger.json").read_text("utf-8"))
def stub(repo,id):
    return {"id":id,"status":"completed","conclusion":"success",
            "run_started_at":"2026-10-13T18:00:00Z","updated_at":"2026-10-13T18:01:02Z"}
class UsageLedgerTests(unittest.TestCase):
    def test_append_verified_success_once(self):
        record=usage.verified_run("DSLitvinov1/my_first_repo",99999001,stub)
        after,changed=usage.append_checked(LEDGER,record)
        self.assertTrue(changed);self.assertEqual(after["runs"][-1]["elapsed_wall_seconds"],62)
        self.assertIsNone(after["monetary_charges"]["verified_amount"])
        repeat,changed=usage.append_checked(after,record)
        self.assertFalse(changed);self.assertEqual(repeat,after)
        self.assertEqual(LEDGER["runs"],json.loads((ROOT/"stage5-cost-ledger.json").read_text("utf-8"))["runs"])
    def test_missing_or_nonlist_runs_refused_not_crashing(self):
        proof=usage.verified_run("DSLitvinov1/my_first_repo",99999001,stub)
        for old in (None,{},5,"unsupported"):
            value=copy.deepcopy(LEDGER)
            if old is None:
                value.pop("runs")
            else:
                value["runs"]=old
            with self.assertRaises(usage.UsageError):
                usage.append_checked(value,proof)

    def test_malformed_prior_rows_and_new_entries_denied(self):
        proof=usage.verified_run("DSLitvinov1/my_first_repo",99999001,stub)
        for old in (5,{},{"run_id":"incorrect","elapsed_wall_seconds":3},
                    {"run_id":123,"elapsed_wall_seconds":"wrong"}):
            copy_ledger=copy.deepcopy(LEDGER)
            copy_ledger["runs"].append(old)
            with self.assertRaises(usage.UsageError):
                usage.append_checked(copy_ledger,proof)
        with self.assertRaises(usage.UsageError):
            usage.append_checked(LEDGER,{**proof,"elapsed_wall_seconds":"unknown"})
        with self.assertRaises(usage.UsageError):
            usage.append_checked(LEDGER,{**proof,"run_id":True})

    def test_wrong_project_denied(self):
        with self.assertRaises(usage.UsageError):
            usage.verified_run("owner/other",99999001,stub)
    def test_unfinished_run_denied(self):
        with self.assertRaises(usage.UsageError):
            usage.verified_run("DSLitvinov1/my_first_repo",99999001,
                lambda a,b:{**stub(a,b),"status":"queued"})
    def test_later_repricing_same_run_rejected(self):
        item=usage.verified_run("DSLitvinov1/my_first_repo",99999001,stub)
        after,_=usage.append_checked(LEDGER,item)
        with self.assertRaises(usage.UsageError):
            usage.append_checked(after,{**item,"elapsed_wall_seconds":63})
    def test_reversed_duration_rejected(self):
        with self.assertRaises(usage.UsageError):
            usage.verified_run("DSLitvinov1/my_first_repo",99999001,
                lambda a,b:{**stub(a,b),"updated_at":"2026-10-13T17:59:00Z"})
    def test_fabricated_billing_denied(self):
        bill=copy.deepcopy(LEDGER);bill["monetary_charges"]["verified_amount"]=123
        item=usage.verified_run("DSLitvinov1/my_first_repo",99999001,stub)
        with self.assertRaises(usage.UsageError):usage.append_checked(bill,item)
if __name__=="__main__":unittest.main(verbosity=2)
