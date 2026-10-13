"""Offline fail-closed tests: receipt identity without invoking either model."""
import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from stage5_live_pair_lab import check_source

SAFE = '''def reconcile_receipt(state, published, hash_matches):
    if state in ('publishing', 'needs_receipt_check'):
        if published is False:
            return 'wait'
        if published is True and hash_matches is True:
            return 'verify'
        return 'block'
    if state == 'verified_done':
        if published is True and hash_matches is True:
            return 'done'
        return 'block'
    if state == 'queued' and published is False:
        return 'ready'
    return 'block'
'''

UNSAFE = SAFE.replace('published is True', 'published == True')

class StrictReceiptTests(unittest.TestCase):
    def test_reference_receipt_passes_all_adversarial_vectors(self):
        self.assertEqual(check_source(SAFE, 'reconcile_receipt')['behavior_cases'], 13)

    def test_python_numeric_one_is_never_accepted_as_boolean_true(self):
        with self.assertRaises(ValueError):
            check_source(UNSAFE, 'reconcile_receipt')

    def test_imported_code_still_refused(self):
        with self.assertRaises(ValueError):
            check_source('import os\n'+SAFE,'reconcile_receipt')

if __name__ == '__main__': unittest.main(verbosity=2)
