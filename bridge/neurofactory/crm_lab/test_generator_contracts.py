"""Offline safety and API-contract checks for the synthetic-only CRM agent."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import generate_crm as factory

STORAGE = """import json
def load_records(path):
    return []
def save_records(path, records):
    pass
"""
CRM = """import storage
class CRM:
    def __init__(self, path): pass
    def add(self, name, phone, note=""): pass
    def all(self): pass
    def search(self, query): pass
    def edit(self, id, name=None, phone=None, note=None): pass
    def set_status(self, id, status): pass
"""
MAIN = """import argparse
from crm import CRM
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--db')
    parser.parse_args()
"""

class Contracts(unittest.TestCase):
    def test_storage_valid(self):
        self.assertTrue(factory.required_contract("storage.py", STORAGE))
    def test_crm_valid(self):
        self.assertTrue(factory.required_contract("crm.py", CRM))
    def test_main_valid(self):
        self.assertTrue(factory.required_contract("main.py", MAIN))
    def test_storage_missing(self):
        with self.assertRaises(ValueError):
            factory.required_contract("storage.py", "def load_records(path): return []")
    def test_crm_missing(self):
        with self.assertRaises(ValueError):
            factory.required_contract("crm.py", "import storage\nclass CRM: pass")
    def test_crm_without_storage_dependency(self):
        with self.assertRaises(ValueError):
            factory.required_contract("crm.py", CRM.replace("import storage", "import json"))
    def test_main_without_crm_dependency(self):
        with self.assertRaises(ValueError):
            factory.required_contract("main.py", MAIN.replace("from crm import CRM", "import json"))
    def test_main_without_argparse(self):
        with self.assertRaises(ValueError):
            factory.required_contract("main.py", "from crm import CRM")
    def test_unsafe_import_denied(self):
        with self.assertRaises(ValueError):
            factory.guard("import subprocess")
    def test_unsafe_exec_denied(self):
        with self.assertRaises(ValueError):
            factory.guard("eval('1+1')")
    def test_minimal_safe_storage(self):
        self.assertTrue(factory.guard(STORAGE))
    def test_minimal_safe_crm(self):
        self.assertTrue(factory.guard(CRM))

if __name__ == "__main__":
    unittest.main()
