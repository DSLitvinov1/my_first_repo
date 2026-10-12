import math, pathlib, subprocess, sys, unittest
from celsius_to_fahrenheit import celsius_to_fahrenheit
from fahrenheit_to_celsius import fahrenheit_to_celsius
class IndependentAcceptance(unittest.TestCase):
    def test_01_celsius_to_fahrenheit(self):
        self.assertTrue(math.isclose(celsius_to_fahrenheit(*(0,)), 32, rel_tol=1e-9, abs_tol=1e-8))
    def test_02_celsius_to_fahrenheit(self):
        self.assertTrue(math.isclose(celsius_to_fahrenheit(*(100,)), 212, rel_tol=1e-9, abs_tol=1e-8))
    def test_03_celsius_to_fahrenheit(self):
        self.assertTrue(math.isclose(celsius_to_fahrenheit(*(-40,)), -40, rel_tol=1e-9, abs_tol=1e-8))
    def test_04_celsius_to_fahrenheit(self):
        self.assertTrue(math.isclose(celsius_to_fahrenheit(*(20,)), 68, rel_tol=1e-9, abs_tol=1e-8))
    def test_05_fahrenheit_to_celsius(self):
        self.assertTrue(math.isclose(fahrenheit_to_celsius(*(32,)), 0, rel_tol=1e-9, abs_tol=1e-8))
    def test_06_fahrenheit_to_celsius(self):
        self.assertTrue(math.isclose(fahrenheit_to_celsius(*(212,)), 100, rel_tol=1e-9, abs_tol=1e-8))
    def test_07_fahrenheit_to_celsius(self):
        self.assertTrue(math.isclose(fahrenheit_to_celsius(*(-40,)), -40, rel_tol=1e-9, abs_tol=1e-8))
    def test_08_fahrenheit_to_celsius(self):
        self.assertTrue(math.isclose(fahrenheit_to_celsius(*(68,)), 20, rel_tol=1e-9, abs_tol=1e-8))
    def test_09_cli(self):
        result = subprocess.run([sys.executable, '-S', 'main.py', 'celsius_to_fahrenheit'] + ['10'], capture_output=True, text=True, timeout=6)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(math.isclose(float(result.stdout.strip()), 50, rel_tol=1e-9, abs_tol=1e-8))
    def test_10_cli(self):
        result = subprocess.run([sys.executable, '-S', 'main.py', 'fahrenheit_to_celsius'] + ['50'], capture_output=True, text=True, timeout=6)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(math.isclose(float(result.stdout.strip()), 10, rel_tol=1e-9, abs_tol=1e-8))
if __name__ == '__main__':
    unittest.main(verbosity=2)
