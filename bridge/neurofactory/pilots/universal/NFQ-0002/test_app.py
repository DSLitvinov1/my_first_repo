import math, pathlib, subprocess, sys, unittest
from fuel_liters import fuel_liters
from fuel_cost import fuel_cost
class IndependentAcceptance(unittest.TestCase):
    def test_01_fuel_liters(self):
        self.assertTrue(math.isclose(fuel_liters(*(100, 8)), 8, rel_tol=1e-9, abs_tol=1e-8))
    def test_02_fuel_liters(self):
        self.assertTrue(math.isclose(fuel_liters(*(250, 6)), 15, rel_tol=1e-9, abs_tol=1e-8))
    def test_03_fuel_liters(self):
        self.assertTrue(math.isclose(fuel_liters(*(0, 10)), 0, rel_tol=1e-9, abs_tol=1e-8))
    def test_04_fuel_liters(self):
        self.assertTrue(math.isclose(fuel_liters(*(50, 12)), 6, rel_tol=1e-9, abs_tol=1e-8))
    def test_05_fuel_cost(self):
        self.assertTrue(math.isclose(fuel_cost(*(10, 55)), 550, rel_tol=1e-9, abs_tol=1e-8))
    def test_06_fuel_cost(self):
        self.assertTrue(math.isclose(fuel_cost(*(0, 70)), 0, rel_tol=1e-9, abs_tol=1e-8))
    def test_07_fuel_cost(self):
        self.assertTrue(math.isclose(fuel_cost(*(8, 50)), 400, rel_tol=1e-9, abs_tol=1e-8))
    def test_08_fuel_cost(self):
        self.assertTrue(math.isclose(fuel_cost(*(2.5, 60)), 150, rel_tol=1e-9, abs_tol=1e-8))
    def test_09_cli(self):
        result = subprocess.run([sys.executable, '-S', 'main.py', 'fuel_liters'] + ['180', '5'], capture_output=True, text=True, timeout=6)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(math.isclose(float(result.stdout.strip()), 9, rel_tol=1e-9, abs_tol=1e-8))
    def test_10_cli(self):
        result = subprocess.run([sys.executable, '-S', 'main.py', 'fuel_cost'] + ['9', '60'], capture_output=True, text=True, timeout=6)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(math.isclose(float(result.stdout.strip()), 540, rel_tol=1e-9, abs_tol=1e-8))
if __name__ == '__main__':
    unittest.main(verbosity=2)
