"""Independent integration and behavioral tests."""
import unittest
from main import quote
from pricing import line_total
from discount import discounted_total

class FirstAppAcceptance(unittest.TestCase):
    def test_quote(self): self.assertEqual(quote(3,150,10),405)
    def test_zero_discount(self): self.assertEqual(quote(3,150,0),450)
    def test_zero_quantity(self): self.assertEqual(quote(0,150,50),0)
    def test_full_discount(self): self.assertEqual(quote(2,150,100),0)
    def test_round_down(self): self.assertEqual(quote(3,33,10),89)
    def test_line_function(self): self.assertEqual(line_total(7,12),84)
    def test_discount_function(self): self.assertEqual(discounted_total(80,25),60)
    def test_negative_quantity(self):
        with self.assertRaises(ValueError): quote(-1,50,0)
    def test_invalid_percentage(self):
        with self.assertRaises(ValueError): quote(2,50,101)
    def test_noninteger_quantity(self):
        with self.assertRaises(TypeError): quote(1.5,20,0)

if __name__=="__main__":
    unittest.main(verbosity=2)
