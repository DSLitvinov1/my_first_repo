"""Independent integration regression checks for offline packaging."""
import unittest
from main import estimate
from volume import parcel_volume
from boxes import boxes_needed

class PackagingTests(unittest.TestCase):
    def test_standard(self): self.assertEqual(estimate(2,3,4,11,4),(24,3))
    def test_exact_fill(self): self.assertEqual(estimate(1,1,1,8,4),(1,2))
    def test_no_items(self): self.assertEqual(estimate(2,3,4,0,6),(24,0))
    def test_small_volume(self): self.assertEqual(parcel_volume(1,1,1),1)
    def test_larger_volume(self): self.assertEqual(parcel_volume(3,5,7),105)
    def test_one_box_for_one(self): self.assertEqual(boxes_needed(1,7),1)
    def test_last_partial_box(self): self.assertEqual(boxes_needed(7,3),3)
    def test_invalid_dimension(self):
        with self.assertRaises(ValueError):estimate(0,3,4,10,2)
    def test_invalid_capacity(self):
        with self.assertRaises(ValueError):estimate(2,3,4,10,0)
    def test_float_rejected(self):
        with self.assertRaises(TypeError):estimate(2.5,3,4,10,2)

if __name__=="__main__":
    unittest.main(verbosity=2)
