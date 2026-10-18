import unittest
from mbl.web import MAX_REQUEST_BYTES

class DashboardContractTests(unittest.TestCase):
    def test_request_body_ceiling_is_bounded(self):
        self.assertEqual(MAX_REQUEST_BYTES, 64 * 1024)

if __name__ == "__main__": unittest.main()
