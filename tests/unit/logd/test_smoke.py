import importlib
import struct
import unittest


class SmokeTest(unittest.TestCase):
    def test_import(self):
        for m in ['event_log', 'packet_log', 'query', 'rotation', '__main__']:
            importlib.import_module("fw_logd." + m)

    def test_record_size(self):
        from fw_logd import packet_log
        self.assertEqual(struct.calcsize(packet_log.RECORD_FMT), 55)


if __name__ == "__main__":
    unittest.main()
