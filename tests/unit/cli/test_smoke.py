import importlib
import unittest


class SmokeTest(unittest.TestCase):
    def test_import(self):
        for m in ['repl', 'parser', 'formatter', 'session', 'commands', 'validation', 'core']:
            importlib.import_module("fw_cli." + m)


if __name__ == "__main__":
    unittest.main()
