import importlib
import unittest


class SmokeTest(unittest.TestCase):
    def test_import(self):
        """Все модули ПС-6 импортируются."""
        for m in ['hasher', 'checker', 'emergency', 'restore', 'mkbaseline', '__main__']:
            importlib.import_module("fw_integrityd." + m)

    def test_commands(self):
        """Для каждой входящей команды заданы допустимые источники (с. 31)."""
        main = importlib.import_module("fw_integrityd.__main__")
        self.assertEqual(set(main.COMMANDS), set(main.ALLOWED_SRC))

    def test_stubs_not_implemented(self):
        """Нереализованные функции бросают NotImplementedError."""
        from fw_integrityd import emergency
        with self.assertRaises(NotImplementedError):
            emergency.is_active()


if __name__ == "__main__":
    unittest.main()
