"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  тестовый стенд (tests/stand)
Модуль:      test_php_client
Назначение:  прогон web/tests/test_protocol.php против заглушек mock_core:
             PHP-клиент ПС-4 и Python-кодек должны понимать друг друга
             (конверт, коды ошибок, M16 после повторов, приём события logd).
             Интерпретатор — переменная PHP или php в PATH; нет — тест пропускается.
Запуск:      python3 tests/stand/test_php_client.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "common"))
sys.path.insert(0, _HERE)

import mock_core  # noqa: E402

PHP = os.environ.get("PHP") or shutil.which("php")
SCRIPT = os.path.join(_HERE, "..", "..", "web", "tests", "test_protocol.php")


@unittest.skipUnless(PHP, "нет интерпретатора PHP (переменная PHP или php в PATH)")
class PhpClientTest(unittest.TestCase):
    def test_php_against_mocks(self):
        mock_core.reset_state()
        with tempfile.TemporaryDirectory() as fast, tempfile.TemporaryDirectory() as slow:
            servers = list(mock_core.start(fast).values())
            servers += mock_core.start(slow, ("authd",), delay=1.0).values()
            try:
                r = subprocess.run([PHP, SCRIPT, fast, slow], capture_output=True, text=True,
                                   timeout=60)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertTrue(r.stdout.startswith("OK"), r.stdout)
                end = time.monotonic() + 2
                while time.monotonic() < end and not [
                        e for e in mock_core.events("E50") if e.get("src") == "web"]:
                    time.sleep(0.02)
                self.assertTrue([e for e in mock_core.events("E50") if e.get("src") == "web"])
            finally:
                for srv in servers:
                    srv.shutdown()
                    srv.server_close()


if __name__ == "__main__":
    unittest.main()
