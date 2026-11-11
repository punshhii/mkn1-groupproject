"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  тестовый стенд (tests/stand)
Модуль:      test_php_listener
Назначение:  приёмник ПС-4 (web/src/listener.php) против заглушек mock_core:
             emergency.enter / emergency.exit от ПС-6 и session.terminate от ПС-5
             приходят на web.sock независимо от CLI, повторы идемпотентны, повтор
             с тем же msg_id получает прежний ответ, чужой отправитель — M14;
             FwInbox::emergency учитывает и уведомление, и integrity.status.
             Интерпретатор — переменная PHP или php в PATH; нет — тест пропускается.
Запуск:      python3 tests/stand/test_php_listener.py
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "common"))
sys.path.insert(0, _HERE)

import mock_core  # noqa: E402
from fwcommon import protocol  # noqa: E402

PHP = os.environ.get("PHP") or shutil.which("php")
WEB = os.path.join(_HERE, "..", "..", "web")
LISTENER = os.path.join(WEB, "src", "listener.php")
UNIT = os.path.join(WEB, "tests", "test_inbox.php")


def _wait(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


@unittest.skipUnless(PHP, "нет интерпретатора PHP (переменная PHP или php в PATH)")
class PhpListenerTest(unittest.TestCase):
    def setUp(self):
        mock_core.reset_state()
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.sock = os.path.join(self.dir, "web.sock")
        self.servers = mock_core.start(self.dir)
        self.proc = subprocess.Popen([PHP, LISTENER, self.dir], stderr=subprocess.PIPE)
        self.assertTrue(_wait(lambda: os.path.exists(self.sock)), "web.sock не появился")

    def tearDown(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.proc.stderr.close()
        for srv in self.servers.values():
            srv.shutdown()
            srv.server_close()
        self._tmp.cleanup()

    def state(self):
        with open(os.path.join(self.dir, "web.state.json"), encoding="utf-8") as f:
            return json.load(f)

    def php(self, code):
        r = subprocess.run([PHP, "-r", "require %r; %s" % (os.path.join(WEB, "src", "inbox.php"), code)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_unit_script(self):
        r = subprocess.run([PHP, UNIT], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(r.stdout.startswith("OK"), r.stdout)

    def test_socket_mode_and_state_file(self):
        self.assertEqual(os.stat(self.sock).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.join(self.dir, "web.state.json")).st_mode & 0o777, 0o600)

    def test_enter_exit_idempotent(self):
        for _ in range(2):
            r = protocol.request(self.sock, "integrityd", "web", "emergency.enter",
                                 {"error_code": "M08", "error_message": "M08 text"})
            self.assertEqual((r["status"], r["payload"]), ("ok", {"mode": "emergency"}))
        self.assertTrue(self.state()["emergency"])
        self.assertEqual(self.php("var_export(FwInbox::emergency(%r));" % self.dir), "true")
        for _ in range(2):
            r = protocol.request(self.sock, "integrityd", "web", "emergency.exit")
            self.assertEqual(r["payload"], {"mode": "normal"})
        self.assertIs(self.state()["emergency"], False)
        # штатный режим по уведомлению и по integrity.status заглушки
        self.assertEqual(self.php("var_export(FwInbox::emergency(%r));" % self.dir), "false")

    def test_retry_same_msg_id_gets_same_response(self):
        msg = protocol.make_msg("request", "integrityd", "web", cmd="emergency.enter", payload={})
        answers = []
        for _ in range(2):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(self.sock)
                s.sendall(protocol.encode_line(msg))
                answers.append(s.makefile("rb").readline())
        self.assertEqual(answers[0], answers[1])
        self.assertEqual(json.loads(answers[0])["reply_to"], msg["msg_id"])

    def test_wrong_sender_m14(self):
        with self.assertRaises(protocol.ProtocolError) as cm:
            protocol.request(self.sock, "authd", "web", "emergency.enter")
        self.assertEqual(cm.exception.code, "M14")
        self.assertIsNone(self.state()["emergency"])

    def test_mock_integrityd_notifies_web_independently_of_cli(self):
        # CLI не запущен (cli.sock нет), ПС-4 всё равно получает оба уведомления
        mock_core.set_broken("/etc/fw/config.json")
        self.assertTrue(_wait(lambda: self.state()["emergency"] is True))
        self.assertIn("целостность", self.state()["notice"])
        mock_core.restore_all()
        self.assertTrue(_wait(lambda: self.state()["emergency"] is False))

    def test_session_kill_terminates_web_session(self):
        authd = os.path.join(self.dir, "authd.sock")
        admin = protocol.request(authd, "cli", "authd", "auth.login",
                                 {"id": "admin", "password": "admin123", "source": "cli"})["payload"]
        web = protocol.request(authd, "web", "authd", "auth.login",
                               {"id": "viewer", "password": "viewer123", "source": "web"})["payload"]
        protocol.request(authd, "cli", "authd", "session.kill",
                         {"session_id": admin["session_id"], "target_session_id": web["session_id"]})
        self.assertTrue(_wait(lambda: web["session_id"] in self.state()["terminated"]))
        self.assertEqual(self.php("echo FwInbox::terminatedReason(%r, %r);"
                                  % (self.dir, web["session_id"])),
                         "сеанс сброшен администратором admin")
        self.assertNotIn(admin["session_id"], self.state()["terminated"])


if __name__ == "__main__":
    unittest.main()
