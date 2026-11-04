"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      test_listener
Назначение:  тесты приёма входящих команд ПС-3 (README, «Принимает»):
             emergency.enter / emergency.exit от ПС-6 (идемпотентность, M08,
             приглашение EMERGENCY, M10), session.terminate от ПС-5 (M15),
             проверка отправителя, один сокет на несколько процессов CLI,
             уведомления заглушек ПС-6 и ПС-5 через cli.sock
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "stand"))

import mock_core  # noqa: E402
from fwcommon import protocol  # noqa: E402
from fw_cli import core, listener, parser, repl  # noqa: E402

IFACES = ["eth0", "eth1", "eth2"]


def _wait(pred, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


def _msg(cmd, src, payload=None):
    return protocol.make_msg("request", src, "cli", cmd=cmd, payload=payload or {})


class InboxTest(unittest.TestCase):
    def setUp(self):
        self.changes = []
        self.inbox = listener.Inbox(on_change=lambda: self.changes.append(1))

    def test_emergency_enter_exit_idempotent(self):
        enter = _msg("emergency.enter", "integrityd", {"error_code": "M08", "error_message": "M08 text"})
        self.assertEqual(self.inbox.handler(enter)[:2], ("ok", {"mode": "emergency"}))
        self.assertEqual(self.inbox.handler(enter)[:2], ("ok", {"mode": "emergency"}))
        self.assertEqual(len(self.changes), 1)          # повтор не меняет состояния
        self.assertEqual(self.inbox.take_notice(), "M08 text")
        self.assertIsNone(self.inbox.take_notice())
        leave = _msg("emergency.exit", "integrityd")
        self.assertEqual(self.inbox.handler(leave)[:2], ("ok", {"mode": "normal"}))
        self.assertEqual(self.inbox.handler(leave)[:2], ("ok", {"mode": "normal"}))
        self.assertEqual(len(self.changes), 2)
        self.assertFalse(self.inbox.emergency)

    def test_exit_in_normal_mode_is_ok(self):
        self.assertEqual(self.inbox.handler(_msg("emergency.exit", "integrityd"))[0], "ok")

    def test_sender_checked(self):
        for cmd, src in (("emergency.enter", "authd"), ("session.terminate", "integrityd"),
                         ("rule.replace", "integrityd")):
            self.assertEqual(self.inbox.handler(_msg(cmd, src))[2], "M14")
        self.assertIsNone(self.inbox.emergency)

    def test_session_terminate(self):
        self.assertEqual(self.inbox.handler(_msg("session.terminate", "authd"))[2], "M06")
        r = self.inbox.handler(_msg("session.terminate", "authd",
                                    {"session_id": "abc", "reason": "сброшен"}))
        self.assertEqual(r[0], "ok")
        self.assertEqual(self.inbox.terminated_reason("abc"), "сброшен")
        self.assertIsNone(self.inbox.terminated_reason("other"))


class SocketTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "cli.sock")

    def tearDown(self):
        self._tmp.cleanup()

    def test_receives_over_socket_and_second_process_does_not_steal(self):
        first = listener.start(self.path)
        try:
            self.assertIsNotNone(first.srv)
            self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
            r = protocol.request(self.path, "integrityd", "cli", "emergency.enter",
                                 {"error_code": "M08"})
            self.assertEqual(r["status"], "ok")
            self.assertTrue(first.emergency)
            second = listener.start(self.path)      # другой вход: сокет уже занят
            self.assertIsNone(second.srv)
            self.assertTrue(listener.socket_busy(self.path))
        finally:
            first.close()
        self.assertFalse(os.path.exists(self.path))

    def test_socket_taken_over_after_owner_exits(self):
        first = listener.start(self.path)
        second = listener.start(self.path)
        self.assertIsNone(second.srv)
        first.close()                               # первый вход завершён
        try:
            self.assertTrue(second.listen())        # следующее приглашение второго CLI
            r = protocol.request(self.path, "integrityd", "cli", "emergency.enter", {})
            self.assertEqual(r["status"], "ok")
            self.assertTrue(second.emergency)
        finally:
            second.close()

    def test_stale_socket_file_is_replaced(self):
        stale = listener.start(self.path)
        stale.srv.shutdown()
        stale.srv.server_close()                    # процесс «упал», файл остался
        self.assertTrue(os.path.exists(self.path))
        fresh = listener.start(self.path)
        try:
            self.assertIsNotNone(fresh.srv)
        finally:
            fresh.close()


class StandTest(unittest.TestCase):
    """Приёмник CLI против заглушек: уведомления приходят от ПС-6 и ПС-5 через cli.sock."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = cls._tmp.name
        cls.servers = mock_core.start(cls.dir)

    @classmethod
    def tearDownClass(cls):
        for srv in cls.servers.values():
            srv.shutdown()
            srv.server_close()
        cls._tmp.cleanup()

    def setUp(self):
        mock_core.reset_state()
        self.inbox = listener.start(os.path.join(self.dir, "cli.sock"))
        self.core = core.Core(run_dir=self.dir, ifaces=IFACES, event_retry=False,
                              inbox=self.inbox)

    def tearDown(self):
        self.inbox.close()

    def run_cmd(self, line, sess):
        return self.core.execute(parser.parse(line), sess, confirm=lambda: True,
                                 ask_password=lambda _p: "")

    def test_mock_integrityd_notifies_enter_and_exit(self):
        s = self.core.login("admin", "admin123")
        mock_core.set_broken("/etc/fw/config.json")
        self.assertTrue(_wait(lambda: self.inbox.emergency is True))
        self.assertIn("целостность", self.inbox.take_notice())         # M08
        self.assertEqual(self.run_cmd("rule enable 1", s).code, "M10")
        self.assertEqual({n["dst"] for n in mock_core.notified("emergency.enter")},
                         {"cli", "web"})                              # обеим подсистемам
        mock_core.restore_all()
        self.assertTrue(_wait(lambda: self.inbox.emergency is False))
        self.assertFalse(self.core.emergency())
        self.assertEqual(self.run_cmd("rule enable 1", s).code, "M09")

    def test_enter_applies_before_integrity_status(self):
        # ПС-6 ещё отвечает «normal», но emergency.enter уже принят — режим аварийный
        self.inbox.handler(_msg("emergency.enter", "integrityd"))
        self.assertTrue(self.core.emergency())

    def test_session_kill_terminates_cli(self):
        a = self.core.login("admin", "admin123")
        v = self.core.login("viewer", "viewer123")
        self.assertEqual(self.run_cmd("session kill %s" % v.session_id, a).code, "M09")
        self.assertTrue(_wait(lambda: self.inbox.terminated_reason(v.session_id) is not None))
        self.assertIsNone(self.inbox.terminated_reason(a.session_id))

    def test_repl_prints_m15_and_exits_on_terminate(self):
        lines = iter(["viewer", "whoami"])
        out = []

        def read(p):
            line = next(lines)
            if line == "whoami":  # пока администратор набирает команду, его сеанс сбросили
                sid = next(iter(mock_core._state["sessions"]))
                self.inbox.handler(_msg("session.terminate", "authd",
                                        {"session_id": sid, "reason": "сеанс сброшен"}))
            return line
        rc = repl.run(self.core, read=read, read_secret=lambda p: "viewer123", write=out.append)
        self.assertEqual(rc, 0)
        self.assertIn("Сеанс завершён: «сеанс сброшен»", out)
        self.assertFalse(any("Идентификатор: viewer" in o for o in out))  # whoami не выполнялась

    def test_repl_shows_m08_and_emergency_prompt(self):
        lines = iter(["admin", "exit"])
        prompts, out = [], []

        def read(p):
            prompts.append(p)
            if p.endswith("> ") and len(prompts) == 2:
                self.inbox.handler(_msg("emergency.enter", "integrityd",
                                        {"error_message": "M08 text"}))
                raise repl.Wake()  # как SIGUSR1 от приёмника во время ожидания ввода
            return next(lines)
        repl.run(self.core, read=read, read_secret=lambda p: "admin123", write=out.append)
        self.assertEqual(prompts[1], "admin@fw[rw]> ")
        self.assertEqual(prompts[2], "admin@fw[EMERGENCY]> ")
        self.assertIn("M08 text", out)

    def test_wake_signal_only_while_waiting(self):
        repl.on_wake_signal()  # вне ожидания ввода — ничего не происходит
        repl._waiting = True
        try:
            with self.assertRaises(repl.Wake):
                repl.on_wake_signal()
        finally:
            repl._waiting = False


if __name__ == "__main__":
    unittest.main()
