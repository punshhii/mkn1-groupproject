"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      test_core
Назначение:  тесты ядра управления, сеанса и цикла CLI против заглушек
             подсистем tests/stand/mock_core.py (через сокеты и кодек):
             вход и роли (FR-30, FR-32, FR-34), события E20–E22, E35, E43, E50,
             правила через rule.replace по пути (FR-10, FR-13), учётные записи,
             сеансы, журнал событий, таблица состояний (FR-44), аварийный
             режим (M10), таймаут сеанса (M15), недоступная ПС-2 (очередь)
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "stand"))

import mock_core  # noqa: E402
from fw_cli import core, parser, repl, session  # noqa: E402

IFACES = ["eth0", "eth1", "eth2"]


def _wait(pred, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


class _Stand(unittest.TestCase):
    names = mock_core.SUBSYSTEMS

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = cls._tmp.name
        cls.servers = mock_core.start(cls.dir, cls.names)

    @classmethod
    def tearDownClass(cls):
        for srv in cls.servers.values():
            srv.shutdown()
            srv.server_close()
        cls._tmp.cleanup()

    def setUp(self):
        mock_core.reset_state()
        self.core = core.Core(run_dir=self.dir, ifaces=IFACES, event_retry=False)

    def login(self, uid="admin", pwd="admin123"):
        return self.core.login(uid, pwd, ip="10.0.0.5")

    def run_cmd(self, line, sess, confirm=True, passwords=()):
        pw = list(passwords)
        return self.core.execute(parser.parse(line), sess, confirm=lambda: confirm,
                                 ask_password=lambda _p: pw.pop(0))

    def cli_events(self, code, n=1):
        """События, присланные ядром (поле source ставит CLI; в исходном журнале заглушки его нет)."""
        mine = lambda: [e for e in mock_core.events(code)  # noqa: E731
                        if e.get("src") == "cli" and e.get("source") == "cli"]
        _wait(lambda: len(mine()) >= n, 2.0)
        return mine()


class SessionTest(_Stand):
    def test_login_ping_logout(self):
        s = self.login()
        self.assertEqual((s.username, s.role, s.ip), ("admin", "rw", "10.0.0.5"))
        session.ping(self.core.path("authd"), s)
        session.logout(self.core.path("authd"), s)
        with self.assertRaises(core.protocol.ProtocolError) as cm:
            session.ping(self.core.path("authd"), s)
        self.assertEqual(cm.exception.code, "M15")

    def test_login_errors_and_downgrade(self):
        with self.assertRaises(core.protocol.ProtocolError) as cm:
            self.login(pwd="wrong-password")
        self.assertEqual(cm.exception.code, "M02")
        self.login()
        second = self.login()
        self.assertEqual((second.role, second.warning), ("ro", "M04"))

    def test_ping_if_due(self):
        s = self.login()
        mock_core.advance_clock(901)
        session.ping_if_due(self.core.path("authd"), s, interval=3600)  # рано — без запроса
        with self.assertRaises(core.protocol.ProtocolError):
            session.ping_if_due(self.core.path("authd"), s, interval=0)


class AccessTest(_Stand):
    def test_ro_denied_m03_e50(self):
        s = self.login("viewer", "viewer123")
        r = self.run_cmd("rule add 10 action=drop", s)
        self.assertEqual((r.code, r.error), ("M03", True))
        self.assertEqual(self.cli_events("E50")[-1]["cmd"], "rule add")
        self.assertEqual(len(mock_core._state["rules"]), 2)
        self.assertFalse(self.run_cmd("rule list", s).error)  # просмотр разрешён

    def test_emergency_m10(self):
        s = self.login()
        mock_core.set_broken("/etc/fw/policy.json")
        self.assertEqual(self.run_cmd("rule add 10 action=drop", s).code, "M10")
        self.assertFalse(self.run_cmd("rule list", s).error)
        self.assertTrue(self.core.emergency())

    def test_session_timeout_m15_ends_session(self):
        self.core.ping_interval = 0
        s = self.login()
        mock_core.advance_clock(901)
        r = self.run_cmd("rule list", s)
        self.assertEqual(r.code, "M15")
        self.assertTrue(r.end_session)

    def test_not_implemented(self):
        r = self.run_cmd("config show current", self.login())
        self.assertTrue(r.error)
        self.assertIn("config show current", r.text)


class RuleTest(_Stand):
    def test_list_and_show(self):
        s = self.login()
        out = self.run_cmd("rule list", s).render()
        self.assertIn("accept", out)
        self.assertIn("eth1", out)
        show = self.run_cmd("rule show 1", s).render()
        self.assertIn("hits", show)
        r = self.run_cmd("rule show 9", s)
        self.assertEqual(r.code, "M07")

    def test_add_writes_policy_by_path(self):
        s = self.login()
        r = self.run_cmd("rule add 10 in=eth0 proto=icmp icmp-type=8 action=accept out=eth2 "
                         "comment=\"пинг\"", s)
        self.assertEqual(r.code, "M09", r.text)
        rules = mock_core._state["rules"]
        self.assertEqual([x["id"] for x in rules], [1, 2, 10])
        self.assertEqual(rules[0]["hits"], 7)        # счётчики неизменённых правил сохранены
        self.assertEqual(rules[2]["out_ifaces"], [2])
        path = mock_core._state["last_policy_path"]
        self.assertTrue(os.path.isabs(path))
        self.assertFalse(os.path.exists(path))       # временный файл удалён
        self.assertEqual(self.cli_events("E20")[-1]["rule"], 10)

    def test_add_existing_m07_e43(self):
        s = self.login()
        r = self.run_cmd("rule add 1 action=drop", s)
        self.assertEqual(r.code, "M07")
        self.assertTrue(self.cli_events("E43"))

    def test_add_invalid_m06_e43(self):
        s = self.login()
        r = self.run_cmd("rule add 10 action=accept out=eth9", s)
        self.assertEqual(r.code, "M06")
        self.assertTrue(self.cli_events("E43"))

    def test_goto_and_delete_referenced_m11(self):
        s = self.login()
        self.assertEqual(self.run_cmd("rule add 30 action=drop", s).code, "M09")
        self.assertEqual(self.run_cmd("rule add 10 action=goto to=30", s).code, "M09")
        r = self.run_cmd("rule del 30", s)
        self.assertEqual(r.code, "M11")
        self.assertIn("10", r.text)
        self.assertEqual(self.run_cmd("rule del 10", s).code, "M09")
        self.assertEqual(self.run_cmd("rule del 30", s).code, "M09")
        self.assertTrue(self.cli_events("E22"))

    def test_edit_and_disable(self):
        s = self.login()
        self.assertEqual(self.run_cmd("rule edit 2 dport=5353", s).code, "M09")
        self.assertEqual(mock_core._state["rules"][1]["dport"], 5353)
        self.assertEqual([c["rule_id"] for c in mock_core._state["ct_entries"]], [1])  # FR-23
        self.assertEqual(self.run_cmd("rule disable 1", s).code, "M09")
        self.assertFalse(mock_core._state["rules"][0]["active"])
        self.assertEqual(self.run_cmd("rule enable 1", s).code, "M09")
        self.assertTrue(mock_core._state["rules"][0]["active"])
        self.assertEqual(self.run_cmd("rule edit 99 action=drop", s).code, "M07")
        self.assertEqual(len(self.cli_events("E21", 3)), 3)


class UserSessionTest(_Stand):
    def test_user_add_list_del(self):
        s = self.login()
        r = self.run_cmd("user add oper_1 role=ro", s, passwords=["password1", "password1"])
        self.assertEqual(r.code, "M09", r.text)
        self.assertIn("oper_1", self.run_cmd("user list", s).render())
        r = self.run_cmd("user add oper_2 role=ro", s, passwords=["password1", "password2"])
        self.assertEqual(r.code, "M06")
        r = self.run_cmd("user add oper_3 role=ro", s, passwords=["short"])
        self.assertEqual(r.code, "M06")
        self.assertEqual(self.run_cmd("user del oper_1", s, confirm=False).text,
                         "Операция отменена")
        self.assertIn("oper_1", mock_core._state["users"])
        self.assertEqual(self.run_cmd("user del oper_1", s).code, "M09")
        self.assertNotIn("oper_1", mock_core._state["users"])

    def test_user_edit_and_builtin_admin_m05(self):
        s = self.login()
        self.assertEqual(self.run_cmd("user edit viewer role=rw", s).code, "M09")
        self.assertEqual(self.run_cmd("user edit admin role=ro", s).code, "M05")
        r = self.run_cmd("user edit admin password", s, passwords=["newpass99", "newpass99"])
        self.assertEqual(r.code, "M09")
        self.assertEqual(mock_core._state["users"]["admin"]["password"], "newpass99")
        self.assertNotIn("newpass99", self.run_cmd("user list", s).render())  # FR-37

    def test_session_list_kill(self):
        s = self.login()
        v = self.login("viewer", "viewer123")
        self.assertIn("viewer", self.run_cmd("session list", s).render())
        self.assertEqual(self.run_cmd("session kill %s" % v.session_id, s).code, "M09")
        with self.assertRaises(core.protocol.ProtocolError):
            session.ping(self.core.path("authd"), v)

    def test_whoami_help_logout(self):
        s = self.login()
        out = self.run_cmd("whoami", s).render()
        self.assertIn("admin", out)
        self.assertIn("10.0.0.5", out)
        self.assertIn("Правила фильтрации", self.run_cmd("help", s).render())
        self.assertIn("rule add", self.run_cmd("help rule", s).render())
        self.assertEqual(self.run_cmd("help nope", s).code, "M06")
        r = self.run_cmd("logout", s)
        self.assertTrue(r.end_session)
        self.assertEqual(mock_core._state["sessions"], {})


class LogStateTest(_Stand):
    def test_log_events(self):
        s = self.login()
        r = self.run_cmd("log events show code=E01", s)
        self.assertGreaterEqual(len(r.rows), 1)
        self.assertEqual(r.rows[0]["text"], "Вход администратора")
        self.assertIn("Страница 1 из", r.render())
        self.assertEqual(self.run_cmd("log events show code=E37", s).render(), "Записи не найдены")
        self.assertEqual(self.run_cmd('log events show from="2026-10-21 00:00:00" '
                                      'to="2026-10-20 00:00:00"', s).code, "M06")

    def test_state(self):
        s = self.login()
        out = self.run_cmd("state table", s).render()
        self.assertIn("192.168.1.10:40000", out)
        self.assertIn("ESTABLISHED", out)
        self.assertIn("Контроль состояний", self.run_cmd("state status", s).render())
        self.assertEqual(self.run_cmd("state delete 1", s).code, "M09")
        self.assertEqual(self.run_cmd("state delete 1", s).code, "M13")
        self.assertEqual(self.run_cmd("state delete all", s, confirm=False).text,
                         "Операция отменена")
        self.assertEqual(len(mock_core._state["ct_entries"]), 1)
        self.assertEqual(self.run_cmd("state delete all", s).code, "M09")
        self.assertEqual(self.run_cmd("state table", s).render(), "Записи не найдены")
        self.assertEqual(len(self.cli_events("E35", 2)), 2)
        self.assertEqual(self.run_cmd("state disable", s).code, "M09")
        self.assertTrue(mock_core.events("E15"))


class NoIntegrityNoLogdTest(_Stand):
    names = ("authd", "filter")

    def test_fail_closed_and_event_queue(self):
        s = self.login()
        self.assertTrue(self.core.emergency())                      # ПС-6 не отвечает
        self.assertEqual(self.run_cmd("rule add 10 action=drop", s).code, "M10")
        self.run_cmd("rule list", s)
        self.core.events.send({"code": "E43"})
        self.assertGreater(len(self.core.events), 0)                 # ПС-2 нет — в очереди


class ReplTest(_Stand):
    def test_session_script(self):
        lines = iter(["admin", "admin", "rule list", "", "rule drop 1", "state delete all", "n",
                      "whoami", "exit"])
        secrets = iter(["wrong-password", "admin123"])
        prompts, out = [], []

        def read(p):
            prompts.append(p)
            return next(lines)

        def read_secret(p):
            prompts.append(p)
            return next(secrets)

        rc = repl.run(self.core, read=read, read_secret=read_secret, write=out.append)
        self.assertEqual(rc, 0)
        self.assertEqual(prompts[:2], ["Введите идентификатор: ", "Введите пароль: "])
        self.assertIn("admin@fw[rw]> ", prompts)
        self.assertIn(repl.CONFIRM_PROMPT, prompts)
        text = "\n".join(out)
        self.assertIn("неверный идентификатор или пароль", text)   # M02
        self.assertIn("неизвестная команда", text)                 # M14
        self.assertIn("Операция отменена", text)
        self.assertNotIn("admin123", text)                          # пароль не выводится
        self.assertEqual(len(mock_core._state["ct_entries"]), 2)    # n — без изменений

    def test_eof_logs_out(self):
        def read(p):
            if p.startswith("Введите"):
                return "admin"
            raise EOFError
        rc = repl.run(self.core, read=read, read_secret=lambda p: "admin123", write=lambda s: None)
        self.assertEqual(rc, 0)
        self.assertEqual(mock_core._state["sessions"], {})

    def test_emergency_prompt(self):
        mock_core.set_broken("/etc/fw/config.json")
        lines = iter(["admin", "exit"])
        prompts = []

        def read(p):
            prompts.append(p)
            return next(lines)
        repl.run(self.core, read=read, read_secret=lambda p: "admin123", write=lambda s: None)
        self.assertIn("admin@fw[EMERGENCY]> ", prompts)


if __name__ == "__main__":
    unittest.main()
