"""
Контрактные тесты ПС-5 authd.

Те же сценарии, что AuthdTest в tests/stand/test_stand_codec.py (ветка cli/stand),
но против настоящих обработчиков fw_authd, а не заглушки mock_core: поля ответов
auth.*, user.*, session.*, коды M.. и события E.. должны совпадать с заглушкой,
по которой написан клиент CLI. Плюс проверки безопасности, найденные на ревью,
тесты поля ip, продления сеанса через auth.check и взаимодействия с ПС-2/ПС-6.
"""
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from fwcommon import protocol
from fw_authd import __main__ as authd
from fw_authd import accounts, auth, roles, sessions

_real_time = time.time

# Unix-сокеты и права 0600 проверяются только на Linux (целевая ОС — Debian 12)
_LINUX_ONLY = unittest.skipUnless(sys.platform.startswith("linux"), "нужен Linux (Unix-сокеты, права 0600)")


class _Clock:
    """Сдвиг часов для проверки блокировки (60 с) и таймаута сеанса (900 с)."""

    def __init__(self):
        self.offset = 0.0

    def __call__(self):
        return _real_time() + self.offset


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "accounts.json")
        old_path = accounts.DEFAULT_ACCOUNTS_PATH
        accounts.DEFAULT_ACCOUNTS_PATH = self.path
        self.addCleanup(setattr, accounts, "DEFAULT_ACCOUNTS_PATH", old_path)
        accounts.save_accounts({})
        accounts.add_user("admin", "admin123", "rw")
        accounts.add_user("viewer", "viewer123", "ro")
        sessions.clear_all_sessions()
        auth.clear_lockouts()
        self.addCleanup(sessions.clear_all_sessions)
        self.addCleanup(auth.clear_lockouts)

        # События перехватываются вместо отправки в ПС-2; ПС-6 не вызывается
        self.events = []
        p1 = mock.patch.object(authd, "emit_event",
                               side_effect=lambda c, d=None: self.events.append(dict(d or {}, code=c)))
        p2 = mock.patch.object(authd, "notify_integrity")
        self.notify = p2.start()
        p1.start()
        self.addCleanup(mock.patch.stopall)

        self.clock = _Clock()
        mock.patch("time.time", self.clock).start()

    def call(self, cmd, payload=None, src="cli"):
        return authd.dispatch_request({"cmd": cmd, "src": src, "payload": payload or {}})

    def ok(self, cmd, payload=None, src="cli"):
        status, p, ec, em = self.call(cmd, payload, src)
        self.assertEqual(status, "ok", (cmd, ec, em))
        self.assertIsNone(ec)
        return p

    def err(self, cmd, payload=None):
        status, p, ec, em = self.call(cmd, payload)
        self.assertEqual(status, "error", cmd)
        self.assertTrue(em)
        return ec, p

    def login(self, uid="admin", pwd="admin123", src="cli", ip=None):
        payload = {"id": uid, "password": pwd, "source": src}
        if ip is not None:
            payload["ip"] = ip
        return self.ok("auth.login", payload, src=src)

    def ev(self, code):
        return [e for e in self.events if e["code"] == code]


class AuthContractTest(_Base):
    """auth.login / logout / ping / check — как в mock_core."""

    def test_login_ok_fields(self):
        p = self.login()
        self.assertEqual(set(p), {"session_id", "username", "role", "downgraded"})
        self.assertEqual(p["role"], "rw")
        self.assertFalse(p["downgraded"])
        self.assertEqual(len(p["session_id"]), 32)
        self.assertTrue(self.ev("E01"))

    def test_login_bad_password_m02_e03(self):
        self.assertEqual(self.err("auth.login", {"id": "admin", "password": "wrong-password"})[0], "M02")
        self.assertTrue(self.ev("E03"))

    def test_login_bad_types_m02(self):
        self.assertEqual(self.err("auth.login", {"id": 1, "password": None})[0], "M02")

    def test_lockout_after_five_failures_per_id(self):
        for _ in range(4):
            self.assertEqual(self.err("auth.login", {"id": "admin", "password": "x"})[0], "M02")
        self.assertEqual(self.err("auth.login", {"id": "admin", "password": "x"})[0], "M12")
        self.assertEqual(len(self.ev("E06")), 1)
        self.assertEqual(len(self.ev("E03")), 5)
        self.assertEqual(self.err("auth.login", {"id": "admin", "password": "admin123"})[0], "M12")
        self.assertEqual(len(self.ev("E06")), 1, "E06 — один раз, при установке блокировки")
        self.assertEqual(self.login("viewer", "viewer123")["role"], "ro")
        self.clock.offset += 61
        self.assertEqual(self.login()["role"], "rw")

    def test_second_rw_downgraded_m04(self):
        self.login()
        p = self.login(src="web")
        self.assertEqual(p["role"], "ro")
        self.assertTrue(p["downgraded"])
        self.assertEqual(p["warning"], "M04")
        self.assertTrue(p["warning_message"])
        self.assertTrue(self.ev("E04"))

    def test_ping_and_idle_timeout_m15_e07(self):
        sid = self.login()["session_id"]
        self.assertEqual(self.ok("auth.ping", {"session_id": sid})["status"], "pong")
        self.clock.offset += 901
        self.assertEqual(self.err("auth.ping", {"session_id": sid})[0], "M15")
        self.assertTrue(self.ev("E07"))

    def test_housekeeping_expires_sessions_e07(self):
        self.login()
        self.clock.offset += 901
        authd.housekeeping_tick()
        self.assertEqual(self.ev("E07")[-1]["reason"], "бездействие")
        self.assertEqual(sessions.list_active_sessions(), [])

    def test_logout_e02_and_unknown_session_m15(self):
        sid = self.login()["session_id"]
        self.assertEqual(self.ok("auth.logout", {"session_id": sid}), {"status": "logged_out"})
        self.assertTrue(self.ev("E02"))
        self.assertEqual(self.err("auth.ping", {"session_id": sid})[0], "M15")
        self.assertEqual(self.err("auth.logout", {"session_id": sid})[0], "M15")

    def test_auth_check_ro_m03_e50(self):
        sid = self.login("viewer", "viewer123")["session_id"]
        self.assertEqual(self.ok("auth.check", {"session_id": sid, "cmd": "rule.get"}), {"allowed": True})
        code, p = self.err("auth.check", {"session_id": sid, "cmd": "rule.replace"})
        self.assertEqual(code, "M03")
        self.assertEqual(p, {"allowed": False})
        self.assertEqual(self.ev("E50")[-1]["cmd"], "rule.replace")

    def test_auth_check_requires_session(self):
        # Роль из запроса не принимается: без сеанса — M15
        self.assertEqual(self.err("auth.check", {"role": "rw", "cmd": "rule.add"})[0], "M15")

    def test_unknown_command_m14(self):
        self.assertEqual(self.err("auth.nope")[0], "M14")


class UserSessionContractTest(_Base):
    """user.* / session.* — как в mock_core."""

    def test_users_builtin_admin_m05(self):
        sid = self.login()["session_id"]
        self.assertEqual(self.err("user.delete", {"session_id": sid, "id": "admin"})[0], "M05")
        self.assertEqual(self.err("user.edit", {"session_id": sid, "id": "admin", "role": "ro"})[0], "M05")
        self.assertEqual(self.ok("user.edit", {"session_id": sid, "id": "admin", "password": "newpass99"}), {})

    def test_user_add_validation_m06(self):
        sid = self.login()["session_id"]
        cases = (({"id": "ab", "password": "password1", "role": "ro"}, "«id»"),
                 ({"id": "оператор", "password": "password1", "role": "ro"}, "«id»"),
                 ({"id": "oper", "password": "short", "role": "ro"}, "«password»"),
                 ({"id": "oper", "password": "password1", "role": "admin"}, "«role»"),
                 ({"id": "viewer", "password": "password1", "role": "ro"}, "уникальный"))
        for bad, text in cases:
            bad["session_id"] = sid
            status, _, code, msg = self.call("user.add", bad)
            self.assertEqual(code, "M06", bad)
            self.assertIn(text, msg, bad)
        self.assertEqual(self.ok("user.add", {"session_id": sid, "id": "oper_1",
                                              "password": "password1", "role": "ro"}), {})
        users = self.ok("user.list", {"session_id": sid})["users"]
        self.assertIn({"id": "oper_1", "role": "ro"}, users)
        self.assertNotIn("password", repr(users))  # FR-37
        e32 = self.ev("E32")[-1]
        self.assertEqual((e32["actor"], e32["target"], e32["op"]), ("admin", "oper_1", "add"))
        self.notify.assert_called()

    def test_user_edit_unknown_m06(self):
        sid = self.login()["session_id"]
        status, _, code, msg = self.call("user.edit", {"session_id": sid, "id": "ghost", "role": "ro"})
        self.assertEqual(code, "M06")
        self.assertIn("существующий", msg)

    def test_user_edit_invalid_password_keeps_role(self):
        sid = self.login()["session_id"]
        self.assertEqual(self.err("user.edit", {"session_id": sid, "id": "viewer",
                                                "role": "rw", "password": "short"})[0], "M06")
        self.assertEqual(accounts.get_user("viewer")["role"], "ro")

    def test_ro_cannot_modify_users_m03_e50(self):
        sid = self.login("viewer", "viewer123")["session_id"]
        self.assertEqual(self.err("user.add", {"session_id": sid, "id": "x_user",
                                                "password": "password1", "role": "rw"})[0], "M03")
        self.assertEqual(self.ev("E50")[-1]["cmd"], "user.add")

    def test_user_delete_kills_sessions_e07(self):
        admin = self.login()["session_id"]
        viewer = self.login("viewer", "viewer123")["session_id"]
        self.assertEqual(self.ok("user.delete", {"session_id": admin, "id": "viewer"}), {})
        self.assertEqual(self.err("auth.ping", {"session_id": viewer})[0], "M15")
        self.assertTrue(self.ev("E07"))
        self.assertNotIn("session_id", repr(self.events), "идентификаторы сеансов не пишутся в журнал")

    def test_session_list_fields(self):
        admin = self.login()["session_id"]
        self.login("viewer", "viewer123")
        items = self.ok("session.list", {"session_id": admin})["sessions"]
        self.assertEqual(len(items), 2)
        for it in items:
            for key in ("session_id", "username", "role", "source", "idle_sec", "downgraded"):
                self.assertIn(key, it)
            self.assertIsInstance(it["idle_sec"], int)

    def test_session_list_masks_ids_for_ro(self):
        admin = self.login()["session_id"]
        viewer = self.login("viewer", "viewer123")["session_id"]
        ids = [it["session_id"] for it in self.ok("session.list", {"session_id": viewer})["sessions"]]
        self.assertNotIn(admin, ids)

    def test_session_kill_e05(self):
        admin = self.login()["session_id"]
        viewer = self.login("viewer", "viewer123")["session_id"]
        self.assertEqual(self.err("session.kill", {"session_id": viewer, "target_session_id": admin})[0], "M03")
        self.assertEqual(self.ok("session.kill", {"session_id": admin, "target_session_id": viewer}),
                         {"killed": viewer})
        e05 = self.ev("E05")[-1]
        self.assertEqual((e05["actor"], e05["target"]), ("admin", "viewer"))
        self.assertEqual(self.err("auth.ping", {"session_id": viewer})[0], "M15")
        self.assertEqual(self.err("session.kill", {"session_id": admin, "target_session_id": viewer})[0], "M13")


class IpAndAuthCheckFeatureTest(_Base):
    """Тесты поля ip, продления сеанса через auth.check и проверки прав по таблице CLI."""

    def test_login_ip_field_in_session_list_and_e01(self):
        p = self.login(uid="admin", pwd="admin123", ip="192.168.1.50")
        self.assertEqual(p.get("ip"), "192.168.1.50")
        sid = p["session_id"]
        items = self.ok("session.list", {"session_id": sid})["sessions"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["ip"], "192.168.1.50")
        e01 = self.ev("E01")[-1]
        self.assertEqual(e01["ip"], "192.168.1.50")
        self.assertEqual(e01["actor"], "admin")

    def test_login_failure_ip_in_e03(self):
        self.err("auth.login", {"id": "admin", "password": "bad", "ip": "10.0.0.99"})
        e03 = self.ev("E03")[-1]
        self.assertEqual(e03["ip"], "10.0.0.99")
        self.assertEqual(e03["actor"], "admin")

    def test_login_downgrade_ip_in_e04(self):
        self.login(uid="admin", pwd="admin123", ip="192.168.1.10")
        p2 = self.login(uid="admin", pwd="admin123", ip="192.168.1.20")
        self.assertTrue(p2["downgraded"])
        self.assertEqual(p2.get("ip"), "192.168.1.20")
        e04 = self.ev("E04")[-1]
        self.assertEqual(e04["ip"], "192.168.1.20")

    def test_auth_check_extends_session(self):
        sid = self.login()["session_id"]
        # Сдвигаем время на 800 с (< 900 с таймаута)
        self.clock.offset += 800
        # auth.check должен продлить активность сеанса
        self.ok("auth.check", {"session_id": sid, "cmd": "rule.get"})
        # Сдвигаем еще на 800 с (суммарно 1600 с от входа, но 800 с от auth.check)
        self.clock.offset += 800
        # Сеанс все еще активен благодаря auth.check!
        self.assertEqual(self.ok("auth.ping", {"session_id": sid})["status"], "pong")
        # Еще через 901 с бездействия — таймаут
        self.clock.offset += 901
        self.assertEqual(self.err("auth.ping", {"session_id": sid})[0], "M15")

    def test_ro_denied_modifying_commands_table7(self):
        sid = self.login("viewer", "viewer123", src="cli")["session_id"]
        # Команды из таблицы 7 CLI (commands.py), требующие rw
        cli_modifying = [
            "rule add", "rule edit", "rule enable", "rule disable", "rule del",
            "rule.add", "rule.edit", "rule.delete", "rule.replace",
            "state enable", "state disable", "state delete", "state delete all", "state.clear",
            "log packets clear", "log.packets.clear", "log.flush",
            "config save", "config apply saved", "config apply default", "config set",
            "user add", "user edit", "user del", "session kill",
            "if up", "if down", "if ip", "time set", "route add", "route del",
            "subsystem restart", "sys reboot", "sys shutdown",
            "integrity check", "integrity restore"
        ]
        for cmd in cli_modifying:
            code, p = self.err("auth.check", {"session_id": sid, "cmd": cmd})
            self.assertEqual(code, "M03", f"Команда {cmd} должна возвращать M03 для роли ro")
            self.assertEqual(p, {"allowed": False})
            self.assertEqual(self.ev("E50")[-1]["cmd"], cmd)

    def test_ro_allowed_read_only_commands_table7(self):
        sid = self.login("viewer", "viewer123", src="cli")["session_id"]
        # Команды чтения из таблицы 7 CLI (commands.py)
        cli_read_only = [
            "rule list", "rule show", "rule.get", "rule.list", "rule.show",
            "log events show", "log packets show", "log.query.events", "log.query.packets",
            "state status", "state table", "state.status", "stats.get",
            "config show current", "config show saved", "config.show",
            "user list", "user.list", "session list", "session.list",
            "if list", "if show", "if.list", "if.show",
            "sys info", "sys.info", "time show", "time.show",
            "route list", "route.list", "subsystem list", "subsystem.list",
            "integrity status", "integrity.status",
            "help", "whoami", "logout", "exit"
        ]
        for cmd in cli_read_only:
            p = self.ok("auth.check", {"session_id": sid, "cmd": cmd})
            self.assertEqual(p, {"allowed": True}, f"Команда {cmd} должна быть разрешена для роли ro")


class SubsystemsInteractionTest(unittest.TestCase):
    """Проверка работы ПС-5 без запущенных ПС-2 и ПС-6, и вместе с настоящими (FR-28, FR-45)."""

    def setUp(self):
        authd._event_queue.clear()
        sessions.clear_all_sessions()
        auth.clear_lockouts()
        self.tmp = tempfile.TemporaryDirectory()
        self.accounts_path = os.path.join(self.tmp.name, "accounts.json")
        accounts.save_accounts({}, path=self.accounts_path)
        accounts.add_user("admin", "Admin_12345", "rw", path=self.accounts_path)

    def tearDown(self):
        self.tmp.cleanup()
        authd._event_queue.clear()
        sessions.clear_all_sessions()
        auth.clear_lockouts()

    def test_works_without_ps2_and_ps6(self):
        # Направляем сокеты на несуществующие пути
        run_dir = os.path.join(self.tmp.name, "no_services")
        authd.set_run_dir(run_dir)

        # Выполняем операции через dispatch_request: аутентификация, добавление пользователя
        res, payload, code, _ = authd.handle_auth_login(
            {"id": "admin", "password": "Admin_12345", "ip": "10.1.1.1"}, {"src": "cli"}
        )
        self.assertEqual(res, "ok")
        sid = payload["session_id"]

        # user.add требует уведомления ПС-6 и генерации E32 в ПС-2
        res, _, code, _ = authd.handle_user_add(
            {"session_id": sid, "id": "new_user", "password": "Password123", "role": "ro"},
            {"src": "cli"}
        )
        self.assertEqual(res, "ok")

        # auth.check для ro команды
        res, p, _, _ = authd.handle_auth_check(
            {"session_id": sid, "cmd": "user add"}, {"src": "cli"}
        )
        self.assertEqual(res, "ok")
        self.assertTrue(p["allowed"])

        # Проверяем, что события накопились в очереди без падений
        with authd._event_queue_lock:
            self.assertGreater(len(authd._event_queue), 0)
            codes_in_queue = [m["payload"]["code"] for m in authd._event_queue]
            self.assertIn("E01", codes_in_queue)
            self.assertIn("E32", codes_in_queue)

    def test_works_with_running_ps2_and_ps6(self):
        received_events = []
        received_integrity = []

        def mock_send(msg):
            received_events.append(msg)

        def mock_integrity_req(sock, src, dst, cmd, payload=None, **kw):
            received_integrity.append({"src": src, "dst": dst, "cmd": cmd, "payload": payload})
            return {"status": "ok", "payload": {}}

        run_dir = os.path.join(self.tmp.name, "with_services")
        os.makedirs(run_dir, exist_ok=True)
        authd.set_run_dir(run_dir)

        # Создаем файлы сокетов
        open(authd.LOGD_SOCKET, "w").close()
        open(authd.INTEGRITYD_SOCKET, "w").close()

        with mock.patch.object(authd, "_send_event", side_effect=mock_send), \
                mock.patch("fwcommon.protocol.request", side_effect=mock_integrity_req):
            # Вход администратора
            res, p, _, _ = authd.handle_auth_login(
                {"id": "admin", "password": "Admin_12345", "ip": "10.2.2.2"}, {"src": "cli"}
            )
            self.assertEqual(res, "ok")
            sid = p["session_id"]

            # Добавление пользователя -> вызывает notify_integrity
            res, _, _, _ = authd.handle_user_add(
                {"session_id": sid, "id": "test_user_2", "password": "Password123", "role": "ro"},
                {"src": "cli"}
            )
            self.assertEqual(res, "ok")

            # Даем фоновому потоку notify_integrity время отработать
            time.sleep(0.1)

            # Проверяем, что события успешно ушли в ПС-2
            event_codes = [m["payload"]["code"] for m in received_events]
            self.assertIn("E01", event_codes)
            self.assertIn("E32", event_codes)

            # Проверяем доставку в ПС-6
            self.assertEqual(len(received_integrity), 1)
            self.assertEqual(received_integrity[0]["cmd"], "integrity.update_baseline")
            self.assertEqual(received_integrity[0]["src"], "authd")
            self.assertEqual(received_integrity[0]["dst"], "integrityd")


class SecurityReviewTest(unittest.TestCase):
    """Проверки, добавленные по итогам ревью."""

    def test_whitelist_unknown_and_replace_need_rw(self):
        for cmd in ("rule.replace", "integrity.check", "something.new", None):
            self.assertFalse(roles.check_permission("ro", cmd)[0], cmd)
        for cmd in ("rule.get", "rule.list", "log.query.events", "session.list"):
            self.assertTrue(roles.check_permission("ro", cmd)[0], cmd)

    @_LINUX_ONLY
    def test_accounts_file_is_0600(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "accounts.json")
            accounts.save_accounts({}, path=path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertFalse(os.path.exists(path + ".tmp"))


@_LINUX_ONLY
class ServerTest(unittest.TestCase):
    """Запуск службы: настоящий Unix-сокет, конфигурация, код возврата main()."""

    def test_socket_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            old_path = accounts.DEFAULT_ACCOUNTS_PATH
            accounts.DEFAULT_ACCOUNTS_PATH = os.path.join(d, "accounts.json")
            accounts.mkaccounts("Admin_12345")
            try:
                with mock.patch.object(authd, "emit_event"):
                    sock = os.path.join(d, "authd.sock")
                    srv = authd.start_server(sock)
                    threading.Thread(target=srv.serve_forever, daemon=True).start()
                    try:
                        self.assertEqual(stat.S_IMODE(os.stat(sock).st_mode), 0o600)
                        r = protocol.request(sock, "cli", "authd", "auth.login",
                                             {"id": "admin", "password": "Admin_12345"})
                        self.assertEqual(r["status"], "ok")
                        self.assertEqual(r["payload"]["role"], "rw")
                    finally:
                        srv.shutdown()
                        srv.server_close()
            finally:
                accounts.DEFAULT_ACCOUNTS_PATH = old_path
                sessions.clear_all_sessions()

    def test_load_and_apply_config(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w", encoding="utf-8") as f:
                f.write('{"authd": {"accounts_path": "%s/acc.json", "hash_iterations": 250000}}' % d)
            old = accounts.DEFAULT_ACCOUNTS_PATH, accounts.DEFAULT_HASH_ITERATIONS
            try:
                authd.apply_config(authd.load_config(cfg))
                self.assertEqual(accounts.DEFAULT_ACCOUNTS_PATH, d + "/acc.json")
                self.assertEqual(accounts.DEFAULT_HASH_ITERATIONS, 250000)
            finally:
                accounts.DEFAULT_ACCOUNTS_PATH, accounts.DEFAULT_HASH_ITERATIONS = old
        self.assertEqual(authd.load_config("/nonexistent/config.json"), {})

    def test_main_returns_1_when_socket_cannot_be_created(self):
        with mock.patch.dict(os.environ, {"FW_RUN_DIR": "/proc/fw-authd-test",
                                          "FW_CONFIG": "/nonexistent"}), \
                mock.patch.object(authd, "emit_event"):
            self.assertEqual(authd.main(), 1)
        authd.set_run_dir(authd.DEFAULT_RUN_DIR)


if __name__ == "__main__":
    unittest.main()
