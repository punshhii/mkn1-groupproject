"""
Unit-тесты для подсистемы ПС-5 Авторизация (fw-authd).
Проверка требований FR-30 – FR-37.
"""
import os
import tempfile
import unittest
from fw_authd import accounts, auth, roles, sessions, __main__


class AccountsTest(unittest.TestCase):
    def test_validation(self):
        # Username
        self.assertTrue(accounts.validate_username("admin")[0])
        self.assertTrue(accounts.validate_username("user_123")[0])
        self.assertFalse(accounts.validate_username("ab")[0])  # < 3
        self.assertFalse(accounts.validate_username("a" * 33)[0])  # > 32
        self.assertFalse(accounts.validate_username("bad-name")[0])  # дефис запрещен

        # Password
        self.assertTrue(accounts.validate_password("12345678")[0])
        self.assertFalse(accounts.validate_password("short")[0])  # < 8

        # Role
        self.assertTrue(accounts.validate_role("rw")[0])
        self.assertTrue(accounts.validate_role("ro")[0])
        self.assertFalse(accounts.validate_role("superuser")[0])

    def test_hash_verify(self):
        pwd = "Secret_Password_2026"
        h, salt = accounts.hash_password(pwd)
        self.assertTrue(accounts.verify_password(pwd, h, salt))
        self.assertFalse(accounts.verify_password("wrong_password", h, salt))

    def test_builtin_admin_protection(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tmp_path = tf.name
        try:
            # Создаем учетку admin
            accounts.save_accounts({}, path=tmp_path)
            ok, _ = accounts.add_user("admin", "Admin_12345", "rw", path=tmp_path)
            self.assertTrue(ok)

            # Попытка удалить admin -> M05
            ok, err = accounts.delete_user("admin", path=tmp_path)
            self.assertFalse(ok)
            self.assertEqual(err, "M05")

            # Попытка сменить роль admin -> M05
            ok, err = accounts.edit_user("admin", new_role="ro", path=tmp_path)
            self.assertFalse(ok)
            self.assertEqual(err, "M05")

            # Смена пароля admin разрешена
            ok, err = accounts.edit_user("admin", new_password="NewAdminPassword123", path=tmp_path)
            self.assertTrue(ok)
            self.assertIsNone(err)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class AuthAndLockoutTest(unittest.TestCase):
    def setUp(self):
        auth.clear_lockouts()
        sessions.clear_all_sessions()
        self.tmp_fd, self.tmp_path = tempfile.mkstemp()
        os.close(self.tmp_fd)
        accounts.save_accounts({}, path=self.tmp_path)
        accounts.add_user("testuser", "Password_123", "rw", path=self.tmp_path)

    def tearDown(self):
        auth.clear_lockouts()
        sessions.clear_all_sessions()
        if os.path.exists(self.tmp_path):
            os.remove(self.tmp_path)

    def test_auth_success(self):
        ok, sess, warn, ev = auth.authenticate("testuser", "Password_123", source="cli", accounts_path=self.tmp_path)
        self.assertTrue(ok)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["username"], "testuser")
        self.assertEqual(sess["effective_role"], "rw")
        self.assertEqual(ev, "E01")

    def test_auth_failure_and_lockout(self):
        # 4 неудачи подряд -> M02, E03
        for i in range(4):
            ok, sess, msg, ev = auth.authenticate("testuser", "wrong", source="cli", accounts_path=self.tmp_path)
            self.assertFalse(ok)
            self.assertEqual(msg, "M02")
            self.assertEqual(ev, "E03")

        # 5-я неудача -> блокировка на 60 с (M12, E06)
        ok, sess, msg, ev = auth.authenticate("testuser", "wrong", source="cli", accounts_path=self.tmp_path)
        self.assertFalse(ok)
        self.assertEqual(msg, "M12")
        self.assertEqual(ev, "E06")
        self.assertTrue(auth.is_locked("testuser"))

        # Следующая попытка (даже с верным паролем) заблокирована (M12)
        ok, sess, msg, ev = auth.authenticate("testuser", "Password_123", source="cli", accounts_path=self.tmp_path)
        self.assertFalse(ok)
        self.assertEqual(msg, "M12")


class SessionsAndRolesTest(unittest.TestCase):
    def setUp(self):
        sessions.clear_all_sessions()

    def tearDown(self):
        sessions.clear_all_sessions()

    def test_concurrent_rw_downgrade(self):
        # Первый RW сеанс
        s1, warn1, ev1 = sessions.create_session("admin", "rw", source="cli")
        self.assertEqual(s1["effective_role"], "rw")
        self.assertIsNone(warn1)
        self.assertEqual(ev1, "E01")

        # Второй RW сеанс во время активности первого -> понижение до ro (FR-34, M04, E04)
        s2, warn2, ev2 = sessions.create_session("operator", "rw", source="web")
        self.assertEqual(s2["effective_role"], "ro")
        self.assertEqual(warn2, "M04")
        self.assertEqual(ev2, "E04")

    def test_touch_and_kill(self):
        s1, _, _ = sessions.create_session("admin", "rw", source="cli")
        sid = s1["session_id"]
        self.assertTrue(sessions.touch_session(sid))

        ok, msg, ev = sessions.kill_session(sid)
        self.assertTrue(ok)
        self.assertEqual(msg, "M15")
        self.assertEqual(ev, "E05")
        self.assertIsNone(sessions.get_session(sid))

    def test_roles_permissions(self):
        # rw может все
        ok, err, ev = roles.check_permission("rw", "rule.add")
        self.assertTrue(ok)
        self.assertIsNone(err)

        # ro может читать
        ok, err, ev = roles.check_permission("ro", "rule.list")
        self.assertTrue(ok)
        self.assertIsNone(err)

        # ro не может изменять -> M03, E50
        ok, err, ev = roles.check_permission("ro", "rule.add")
        self.assertFalse(ok)
        self.assertEqual(err, "M03")
        self.assertEqual(ev, "E50")


class DispatchTest(unittest.TestCase):
    def setUp(self):
        sessions.clear_all_sessions()
        auth.clear_lockouts()
        self.tmp_fd, self.tmp_path = tempfile.mkstemp()
        os.close(self.tmp_fd)
        accounts.save_accounts({}, path=self.tmp_path)
        accounts.add_user("admin", "Admin_12345", "rw", path=self.tmp_path)
        accounts.DEFAULT_ACCOUNTS_PATH = self.tmp_path

    def tearDown(self):
        sessions.clear_all_sessions()
        auth.clear_lockouts()
        if os.path.exists(self.tmp_path):
            os.remove(self.tmp_path)

    def test_dispatch_login_and_ping(self):
        login_msg = {
            "cmd": "auth.login",
            "payload": {"id": "admin", "password": "Admin_12345", "source": "cli"},
        }
        status, payload, err_c, err_m = __main__.dispatch_request(login_msg)
        self.assertEqual(status, "ok")
        self.assertIn("session_id", payload)
        sid = payload["session_id"]

        ping_msg = {
            "cmd": "auth.ping",
            "payload": {"session_id": sid},
        }
        status, payload, err_c, err_m = __main__.dispatch_request(ping_msg)
        self.assertEqual(status, "ok")
        self.assertEqual(payload["status"], "pong")


if __name__ == "__main__":
    unittest.main()
