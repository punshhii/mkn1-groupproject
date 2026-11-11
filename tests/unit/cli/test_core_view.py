"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      test_core_view
Назначение:  unit-тесты проверки прав и режима (FR-32, M03, M10), приглашений,
             подтверждения, help, вывода таблиц и IP-адреса сеанса SSH
"""
import unittest

from fw_cli import commands, core, formatter, repl, session

C = commands.COMMANDS


class AccessTest(unittest.TestCase):
    def test_roles_and_emergency(self):
        # роль здесь не проверяется (её решает ПС-5 по auth.check), только режим
        self.assertIsNone(core.access_error(C["rule list"], False))
        self.assertIsNone(core.access_error(C["rule add"], False))
        self.assertEqual(core.access_error(C["rule add"], True), "M10")
        self.assertIsNone(core.access_error(C["integrity restore"], True))
        self.assertIsNone(core.access_error(C["log events show"], True))


class ReplTest(unittest.TestCase):
    def test_prompt(self):
        self.assertEqual(repl.prompt("admin", "rw"), "admin@fw[rw]> ")
        self.assertEqual(repl.prompt("viewer", "ro"), "viewer@fw[ro]> ")
        self.assertEqual(repl.prompt("admin", "rw", emergency=True), "admin@fw[EMERGENCY]> ")

    def test_confirm(self):
        self.assertTrue(repl.is_confirmed("y"))
        for a in ("Y", "yes", "n", "", "да"):
            self.assertFalse(repl.is_confirmed(a), a)

    def test_help(self):
        self.assertIn("Правила фильтрации", repl.help_text())
        self.assertIn("rule add", repl.help_text("rule"))
        self.assertIsNone(repl.help_text("nope"))


class FormatterTest(unittest.TestCase):
    def test_table(self):
        out = formatter.table([("id", "ID"), ("role", "Роль"), ("password", "Пароль")],
                              [{"id": "admin", "role": "rw", "password": "secret"}])
        self.assertEqual(out.splitlines()[0], "ID     Роль")
        self.assertNotIn("secret", out)  # FR-37
        self.assertNotIn("Пароль", out)

    def test_empty_is_m13(self):
        self.assertEqual(formatter.table([("id", "ID")], []), "Записи не найдены")

    def test_page_footer(self):
        self.assertEqual(formatter.page_footer(2, 20, 41), "Страница 2 из 3, записей 41")
        self.assertEqual(formatter.page_footer(1, 20, 0), "Страница 1 из 1, записей 0")


class SessionTest(unittest.TestCase):
    def test_client_ip(self):
        self.assertEqual(session.client_ip({"SSH_CONNECTION": "10.0.0.5 50000 10.0.0.1 22"}),
                         "10.0.0.5")
        self.assertEqual(session.client_ip({}), "127.0.0.1")  # консоль


if __name__ == "__main__":
    unittest.main()
