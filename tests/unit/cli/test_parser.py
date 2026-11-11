"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      test_parser
Назначение:  unit-тесты разбора команд и таблицы команд (таблица 7 ТЗ)
"""
import unittest

from fw_cli import commands, parser
from fw_cli.parser import ParseError


class TokenizeTest(unittest.TestCase):
    def test_spaces_and_quotes(self):
        self.assertEqual(parser.tokenize('rule add 5 comment="веб сервер" action=drop'),
                         ["rule", "add", "5", "comment=веб сервер", "action=drop"])
        self.assertEqual(parser.tokenize('time set "2026-10-22 10:00:00"'),
                         ["time", "set", "2026-10-22 10:00:00"])

    def test_escapes_and_empty_value(self):
        self.assertEqual(parser.tokenize(r'x comment="a \"b\" \\c"'), ["x", 'comment=a "b" \\c'])
        self.assertEqual(parser.tokenize('x comment=""'), ["x", "comment="])
        self.assertEqual(parser.tokenize('  \t '), [])

    def test_unclosed_quote_m06(self):
        with self.assertRaises(ParseError) as cm:
            parser.tokenize('rule add 1 comment="abc')
        self.assertEqual(cm.exception.code, "M06")

    def test_too_long_m06(self):
        with self.assertRaises(ParseError):
            parser.tokenize("x" * (parser.MAX_LINE + 1))


class ParseTest(unittest.TestCase):
    def test_rule_add(self):
        c = parser.parse("rule add 10 in=eth0 src=192.168.1.0/24 action=accept out=eth1,eth2")
        self.assertEqual(c.name, "rule add")
        self.assertEqual(c.args, {"N": "10"})
        self.assertEqual(c.named, {"in": "eth0", "src": "192.168.1.0/24",
                                   "action": "accept", "out": "eth1,eth2"})

    def test_longest_match(self):
        self.assertEqual(parser.parse("state delete all").name, "state delete all")
        c = parser.parse("state delete 42")
        self.assertEqual((c.name, c.args), ("state delete", {"ID": "42"}))
        self.assertEqual(parser.parse("config apply default").name, "config apply default")
        self.assertEqual(parser.parse("log packets clear").name, "log packets clear")

    def test_empty_line(self):
        self.assertIsNone(parser.parse("   "))

    def test_unknown_and_uppercase_m14(self):
        for line in ("rule drop 1", "RULE LIST", "foo", "log"):
            with self.assertRaises(ParseError) as cm:
                parser.parse(line)
            self.assertEqual(cm.exception.code, "M14", line)

    def test_missing_and_extra_positional_m06(self):
        for line in ("rule show", "rule show 1 2", "route add 10.0.0.0/8", "rule list 5"):
            with self.assertRaises(ParseError) as cm:
                parser.parse(line)
            self.assertEqual(cm.exception.code, "M06", line)

    def test_unknown_and_repeated_named_m06(self):
        with self.assertRaises(ParseError) as cm:
            parser.parse("rule add 1 colour=red")
        self.assertIn("colour", cm.exception.message)
        with self.assertRaises(ParseError):
            parser.parse("rule add 1 action=drop action=accept")
        with self.assertRaises(ParseError):
            parser.parse("rule list page=2")  # у rule list нет именованных аргументов

    def test_optional_and_keyword_args(self):
        self.assertEqual(parser.parse("help").args, {})
        self.assertEqual(parser.parse("help rule").args, {"GROUP": "rule"})
        c = parser.parse("user edit oper password role=ro")
        self.assertEqual((c.args, c.flags, c.named), ({"ID": "oper"}, {"password"}, {"role": "ro"}))
        c = parser.parse("user edit oper role=rw")
        self.assertEqual(c.flags, set())

    def test_log_filters(self):
        c = parser.parse('log events show code=E50 from="2026-10-20 00:00:00" page=2')
        self.assertEqual(c.named, {"code": "E50", "from": "2026-10-20 00:00:00", "page": "2"})


class CommandTableTest(unittest.TestCase):
    def test_table7_properties(self):
        C = commands.COMMANDS
        self.assertFalse(C["rule list"].rw)
        self.assertTrue(C["rule list"].emergency)
        self.assertTrue(C["rule add"].rw)
        self.assertFalse(C["rule add"].emergency)
        self.assertEqual(C["rule add"].events, ("E20",))
        # подтверждение «*» по таблице 7
        confirm = {n for n, s in C.items() if s.confirm}
        self.assertEqual(confirm, {"log packets clear", "state delete all", "config apply saved",
                                   "config apply default", "user del", "subsystem restart",
                                   "sys reboot", "sys shutdown"})
        # целостность: изменяющие, но доступны в аварийном режиме
        for n in ("integrity check", "integrity restore"):
            self.assertTrue(C[n].rw and C[n].emergency, n)

    def test_every_group_has_title(self):
        for g in commands.groups():
            self.assertIn(g, commands.GROUP_TITLES)


if __name__ == "__main__":
    unittest.main()
