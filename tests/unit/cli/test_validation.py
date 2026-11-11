"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      test_validation
Назначение:  unit-тесты проверки данных по common/validation.json (таблицы 2
             и 3, FR-13, FR-36, FR-39) и преобразования правила в policy.json
"""
import unittest

from fw_cli import validation as v
from fw_cli.validation import ValidationError

IFACES = ["eth0", "eth1", "eth2"]


class ValuesTest(unittest.TestCase):
    def bad(self, fn, *args):
        with self.assertRaises(ValidationError) as cm:
            fn(*args)
        self.assertEqual(cm.exception.code, "M06")
        return cm.exception

    def test_ipv4_expr(self):
        for ok in ("192.168.1.10", "192.168.1.0/24", "0.0.0.0/0", "10.0.0.1-10.0.0.9", "any"):
            self.assertEqual(v.check_ipv4_expr(ok, "src"), ok)
        for bad in ("256.1.1.1", "1.2.3", "01.2.3.4", "1.2.3.4/33", "10.0.0.9-10.0.0.1",
                    "1.2.3.4/", "a.b.c.d", " 1.2.3.4", ""):
            e = self.bad(v.check_ipv4_expr, bad, "src")
            self.assertIn("«src»", e.message)

    def test_mac(self):
        self.assertEqual(v.check_mac("aa:bb:cc:dd:ee:ff", "smac"), "AA:BB:CC:DD:EE:FF")
        for bad in ("AA:BB:CC:DD:EE", "AA-BB-CC-DD-EE-FF", "GG:BB:CC:DD:EE:FF"):
            self.bad(v.check_mac, bad, "smac")
        self.bad(v.check_mac, "any", "smac", False)

    def test_ports(self):
        for ok in ("80", "1024-2000", "1", "65535", "any"):
            v.check_port_expr(ok, "dport")
        for bad in ("0", "65536", "2000-1024", "80-", "-80", "08", "http"):
            self.bad(v.check_port_expr, bad, "dport")

    def test_datetime(self):
        v.check_datetime("2026-10-22 10:00:00", "from")
        for bad in ("2026-02-30 10:00:00", "22.10.2026 10:00:00", "2026-10-22", "2026-10-22 25:00:00"):
            self.bad(v.check_datetime, bad, "from")

    def test_cidr_and_addr(self):
        v.check_cidr("10.0.0.0/8", "NET")
        self.bad(v.check_cidr, "10.0.0.0", "NET")
        v.check_ipv4_addr("10.0.0.1", "GW")
        self.bad(v.check_ipv4_addr, "10.0.0.0/8", "GW")


class RuleTest(unittest.TestCase):
    def rule(self, fields, rid="10", existing=(), base=None):
        return v.validate_rule(rid, fields, IFACES, existing, base)

    def bad(self, fields, field, rid="10", existing=(), base=None):
        with self.assertRaises(ValidationError) as cm:
            self.rule(fields, rid, existing, base)
        self.assertEqual(cm.exception.code, "M06")
        self.assertEqual(cm.exception.field, field)

    def test_accept_with_defaults(self):
        r = self.rule({"in": "eth0", "src": "192.168.1.0/24", "proto": "tcp", "dport": "80",
                       "action": "accept", "out": "eth1,eth2", "state": "on", "log": "yes"})
        self.assertEqual(r["id"], 10)
        self.assertEqual(r["out"], ["eth1", "eth2"])
        self.assertEqual((r["active"], r["dst"], r["comment"]), ("yes", "any", ""))

    def test_rule_number(self):
        for bad in ("0", "65536", "abc", "-1"):
            self.bad({"action": "drop"}, "N", rid=bad)

    def test_action_required_and_values(self):
        self.bad({"proto": "tcp"}, "action")
        self.bad({"action": "allow"}, "action")

    def test_unknown_field(self):
        self.bad({"action": "drop", "colour": "red"}, "colour")

    def test_proto(self):
        self.assertEqual(self.rule({"action": "drop", "proto": "47"})["proto"], 47)
        self.assertEqual(self.rule({"action": "drop", "proto": "6", "dport": "22"})["proto"], "tcp")
        self.bad({"action": "drop", "proto": "256"}, "proto")
        self.bad({"action": "drop", "proto": "sctp"}, "proto")

    def test_only_if(self):
        self.bad({"action": "drop", "dport": "80"}, "dport")                  # нет proto
        self.bad({"action": "drop", "proto": "icmp", "sport": "80"}, "sport")
        self.bad({"action": "drop", "proto": "tcp", "icmp-type": "8"}, "icmp-type")
        self.bad({"action": "drop", "state": "on"}, "state")
        r = self.rule({"action": "drop", "proto": "icmp", "icmp-type": "8", "icmp-code": "0"})
        self.assertEqual((r["icmp-type"], r["icmp-code"]), (8, 0))

    def test_out(self):
        self.bad({"action": "accept"}, "out")                                  # обязателен
        self.bad({"action": "accept", "in": "eth0", "out": "eth0,eth1"}, "out")  # входной
        self.bad({"action": "accept", "out": "eth1,eth1"}, "out")
        self.bad({"action": "accept", "out": "eth1, eth2"}, "out")
        self.bad({"action": "accept", "out": "eth9"}, "out")
        self.bad({"action": "drop", "out": "eth1"}, "out")
        self.bad({"action": "drop", "in": "eth7"}, "in")

    def test_goto(self):
        self.assertEqual(self.rule({"action": "goto", "to": "20"}, existing={20})["to"], 20)
        self.bad({"action": "goto"}, "to")
        self.bad({"action": "goto", "to": "20"}, "to")                         # не существует
        self.bad({"action": "goto", "to": "5"}, "to", existing={5})            # меньший номер
        self.bad({"action": "goto", "to": "10"}, "to", existing={10})          # на себя
        self.bad({"action": "drop", "to": "20"}, "to", existing={20})

    def test_comment(self):
        self.rule({"action": "drop", "comment": "я" * 255})
        self.bad({"action": "drop", "comment": "я" * 256}, "comment")

    def test_edit_resets_inherited_fields(self):
        base = self.rule({"in": "eth0", "proto": "tcp", "dport": "80", "action": "accept",
                          "out": "eth1", "state": "on"})
        r = self.rule({"action": "drop"}, base=base)
        self.assertNotIn("out", r)
        self.assertEqual(r["state"], "off")
        r = self.rule({"proto": "icmp"}, base=base)
        self.assertEqual(r["dport"], "any")
        self.bad({"proto": "icmp", "dport": "81"}, "dport", base=base)


class RuleConversionTest(unittest.TestCase):
    def test_to_filter_and_back(self):
        r = v.validate_rule("10", {"in": "eth0", "src": "192.168.1.0/24", "proto": "tcp",
                                   "sport": "1024-2000", "dport": "80", "action": "accept",
                                   "out": "eth1,eth2", "state": "on", "log": "yes",
                                   "comment": "web"}, IFACES)
        f = v.rule_to_filter(r, IFACES)
        self.assertEqual(f, {"id": 10, "active": True, "log": True, "action": "accept",
                             "conntrack": True, "in_iface": 0, "src": "192.168.1.0/24",
                             "proto": "tcp", "sport": "1024-2000", "dport": 80,
                             "out_ifaces": [1, 2], "comment": "web"})
        back = v.rule_from_filter(dict(f, hits=5), IFACES)
        self.assertEqual(back.pop("hits"), 5)
        self.assertEqual(back, r)

    def test_goto_and_icmp(self):
        r = v.validate_rule("1", {"proto": "icmp", "icmp-type": "8", "action": "goto",
                                  "to": "5", "active": "no"}, IFACES, {5})
        f = v.rule_to_filter(r, IFACES)
        self.assertEqual((f["to_rule"], f["icmp_type"], f["active"]), (5, 8, False))
        self.assertNotIn("icmp_code", f)
        self.assertEqual(v.rule_from_filter(f, IFACES), r)


class ConfigAccountTest(unittest.TestCase):
    def test_config(self):
        self.assertEqual(v.validate_config("tcp_est_timeout_sec", "7200"), 7200)
        self.assertIs(v.validate_config("arp_forwarding", "on"), True)
        self.assertIs(v.validate_config("conntrack_enabled", "off"), False)
        for name, bad in (("tcp_est_timeout_sec", "0"), ("tcp_est_timeout_sec", "86401"),
                          ("state_table_size", "1023"), ("arp_forwarding", "maybe"),
                          ("integrity_period_sec", "5"), ("no_such_param", "1")):
            with self.assertRaises(ValidationError, msg=(name, bad)):
                v.validate_config(name, bad)

    def test_account(self):
        v.validate_account("oper_1", "password1", "ro")
        for kw in ({"user_id": "ab"}, {"user_id": "a" * 33}, {"user_id": "опер"},
                   {"user_id": "op-er"}, {"password": "short"}, {"password": "x" * 129},
                   {"role": "admin"}):
            with self.assertRaises(ValidationError, msg=kw):
                v.validate_account(**kw)


class LogFilterTest(unittest.TestCase):
    def test_events(self):
        p = v.validate_event_filter({"code": "E50", "from": "2026-10-20 00:00:00", "page": "2"})
        self.assertEqual(p, {"event_code": "E50", "from_ts": "2026-10-20 00:00:00",
                             "page": 2, "page_size": 20})
        for bad in ({"code": "E99"}, {"page": "0"},
                    {"from": "2026-10-21 00:00:00", "to": "2026-10-20 00:00:00"}):
            with self.assertRaises(ValidationError, msg=bad):
                v.validate_event_filter(bad)

    def test_packets(self):
        p = v.validate_packet_filter({"action": "pass", "in": "eth0", "rule": "0",
                                      "src": "10.0.0.0/8", "dport": "80"}, IFACES)
        self.assertEqual(p, {"action": "accept", "in_iface": "eth0", "rule_id": 0,
                             "src_ip": "10.0.0.0/8", "dport": 80, "page": 1, "page_size": 20})
        for bad in ({"action": "accept"}, {"out": "eth9"}, {"smac": "any"}, {"sport": "0"}):
            with self.assertRaises(ValidationError, msg=bad):
                v.validate_packet_filter(bad, IFACES)


if __name__ == "__main__":
    unittest.main()
