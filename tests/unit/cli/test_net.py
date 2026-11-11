"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      test_net
Назначение:  тесты групп if и route: if list с колонкой «управляющий /
             фильтрующий», if ip и route только для управляющего интерфейса
             (M06), M13, E33, права через ПС-5 (M03), аварийный режим (M10),
             разбор вывода ip -j и фиксированный список команд sudo (SystemNet),
             управляющие интерфейсы из config.json (is_mgmt)
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "stand"))

import mock_core  # noqa: E402
from fw_cli import core, net, parser  # noqa: E402


class NetStandTest(unittest.TestCase):
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
        self.core = core.Core(run_dir=self.dir, ifaces=["eth0", "eth1", "eth2"], mgmt=["eth0"],
                              os_net=net.SocketNet(os.path.join(self.dir, "os.sock")),
                              event_retry=False)
        self.admin = self.core.login("admin", "admin123", ip="10.0.0.5")

    def run_cmd(self, line, sess=None):
        return self.core.execute(parser.parse(line), sess or self.admin, confirm=lambda: True)

    def e33(self, n):
        end = time.monotonic() + 2
        while time.monotonic() < end and len(mock_core.events("E33")) < n:
            time.sleep(0.01)
        return mock_core.events("E33")

    def test_if_list_kind_column(self):
        out = self.run_cmd("if list").render()
        self.assertIn("Управляющий / фильтрующий", out)
        lines = {ln.split()[0]: ln for ln in out.splitlines()[2:]}
        self.assertIn("управляющий", lines["eth0"])
        self.assertIn("192.168.1.1/24", lines["eth0"])
        self.assertIn("фильтрующий", lines["eth1"])
        self.assertIn("фильтрующий", self.run_cmd("if show eth2").render())

    def test_if_ip_only_management(self):
        r = self.run_cmd("if ip eth1 10.0.0.1/24")
        self.assertEqual(r.code, "M06")
        self.assertIn("управляющий интерфейс: eth0", r.text)
        self.assertIsNone(mock_core._state["net"]["links"]["eth1"]["addr"])
        self.assertEqual(self.run_cmd("if ip eth0 192.168.1.2/24").code, "M09")
        self.assertEqual(mock_core._state["net"]["links"]["eth0"]["addr"], "192.168.1.2/24")
        e = self.e33(1)[-1]
        self.assertEqual((e["cmd"], e["iface"], e["ip"]), ("if ip", "eth0", "10.0.0.5"))

    def test_if_up_down_any_interface(self):
        self.assertEqual(self.run_cmd("if up eth2").code, "M09")
        self.assertEqual(mock_core._state["net"]["links"]["eth2"]["state"], "up")
        self.assertEqual(self.run_cmd("if down eth1").code, "M09")
        self.assertEqual(self.run_cmd("if up eth9").code, "M06")

    def test_route_add_only_via_management(self):
        self.assertEqual(self.run_cmd("route add 10.20.0.0/16 192.168.1.254").code, "M09")
        self.assertIn({"dst": "10.20.0.0/16", "gw": "192.168.1.254", "dev": "eth0"},
                      mock_core._state["net"]["routes"])
        r = self.run_cmd("route add 10.30.0.0/16 10.10.0.1")   # шлюз в сети фильтрующего eth1
        self.assertEqual(r.code, "M06")
        self.assertIn("eth0 (192.168.1.1/24)", r.text)

    def test_route_del_only_management(self):
        self.assertEqual(self.run_cmd("route del 10.10.0.0/16").code, "M06")   # через eth1
        self.assertEqual(self.run_cmd("route del 172.16.0.0/12").code, "M13")
        self.assertEqual(self.run_cmd("route del 192.168.1.0/24").code, "M09")
        out = self.run_cmd("route list").render()
        self.assertNotIn("192.168.1.0/24", out)
        self.assertIn("фильтрующий", out)                                      # 10.10.0.0/16 dev eth1

    def test_ro_denied_by_authd(self):
        viewer = self.core.login("viewer", "viewer123", ip="10.0.0.6")
        self.assertFalse(self.run_cmd("if list", viewer).error)
        self.assertEqual(self.run_cmd("if ip eth0 192.168.1.9/24", viewer).code, "M03")
        self.assertEqual(self.run_cmd("route add 10.20.0.0/16 192.168.1.254", viewer).code, "M03")

    def test_emergency_m10(self):
        mock_core.set_broken("/etc/fw/config.json")
        self.assertEqual(self.run_cmd("if ip eth0 192.168.1.2/24").code, "M10")
        self.assertEqual(self.run_cmd("route del 192.168.1.0/24").code, "M10")
        self.assertFalse(self.run_cmd("if list").error)

    def test_os_failure_m16(self):
        broken = core.Core(run_dir=self.dir, ifaces=["eth0"], mgmt=["eth0"], event_retry=False,
                           os_net=net.SocketNet(os.path.join(self.dir, "нет.sock")))
        r = broken.execute(parser.parse("if list"), self.admin)
        self.assertEqual(r.code, "M16")
        self.assertIn("ОС", r.text)


IP_ADDR = [
    {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "address": "00:00:00:00:00:00",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
    {"ifname": "eth0", "flags": ["BROADCAST", "UP", "LOWER_UP"], "address": "52:54:00:00:00:01",
     "addr_info": [{"family": "inet6", "local": "fe80::1", "prefixlen": 64},
                   {"family": "inet", "local": "192.168.65.142", "prefixlen": 24}],
     "stats64": {"rx": {"bytes": 100}, "tx": {"bytes": 200}}},
    {"ifname": "eth1", "flags": ["BROADCAST"], "address": "52:54:00:00:00:02", "addr_info": []},
]
IP_ROUTE = [{"dst": "default", "gateway": "192.168.65.2", "dev": "eth0"},
            {"dst": "192.168.65.0/24", "dev": "eth0"}]


class SystemNetTest(unittest.TestCase):
    def fake(self, calls):
        def run(cmd, **kw):
            calls.append(cmd)
            out = json.dumps(IP_ROUTE if "route" in cmd and "show" in cmd else IP_ADDR)
            return subprocess.CompletedProcess(cmd, 0, out, "")
        return run

    def test_parse_and_fixed_sudo_commands(self):
        calls = []
        with mock.patch.object(net.subprocess, "run", self.fake(calls)):
            n = net.SystemNet()
            links = {i["name"]: i for i in n.links()}
            self.assertEqual(links["eth0"]["addr"], "192.168.65.142/24")
            self.assertEqual((links["eth0"]["state"], links["eth0"]["rx_bytes"]), ("up", 100))
            self.assertEqual((links["eth1"]["state"], links["eth1"]["addr"]), ("down", None))
            self.assertEqual(n.routes()[0], {"dst": "default", "gw": "192.168.65.2", "dev": "eth0"})
            self.assertEqual(calls[0][0], net.IP)            # чтение — без sudo
            calls.clear()
            n.set_addr("eth0", "192.168.65.10/24")
            n.add_route("10.0.0.0/8", "192.168.65.2", "eth0")
            n.del_route("10.0.0.0/8")
            n.set_link("eth1", False)
        self.assertTrue(all(c[:3] == ["sudo", "-n", net.IP] for c in calls))
        self.assertEqual([c[3:] for c in calls], [
            ["addr", "flush", "dev", "eth0"], ["addr", "add", "192.168.65.10/24", "dev", "eth0"],
            ["route", "add", "10.0.0.0/8", "via", "192.168.65.2", "dev", "eth0"],
            ["route", "del", "10.0.0.0/8"], ["link", "set", "dev", "eth1", "down"]])

    def test_failure_raises_net_error(self):
        def run(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 1, "", "sudo: a password is required")
        with mock.patch.object(net.subprocess, "run", run):
            with self.assertRaises(net.NetError) as cm:
                net.SystemNet().set_link("eth0", True)
        self.assertIn("password", str(cm.exception))

    def test_in_subnet(self):
        self.assertTrue(net.in_subnet("192.168.1.254", "192.168.1.1/24"))
        self.assertFalse(net.in_subnet("10.10.0.1", "192.168.1.1/24"))
        self.assertFalse(net.in_subnet("мусор", "192.168.1.1/24"))


class ConfigTest(unittest.TestCase):
    def test_load_mgmt_from_config(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({"ifaces": [{"name": "eth0", "is_mgmt": 1}, {"name": "eth1", "is_mgmt": 0},
                                  {"name": "eth2"}, "мусор"]}, f)
        try:
            self.assertEqual(core.load_ifaces(f.name), ["eth0", "eth1", "eth2"])
            self.assertEqual(core.load_mgmt(f.name), ["eth0"])
        finally:
            os.unlink(f.name)
        self.assertEqual(core.load_mgmt("/нет/такого.json"), [])


if __name__ == "__main__":
    unittest.main()
