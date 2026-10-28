"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  тестовый стенд (tests/stand)
Модуль:      test_stand_codec
Назначение:  интеграционные тесты стенда: клиент fwcommon.protocol.request
             (как его вызывают ПС-3 CLI / ПС-4 web) против заглушек mock_core.
             ПС-5: вход, блокировка (FR-31), понижение прав (FR-34), таймаут
             сеанса (FR-35), учётные записи (FR-33, FR-36), auth.check (FR-32).
             ПС-1: rule.replace по пути к policy.json, счётчики неизменённых
             правил, удаление записей состояний (FR-23), state.*.
             ПС-2: выборки (FR-39), M06 на интервал, приём событий.
             ПС-6: аварийный режим и восстановление. Протокол: M14, M16.
Запуск:      python3 tests/stand/test_stand_codec.py
"""
import json
import os
import sys
import tempfile
import threading
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "common"))
sys.path.insert(0, _HERE)

from fwcommon import protocol  # noqa: E402
import mock_core  # noqa: E402


class _Stand(unittest.TestCase):
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

    def req(self, dst, cmd, payload=None, src="cli"):
        return protocol.request(os.path.join(self.dir, dst + ".sock"), src, dst, cmd, payload)

    def err(self, dst, cmd, payload=None):
        with self.assertRaises(protocol.ProtocolError) as cm:
            self.req(dst, cmd, payload)
        return cm.exception

    def login(self, uid="admin", pwd="admin123", src="cli"):
        return self.req("authd", "auth.login", {"id": uid, "password": pwd, "source": src},
                        src=src)["payload"]


class AuthdTest(_Stand):
    def test_login_ok(self):
        p = self.login()
        self.assertEqual(p["role"], "rw")
        self.assertFalse(p["downgraded"])
        self.assertEqual(len(p["session_id"]), 32)
        self.assertTrue(mock_core.events("E01"))

    def test_login_bad_password_m02_e03(self):
        e = self.err("authd", "auth.login", {"id": "admin", "password": "wrong-password"})
        self.assertEqual(e.code, "M02")
        self.assertTrue(mock_core.events("E03"))

    def test_lockout_after_five_failures_per_id(self):
        for _ in range(4):
            self.assertEqual(self.err("authd", "auth.login",
                                      {"id": "admin", "password": "x"}).code, "M02")
        self.assertEqual(self.err("authd", "auth.login",
                                  {"id": "admin", "password": "x"}).code, "M12")
        self.assertTrue(mock_core.events("E06"))
        # даже верный пароль во время блокировки — M12
        self.assertEqual(self.err("authd", "auth.login",
                                  {"id": "admin", "password": "admin123"}).code, "M12")
        # блокировка только для admin, viewer входит
        self.assertEqual(self.login("viewer", "viewer123")["role"], "ro")
        mock_core.advance_clock(61)
        self.assertEqual(self.login()["role"], "rw")

    def test_second_rw_downgraded_m04(self):
        self.login()
        p = self.login(src="web")
        self.assertEqual(p["role"], "ro")
        self.assertTrue(p["downgraded"])
        self.assertEqual(p["warning"], "M04")
        self.assertTrue(mock_core.events("E04"))

    def test_ping_and_idle_timeout_m15(self):
        sid = self.login()["session_id"]
        self.assertEqual(self.req("authd", "auth.ping", {"session_id": sid})["payload"]["status"],
                         "pong")
        mock_core.advance_clock(901)
        self.assertEqual(self.err("authd", "auth.ping", {"session_id": sid}).code, "M15")
        self.assertTrue(mock_core.events("E07"))

    def test_logout_e02(self):
        sid = self.login()["session_id"]
        self.req("authd", "auth.logout", {"session_id": sid})
        self.assertTrue(mock_core.events("E02"))
        self.assertEqual(self.err("authd", "auth.ping", {"session_id": sid}).code, "M15")

    def test_auth_check_ro_m03_e50(self):
        sid = self.login("viewer", "viewer123")["session_id"]
        ok = self.req("authd", "auth.check", {"session_id": sid, "cmd": "rule.get"})
        self.assertTrue(ok["payload"]["allowed"])
        e = self.err("authd", "auth.check", {"session_id": sid, "cmd": "rule.replace"})
        self.assertEqual(e.code, "M03")
        self.assertEqual(mock_core.events("E50")[-1]["cmd"], "rule.replace")

    def test_users_builtin_admin_m05(self):
        sid = self.login()["session_id"]
        self.assertEqual(self.err("authd", "user.delete",
                                  {"session_id": sid, "id": "admin"}).code, "M05")
        self.assertEqual(self.err("authd", "user.edit",
                                  {"session_id": sid, "id": "admin", "role": "ro"}).code, "M05")
        # смена пароля admin разрешена (FR-33)
        self.req("authd", "user.edit", {"session_id": sid, "id": "admin", "password": "newpass99"})

    def test_user_add_validation_m06(self):
        sid = self.login()["session_id"]
        for bad in ({"id": "ab", "password": "password1", "role": "ro"},
                    {"id": "оператор", "password": "password1", "role": "ro"},
                    {"id": "oper", "password": "short", "role": "ro"},
                    {"id": "oper", "password": "password1", "role": "admin"},
                    {"id": "viewer", "password": "password1", "role": "ro"}):
            bad["session_id"] = sid
            self.assertEqual(self.err("authd", "user.add", bad).code, "M06", bad)
        self.req("authd", "user.add",
                 {"session_id": sid, "id": "oper_1", "password": "password1", "role": "ro"})
        users = self.req("authd", "user.list", {"session_id": sid})["payload"]["users"]
        self.assertIn({"id": "oper_1", "role": "ro"}, users)
        self.assertNotIn("password", json.dumps(users))  # FR-37

    def test_user_delete_kills_sessions_e07(self):
        admin = self.login()["session_id"]
        viewer = self.login("viewer", "viewer123")["session_id"]
        self.req("authd", "user.delete", {"session_id": admin, "id": "viewer"})
        self.assertEqual(self.err("authd", "auth.ping", {"session_id": viewer}).code, "M15")

    def test_session_kill_e05(self):
        admin = self.login()["session_id"]
        viewer = self.login("viewer", "viewer123")["session_id"]
        sessions = self.req("authd", "session.list", {"session_id": admin})["payload"]["sessions"]
        self.assertEqual(len(sessions), 2)
        self.assertIn(viewer, [s["session_id"] for s in sessions])
        masked = self.req("authd", "session.list", {"session_id": viewer})["payload"]["sessions"]
        self.assertNotIn(admin, [s["session_id"] for s in masked])  # ro не видит полный id
        self.assertIn(admin[:8] + "…", [s["session_id"] for s in masked])
        self.assertEqual(self.err("authd", "session.kill",
                                  {"session_id": viewer, "target_session_id": admin}).code, "M03")
        self.req("authd", "session.kill", {"session_id": admin, "target_session_id": viewer})
        self.assertTrue(mock_core.events("E05"))


class FilterTest(_Stand):
    def policy(self, rules):
        path = os.path.join(self.dir, "policy.tmp.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"rules": rules}, fh)
        return path

    R1 = {"id": 1, "action": "accept", "in_iface": 0, "out_ifaces": [1], "proto": "tcp",
          "dport": 80, "conntrack": True, "log": True}
    R2 = {"id": 2, "action": "drop", "proto": "udp"}

    def test_replace_by_path_and_get(self):
        r = self.req("filter", "rule.replace", {"path": self.policy([self.R2, self.R1])})
        self.assertEqual(r["payload"]["rule_count"], 2)
        rules = self.req("filter", "rule.get")["payload"]["rules"]
        self.assertEqual([x["id"] for x in rules], [1, 2])
        self.assertEqual(rules[0]["hits"], 0)

    def test_replace_requires_path_not_inline_rules(self):
        self.assertEqual(self.err("filter", "rule.replace", {"rules": [self.R1]}).code, "M06")
        self.assertEqual(self.err("filter", "rule.replace",
                                  {"path": os.path.join(self.dir, "missing.json")}).code, "M06")

    def test_replace_validation(self):
        dup = self.err("filter", "rule.replace", {"path": self.policy([self.R2, dict(self.R2)])})
        self.assertEqual(dup.code, "M07")
        no_out = self.err("filter", "rule.replace",
                          {"path": self.policy([{"id": 3, "action": "accept"}])})
        self.assertEqual(no_out.code, "M06")
        loop = self.err("filter", "rule.replace", {"path": self.policy(
            [{"id": 5, "action": "goto", "to_rule": 2}, self.R2])})
        self.assertEqual(loop.code, "M06")  # переход только на больший номер
        in_out = dict(self.R1, out_ifaces=[0])
        self.assertEqual(self.err("filter", "rule.replace",
                                  {"path": self.policy([in_out])}).code, "M06")

    def test_hits_kept_for_unchanged_and_states_purged(self):
        # как ПС-3: прочитать таблицу, изменить правило 2, добавить 3, записать файл
        rules = self.req("filter", "rule.get")["payload"]["rules"]
        for r in rules:
            r.pop("hits")
        rules[1]["dport"] = 5353
        rules.append({"id": 3, "action": "drop", "proto": "icmp"})
        r = self.req("filter", "rule.replace", {"path": self.policy(rules)})
        got = self.req("filter", "rule.get")["payload"]["rules"]
        self.assertEqual([x["hits"] for x in got], [7, 0, 0])  # у правила 1 счётчик сохранён
        self.assertEqual(r["payload"]["purged_sessions"], 1)    # запись правила 2 удалена
        ids = [c["rule_id"] for c in self.req("filter", "state.list")["payload"]["entries"]]
        self.assertEqual(ids, [1])

    def test_disabled_rule_purges_states(self):
        rules = self.req("filter", "rule.get")["payload"]["rules"]
        for r in rules:
            r.pop("hits")
        rules[0]["active"] = False
        r = self.req("filter", "rule.replace", {"path": self.policy(rules)})
        self.assertEqual(r["payload"]["purged_sessions"], 1)

    def test_state_commands(self):
        self.assertEqual(len(self.req("filter", "state.list")["payload"]["entries"]), 2)
        self.assertEqual(self.err("filter", "state.delete", {"conn_id": 99}).code, "M13")
        self.req("filter", "state.delete", {"conn_id": 1})
        self.req("filter", "state.disable")
        st = self.req("filter", "state.status")["payload"]
        self.assertFalse(st["enabled"])
        self.assertEqual(st["active_sessions"], 0)
        self.req("filter", "state.enable")
        self.assertTrue(mock_core.events("E15") and mock_core.events("E14"))


class LogdTest(_Stand):
    def test_events_query_and_interval_m06(self):
        r = self.req("logd", "log.query.events",
                     {"from_ts": "2026-10-20 00:00:00", "to_ts": "2026-10-21 00:00:00"})
        items = r["payload"]["items"]
        self.assertEqual(r["payload"]["total"], 3)
        self.assertEqual(items[0]["code"], "E03")  # от новых к старым
        e = self.err("logd", "log.query.events",
                     {"from_ts": "2026-10-21 00:00:00", "to_ts": "2026-10-20 00:00:00"})
        self.assertEqual(e.code, "M06")
        self.assertEqual(self.err("logd", "log.query.events", {"from_ts": "21.10.2026"}).code, "M06")

    def test_newest_first_within_same_second(self):
        sid = self.login()["session_id"]                  # E01
        self.req("authd", "auth.logout", {"session_id": sid})  # E02 в ту же секунду
        items = self.req("logd", "log.query.events")["payload"]["items"]
        self.assertEqual([i["code"] for i in items[:2]], ["E02", "E01"])

    def test_empty_selection_is_not_error(self):
        r = self.req("logd", "log.query.events", {"event_code": "E99"})
        self.assertEqual(r["payload"], {"items": [], "total": 0})  # клиент выводит M13

    def test_paging(self):
        r = self.req("logd", "log.query.events", {"page": 2, "page_size": 2})
        self.assertEqual(r["payload"]["total"], 3)
        self.assertEqual(len(r["payload"]["items"]), 1)
        self.assertEqual(self.err("logd", "log.query.events", {"page": 0}).code, "M06")

    def test_packets_filter_and_clear(self):
        r = self.req("logd", "log.query.packets", {"action": "drop"})
        self.assertEqual(r["payload"]["total"], 1)
        self.assertEqual(r["payload"]["items"][0]["rule_id"], 0)
        r = self.req("logd", "log.query.packets", {"out_iface": "eth1", "dport": 80})
        self.assertEqual(r["payload"]["total"], 1)
        self.assertEqual(self.err("logd", "log.query.packets", {"action": "pass"}).code, "M06")
        self.req("logd", "log.packets.clear")
        self.assertEqual(self.req("logd", "log.query.packets")["payload"]["total"], 0)

    def test_event_from_client_is_stored(self):
        done = threading.Event()
        protocol.send_event(os.path.join(self.dir, "logd.sock"), "cli", "logd",
                            "log.write.event", {"code": "E50", "actor": "viewer",
                                                "cmd": "rule add", "result": "fail"})
        for _ in range(50):
            if mock_core.events("E50"):
                done.set()
                break
            done.wait(0.02)
        self.assertTrue(done.is_set())
        self.assertEqual(mock_core.events("E50")[-1]["src"], "cli")


class IntegritydTest(_Stand):
    def test_emergency_and_restore(self):
        self.assertEqual(self.req("integrityd", "integrity.status")["payload"]["mode"], "normal")
        mock_core.set_broken("/etc/fw/policy.json")
        st = self.req("integrityd", "integrity.check")["payload"]
        self.assertEqual(st["mode"], "emergency")
        self.assertTrue(mock_core.events("E40") and mock_core.events("E42"))
        self.assertEqual(self.req("filter", "state.status")["payload"]["emergency_mode"], True)
        self.assertEqual(self.err("integrityd", "integrity.restore", {"file": "/etc/passwd"}).code,
                         "M06")
        st = self.req("integrityd", "integrity.restore", {"file": "all"})["payload"]
        self.assertEqual(st["mode"], "normal")
        self.assertTrue(mock_core.events("E41"))

    def test_update_baseline(self):
        self.assertTrue(self.req("integrityd", "integrity.update_baseline")["payload"]["updated"])


class ProtocolStandTest(_Stand):
    def test_unknown_command_m14(self):
        self.assertEqual(self.err("authd", "rule.dropall").code, "M14")

    def test_timeout_m16_after_retries(self):
        # задержка 1 с больше окна попыток 0.2 * 3 = 0.6 с -> детерминированный M16
        path = os.path.join(self.dir, "slow.sock")
        srv = protocol.serve(path, "authd",
                             mock_core.with_delay(mock_core.build_handlers("authd"), delay=1.0))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(protocol.ProtocolError) as cm:
                protocol.request(path, "cli", "authd", "auth.ping", timeout=0.2, retries=2)
            self.assertEqual(cm.exception.code, "M16")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_cli_and_web_same_msg_id_get_own_sessions(self):
        # раньше одинаковый msg_id от CLI и web давал web чужой session_id
        path = os.path.join(self.dir, "authd.sock")
        a = protocol._exchange(path, protocol.make_msg(
            "request", "cli", "authd", "auth.login",
            {"id": "admin", "password": "admin123"}, msg_id=1), 2)
        b = protocol._exchange(path, protocol.make_msg(
            "request", "web", "authd", "auth.login",
            {"id": "viewer", "password": "viewer123"}, msg_id=1), 2)
        self.assertEqual(a["payload"]["username"], "admin")
        self.assertEqual(b["payload"]["username"], "viewer")
        self.assertNotEqual(a["payload"]["session_id"], b["payload"]["session_id"])


if __name__ == "__main__":
    unittest.main()
