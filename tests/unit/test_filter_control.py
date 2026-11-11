"""
Тесты совместимости IPC-протокола модуля filter (ПС-1) со стандартным fwcommon.protocol.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "common"))
from fwcommon import protocol  # noqa: E402


class FilterControlProtocolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Путь к бинарнику test_control
        base = os.path.join(os.path.dirname(__file__), "..", "..", "filter")
        cls.bin_path = os.path.join(base, "tests", "test_control")
        if not os.path.exists(cls.bin_path):
            subprocess.check_call(["make", "-C", base, "tests/test_control"])

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sock_path = os.path.join(self.tmpdir.name, "filter.sock")
        self.logd_sock_path = os.path.join(self.tmpdir.name, "logd.sock")

        # Запустить C-сервер управления
        self.proc = subprocess.Popen(
            [self.bin_path, "--server", self.sock_path, self.logd_sock_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Дождаться сигнала готовности READY
        ready = False
        for _ in range(50):
            line = self.proc.stdout.readline()
            if "READY" in line:
                ready = True
                break
            time.sleep(0.05)
        self.assertTrue(ready, "C control server failed to start")

    def tearDown(self):
        if self.proc:
            if self.proc.poll() is None:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            if self.proc.stdout:
                self.proc.stdout.close()
            if self.proc.stderr:
                self.proc.stderr.close()
        self.tmpdir.cleanup()

    def test_state_status_and_deduplication(self):
        """Проверка запроса state.status и дедупликации повторных msg_id."""
        msg = protocol.make_msg("request", "cli", "filter", "state.status")
        r1 = protocol._exchange(self.sock_path, msg, timeout=2)
        r2 = protocol._exchange(self.sock_path, msg, timeout=2)

        self.assertEqual(r1["status"], "ok")
        self.assertEqual(r1["reply_to"], msg["msg_id"])
        self.assertEqual(r1, r2)
        self.assertTrue(r1["payload"]["enabled"])
        self.assertFalse(r1["payload"]["emergency_mode"])

    def test_state_enable_disable(self):
        """Проверка команд включения/отключения conntrack."""
        r_dis = protocol.request(self.sock_path, "cli", "filter", "state.disable")
        self.assertEqual(r_dis["status"], "ok")
        self.assertFalse(r_dis["payload"]["enabled"])

        r_st = protocol.request(self.sock_path, "cli", "filter", "state.status")
        self.assertFalse(r_st["payload"]["enabled"])

        r_en = protocol.request(self.sock_path, "cli", "filter", "state.enable")
        self.assertEqual(r_en["status"], "ok")
        self.assertTrue(r_en["payload"]["enabled"])

        r_st2 = protocol.request(self.sock_path, "cli", "filter", "state.status")
        self.assertTrue(r_st2["payload"]["enabled"])

    def test_rule_replace_and_get(self):
        """Проверка загрузки и выгрузки правил через rule.replace и rule.get."""
        rules = [
            {
                "id": 10,
                "active": True,
                "log": True,
                "in_iface": 0,
                "smac": None,
                "dmac": None,
                "src": "10.1.2.0/24",
                "dst": "192.168.1.100",
                "proto": "tcp",
                "eth_proto": "any",
                "sport": "1024-65535",
                "dport": 80,
                "action": "accept",
                "out_ifaces": [1],
                "conntrack": True,
                "comment": "Allow web traffic"
            },
            {
                "id": 20,
                "active": True,
                "log": False,
                "in_iface": 1,
                "src": None,
                "dst": None,
                "proto": 0,
                "action": "drop",
                "comment": "Default drop rule 20"
            }
        ]

        resp = protocol.request(self.sock_path, "cli", "filter", "rule.replace", {"rules": rules})
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["payload"]["rule_count"], 2)

        r_get = protocol.request(self.sock_path, "cli", "filter", "rule.get")
        self.assertEqual(r_get["status"], "ok")
        rules_got = r_get["payload"]["rules"]
        self.assertEqual(len(rules_got), 2)
        self.assertEqual(rules_got[0]["id"], 10)
        self.assertEqual(rules_got[0]["action"], "accept")
        self.assertEqual(rules_got[0]["comment"], "Allow web traffic")
        self.assertEqual(rules_got[1]["id"], 20)
        self.assertEqual(rules_got[1]["action"], "drop")

    def test_rule_replace_by_path(self):
        """Проверка загрузки правил через rule.replace по пути к файлу (path)."""
        rules = [
            {"id": 100, "active": True, "action": "accept", "in_iface": 0, "out_ifaces": [1]},
            {"id": 200, "active": True, "action": "drop"}
        ]
        # 1. Успешная загрузка через JSON-файл с объектом {"rules": [...]}
        pol_path = os.path.join(self.tmpdir.name, "policy.json")
        with open(pol_path, "w", encoding="utf-8") as f:
            json.dump({"rules": rules}, f)

        resp = protocol.request(self.sock_path, "cli", "filter", "rule.replace", {"path": pol_path})
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["payload"]["rule_count"], 2)

        # 2. Успешная загрузка через JSON-файл с массивом [...]
        pol_arr_path = os.path.join(self.tmpdir.name, "policy_arr.json")
        with open(pol_arr_path, "w", encoding="utf-8") as f:
            json.dump(rules, f)

        resp2 = protocol.request(self.sock_path, "cli", "filter", "rule.replace", {"path": pol_arr_path})
        self.assertEqual(resp2["status"], "ok")
        self.assertEqual(resp2["payload"]["rule_count"], 2)

        # 3. Ошибка несуществующего пути -> M06
        with self.assertRaises(protocol.ProtocolError) as cm:
            protocol.request(self.sock_path, "cli", "filter", "rule.replace",
                             {"path": "/tmp/nonexistent_policy_file_xyz.json"})
        self.assertEqual(cm.exception.code, "M06")

        # 4. Ошибка битого JSON в файле -> M06
        broken_path = os.path.join(self.tmpdir.name, "broken.json")
        with open(broken_path, "w", encoding="utf-8") as f:
            f.write("invalid json {")

        with self.assertRaises(protocol.ProtocolError) as cm:
            protocol.request(self.sock_path, "cli", "filter", "rule.replace", {"path": broken_path})
        self.assertEqual(cm.exception.code, "M06")

    def test_traffic_block_unblock(self):
        """Проверка команд аварийного режима от ПС-6 (traffic.block / traffic.unblock)."""
        r_blk = protocol.request(self.sock_path, "integrityd", "filter", "traffic.block")
        self.assertEqual(r_blk["status"], "ok")
        self.assertTrue(r_blk["payload"]["blocked"])

        r_st = protocol.request(self.sock_path, "cli", "filter", "state.status")
        self.assertTrue(r_st["payload"]["emergency_mode"])

        r_unblk = protocol.request(self.sock_path, "integrityd", "filter", "traffic.unblock")
        self.assertEqual(r_unblk["status"], "ok")
        self.assertFalse(r_unblk["payload"]["blocked"])

        r_st2 = protocol.request(self.sock_path, "cli", "filter", "state.status")
        self.assertFalse(r_st2["payload"]["emergency_mode"])

    def test_state_delete_and_clear(self):
        """Проверка очистки и удаления записей таблицы состояний."""
        r_clr = protocol.request(self.sock_path, "cli", "filter", "state.clear")
        self.assertEqual(r_clr["status"], "ok")

        r_del_all = protocol.request(self.sock_path, "cli", "filter", "state.delete_all")
        self.assertEqual(r_del_all["status"], "ok")

        with self.assertRaises(protocol.ProtocolError) as cm:
            protocol.request(self.sock_path, "cli", "filter", "state.delete", {"conn_id": 12345})
        self.assertEqual(cm.exception.code, "M13")

    def test_stats_get(self):
        """Проверка возврата счетчиков пакетов и сессий."""
        r_stats = protocol.request(self.sock_path, "cli", "filter", "stats.get")
        self.assertEqual(r_stats["status"], "ok")
        pl = r_stats["payload"]
        self.assertIn("rx_packets", pl)
        self.assertIn("tx_packets", pl)
        self.assertIn("drop_packets", pl)
        self.assertIn("active_rules", pl)
        self.assertIn("active_sessions", pl)
        self.assertIn("pktlog_dropped", pl)

    def test_state_list_basic(self):
        """Проверка команды state.list."""
        r_list = protocol.request(self.sock_path, "cli", "filter", "state.list")
        self.assertEqual(r_list["status"], "ok")
        self.assertIn("entries", r_list["payload"])

    def test_fw_filter_standalone_run_and_mgmt_rejection(self):
        """
        Проверка запуска fw-filter без root и без фильтрующих интерфейсов,
        с сокетом из FW_RUN_DIR, а также отклонения правил с управляющим интерфейсом (M06).
        """
        filter_bin = os.path.join(os.path.dirname(__file__), "..", "..", "filter", "fw-filter")
        if not os.path.exists(filter_bin):
            subprocess.check_call(["make", "-C", os.path.dirname(filter_bin)])

        with tempfile.TemporaryDirectory() as run_dir:
            # Создаем config.json только с одним управляющим интерфейсом eth0
            cfg_path = os.path.join(run_dir, "config.json")
            import json
            cfg_data = {
                "ifaces": [
                    {
                        "name": "eth0",
                        "enabled": True,
                        "is_mgmt": True
                    }
                ]
            }
            with open(cfg_path, "w") as f:
                json.dump(cfg_data, f)

            env = os.environ.copy()
            env["FW_RUN_DIR"] = run_dir

            sock_path = os.path.join(run_dir, "filter.sock")

            # Запуск fw-filter от обычного пользователя (без root)
            proc = subprocess.Popen(
                [filter_bin, "--config", cfg_path],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            try:
                # Ожидание появления управляющего сокета
                ready = False
                for _ in range(50):
                    if os.path.exists(sock_path):
                        ready = True
                        break
                    time.sleep(0.05)
                self.assertTrue(ready, "filter.sock was not created in FW_RUN_DIR")

                # 1. Проверка опроса state.status через сокет из FW_RUN_DIR
                st = protocol.request(sock_path, "cli", "filter", "state.status")
                self.assertEqual(st["status"], "ok")
                self.assertTrue(st["payload"]["enabled"])

                # 2. Правило с входным управляющим интерфейсом отклоняется с M06
                bad_in = [{"id": 10, "active": True, "action": "drop", "in_iface": 0}]
                with self.assertRaises(protocol.ProtocolError) as cm:
                    protocol.request(sock_path, "cli", "filter", "rule.replace", {"rules": bad_in})
                self.assertEqual(cm.exception.code, "M06")

                # Правило с управляющим интерфейсом по имени eth0 отклоняется с M06
                bad_in_name = [{"id": 11, "active": True, "action": "drop", "in": "eth0"}]
                with self.assertRaises(protocol.ProtocolError) as cm:
                    protocol.request(sock_path, "cli", "filter", "rule.replace", {"rules": bad_in_name})
                self.assertEqual(cm.exception.code, "M06")

                # Правило с выходным управляющим интерфейсом отклоняется с M06
                bad_out = [{"id": 12, "active": True, "action": "accept", "out_ifaces": [0]}]
                with self.assertRaises(protocol.ProtocolError) as cm:
                    protocol.request(sock_path, "cli", "filter", "rule.replace", {"rules": bad_out})
                self.assertEqual(cm.exception.code, "M06")

                # 3. state.list возвращает корректную структуру
                s_list = protocol.request(sock_path, "cli", "filter", "state.list")
                self.assertEqual(s_list["status"], "ok")
                self.assertIn("entries", s_list["payload"])

            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                if proc.stdout: proc.stdout.close()
                if proc.stderr: proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
