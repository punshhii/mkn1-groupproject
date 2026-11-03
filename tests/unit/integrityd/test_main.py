"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      test_main
Назначение:  unit-тесты команд integrity.* и запуска службы (FR-04, FR-46, FR-48, FR-49)
Методы:
  - FakeEmergency — запись обращений к режиму вместо emergency.Emergency
  - AccessTest — источники команд и неизвестные команды
  - StatusTest — integrity.status отвечает сразу и не запускает проверку
  - CheckCommandTest — integrity.check и E42
  - RestoreCommandTest — integrity.restore, повторная проверка, выход из режима
  - UpdateBaselineCommandTest — integrity.update_baseline, M10 в аварийном режиме
  - DaemonTest — порядок запуска службы
"""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fwcommon import codes
from fw_integrityd import __main__ as main
from fw_integrityd import checker, hasher, restore

KEY = b"k" * 32


class FakeEmergency:
    def __init__(self, active=False):
        self.active = active
        self.events = []
        self.calls = []

    def is_active(self):
        return self.active

    def on_check(self, result):
        self.calls.append(("on_check", result["ok"]))
        if not result["ok"]:
            self.active = True

    def leave(self):
        self.calls.append(("leave",))
        self.active = False

    def log_event(self, code, result, details=None, command=None):
        self.events.append((code, result, details, command))


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.tmp.name
        self.a = os.path.join(d, "a.json")
        self.b = os.path.join(d, "b.bin")
        for path in (self.a, self.b):
            with open(path, "wb") as f:
                f.write(path.encode())
        self.config = {"baseline_path": os.path.join(d, "baseline.json"), "backup_dir": os.path.join(d, "backup"),
                       "hmac_key_path": os.path.join(d, "hmac.key"), "check_period_sec": 60,
                       "files": [self.a, self.b]}
        with open(self.config["hmac_key_path"], "wb") as f:
            f.write(KEY)
        hasher.save_baseline(self.config["baseline_path"],
                             {p: hasher.sha256_file(p) for p in (self.a, self.b)}, KEY)
        self.em = FakeEmergency()
        self.checker = checker.Checker(self.config, on_result=self.em.on_check)
        self.checker.check()

    def handle(self, cmd, src="cli", payload=None):
        return main.handle({"cmd": cmd, "src": src, "payload": payload or {}}, self.checker, self.em)


class AccessTest(Fixture):
    def test_unknown_command(self):
        """Неизвестная команда: M14."""
        self.assertEqual(self.handle("integrity.delete")[:3], ("error", {}, "M14"))

    def test_wrong_source(self):
        """Источник вне таблицы входящих команд ПС-6 (с. 36): M14."""
        self.assertEqual(self.handle("integrity.status", src="filter")[2], "M14")
        self.assertEqual(self.handle("integrity.check", src="authd")[2], "M14")

    def test_allowed_sources(self):
        """ПС-3 и ПС-4 вызывают все команды, ПС-5 — только update_baseline (с. 36)."""
        for src in ("cli", "web"):
            self.assertEqual(self.handle("integrity.status", src=src)[0], "ok")
        with mock.patch.object(checker.Checker, "update_baseline"):
            self.assertEqual(self.handle("integrity.update_baseline", src="authd")[0], "ok")


class StatusTest(Fixture):
    def test_result_and_mode(self):
        """integrity.status: результат последней проверки и режим."""
        status, payload, code, _ = self.handle("integrity.status")
        self.assertEqual((status, code), ("ok", None))
        self.assertEqual(payload["mode"], "normal")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["last_check_ts"], self.checker.last_result()["last_check_ts"])
        self.assertEqual(len(payload["files"]), 2)

    def test_emergency_mode(self):
        """В аварийном режиме поле mode равно emergency: ПС-3 и ПС-4 видят это сразу."""
        self.em.active = True
        self.assertEqual(self.handle("integrity.status")[1]["mode"], "emergency")

    def test_no_check(self):
        """integrity.status не запускает проверку и не регистрирует событий."""
        with mock.patch.object(checker, "compare") as compare, mock.patch.object(hasher, "sha256_file") as sha:
            self.handle("integrity.status")
        compare.assert_not_called()
        sha.assert_not_called()
        self.assertEqual(self.em.events, [])

    def test_does_not_wait_for_running_check(self):
        """Идущая проверка держит блокировку: integrity.status всё равно отвечает."""
        with self.checker._lock:
            self.assertEqual(self.handle("integrity.status")[0], "ok")

    def test_last_result_not_changed(self):
        """Ответ не меняет сохранённый результат проверки."""
        self.handle("integrity.status")
        self.assertNotIn("mode", self.checker.last_result())


class CheckCommandTest(Fixture):
    def test_ok(self):
        """integrity.check: новая проверка, E42 с успешным результатом (FR-46)."""
        status, payload, _, _ = self.handle("integrity.check")
        self.assertEqual(status, "ok")
        self.assertEqual(payload["mode"], "normal")
        self.assertEqual(self.em.events, [("E42", True, {"baseline_error": None, "files": []}, "integrity.check")])

    def test_violation(self):
        """Нарушение: файл в ответе, режим аварийный, E42 с неуспешным результатом (FR-48)."""
        os.remove(self.a)
        status, payload, _, _ = self.handle("integrity.check")
        self.assertEqual(status, "ok")
        self.assertEqual(payload["mode"], "emergency")
        self.assertFalse(payload["ok"])
        self.assertEqual(self.em.events[0][:2], ("E42", False))
        self.assertEqual(self.em.events[0][2]["files"], [{"path": self.a, "status": "missing"}])

    def test_allowed_in_emergency(self):
        """В аварийном режиме проверка разрешена (FR-49) и из него не выводит."""
        self.em.active = True
        self.assertEqual(self.handle("integrity.check")[0], "ok")
        self.assertNotIn(("leave",), self.em.calls)


@unittest.skipIf(os.name == "nt", "пути POSIX")
class RestoreCommandTest(Fixture):
    def setUp(self):
        super().setUp()
        for path in (self.a, self.b):
            restore.update_backup(self.config["backup_dir"], path)
        patcher = mock.patch.object(restore.subprocess, "run", self.fake_fw_restore)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.restored = []

    def fake_fw_restore(self, cmd, **kwargs):
        path = cmd[-1]
        self.restored.append(path)
        shutil.copyfile(restore.backup_path(self.config["backup_dir"], path), path)

    def tamper(self, path):
        with open(path, "ab") as f:
            f.write(b"x")

    def test_restore_file(self):
        """Копия совпала: файл заменён, проверка повторена, выход из режима (FR-49)."""
        self.tamper(self.a)
        self.checker.check()
        status, payload, code, _ = self.handle("integrity.restore", payload={"file": self.a})
        self.assertEqual((status, code), ("ok", None))
        self.assertEqual(payload["mode"], "normal")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["errors"], [])
        self.assertEqual(self.restored, [self.a])
        self.assertIn(("leave",), self.em.calls)

    def test_restore_all(self):
        """all: восстанавливаются только нарушенные файлы."""
        self.tamper(self.a)
        self.checker.check()
        self.assertEqual(self.handle("integrity.restore", payload={"file": "all"})[0], "ok")
        self.assertEqual(self.restored, [self.a])

    def test_still_violated(self):
        """Восстановлен не последний нарушенный файл: M08, режим остаётся аварийным."""
        self.tamper(self.a)
        self.tamper(self.b)
        self.checker.check()
        status, payload, code, message = self.handle("integrity.restore", payload={"file": self.a})
        self.assertEqual((status, code, message), ("error", "M08", codes.message_text("M08")))
        self.assertEqual(payload["mode"], "emergency")
        self.assertNotIn(("leave",), self.em.calls)

    def test_bad_backup_not_used(self):
        """Копия не совпала с эталоном: файл не заменяется, M08, причина в errors (FR-49)."""
        self.tamper(self.a)
        self.tamper(restore.backup_path(self.config["backup_dir"], self.a))
        self.checker.check()
        status, payload, code, _ = self.handle("integrity.restore", payload={"file": "all"})
        self.assertEqual((status, code), ("error", "M08"))
        self.assertEqual(self.restored, [])
        self.assertEqual([e["path"] for e in payload["errors"]], [self.a])
        self.assertTrue(self.em.active)

    def test_all_continues_after_bad_backup(self):
        """all: плохая копия одного файла не мешает восстановить остальные."""
        self.tamper(self.a)
        self.tamper(self.b)
        self.tamper(restore.backup_path(self.config["backup_dir"], self.a))
        self.checker.check()
        self.assertEqual(self.handle("integrity.restore", payload={"file": "all"})[2], "M08")
        self.assertEqual(self.restored, [self.b])

    def test_planted_file(self):
        """Подложенный файл без записи в эталоне не удаляется: M08, режим аварийный."""
        planted = os.path.join(self.tmp.name, "planted.json")
        with open(planted, "wb") as f:
            f.write(b"{}")
        self.config["files"].append(planted)
        self.checker.check()
        self.assertEqual(self.handle("integrity.restore", payload={"file": "all"})[2], "M08")
        self.assertTrue(os.path.exists(planted))
        self.assertTrue(self.em.active)

    def test_bad_baseline(self):
        """Нарушен HMAC эталона: сверять копии не с чем, файлы не заменяются."""
        with open(self.config["hmac_key_path"], "wb") as f:
            f.write(b"x" * 32)
        self.checker.check()
        status, payload, code, _ = self.handle("integrity.restore", payload={"file": "all"})
        self.assertEqual((status, code), ("error", "M08"))
        self.assertEqual(self.restored, [])
        self.assertEqual(payload["errors"][0]["path"], self.config["baseline_path"])

    def test_bad_target(self):
        """Файл вне integrityd.files и неверный payload: M06, файловых операций нет (с. 30)."""
        for payload in ({"file": "/etc/passwd"}, {"file": None}, {"file": ["all"]}, {}, "all"):
            result = main.handle({"cmd": "integrity.restore", "src": "cli", "payload": payload},
                                 self.checker, self.em) if isinstance(payload, str) \
                else self.handle("integrity.restore", payload=payload or {})
            self.assertEqual(result[2], "M06", msg=payload)
        self.assertEqual(self.restored, [])


class UpdateBaselineCommandTest(Fixture):
    def test_ok(self):
        """Штатный режим: эталон обновляется по источнику (FR-47)."""
        with mock.patch.object(checker.Checker, "update_baseline") as update:
            self.assertEqual(self.handle("integrity.update_baseline", src="authd", payload={})[0], "ok")
        update.assert_called_once_with("authd")

    def test_rejected_in_emergency(self):
        """Аварийный режим: M10, эталон не меняется (FR-49)."""
        self.em.active = True
        with mock.patch.object(checker.Checker, "update_baseline") as update:
            status, _, code, message = self.handle("integrity.update_baseline")
        self.assertEqual((status, code, message), ("error", "M10", codes.message_text("M10")))
        update.assert_not_called()

    def test_failure(self):
        """Сбой обновления возвращается ответом, а не исключением."""
        for error in (hasher.BaselineError("HMAC"), OSError("нет файла")):
            with mock.patch.object(checker.Checker, "update_baseline", side_effect=error):
                self.assertEqual(self.handle("integrity.update_baseline")[0], "error")


class DaemonTest(Fixture):
    def write_config(self):
        path = os.path.join(self.tmp.name, "config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"integrityd": self.config}, f)
        return path

    def run_daemon(self, em):
        order = []
        server = mock.Mock()
        server.serve_forever.side_effect = lambda: order.append("serve_forever")

        def serve(path, name, handler):
            order.append("serve")
            self.assertEqual((path, name), (main.SOCK_PATH, "integrityd"))
            return server

        em.start = lambda: order.append("start")
        real = em.on_check
        em.on_check = lambda result: (order.append(("check", result["ok"])), real(result))
        with mock.patch.object(main, "Emergency", return_value=em), mock.patch.object(main.protocol, "serve", serve), \
                mock.patch.object(checker.Checker, "start_periodic", lambda _: order.append("periodic")):
            code = main.main(["--config", self.write_config()])
        return code, order

    def test_order(self):
        """Запуск: проверка до сервера (status всегда с результатом), затем таймер и сервер (FR-46)."""
        code, order = self.run_daemon(FakeEmergency())
        self.assertEqual(code, 0)
        self.assertEqual(order, ["start", ("check", True), "serve", "periodic", "serve_forever"])

    def test_violation_at_start(self):
        """Нарушение при запуске сразу включает режим (FR-04)."""
        os.remove(self.a)
        em = FakeEmergency()
        _, order = self.run_daemon(em)
        self.assertIn(("check", False), order)
        self.assertTrue(em.active)

    def test_bad_config(self):
        """Конфигурация не прочитана: код 2, трафик не разрешается, служба не работает (FR-04)."""
        err = io.StringIO()
        with mock.patch.object(main, "Emergency") as emergency_cls, contextlib.redirect_stderr(err):
            code = main.main(["--config", os.path.join(self.tmp.name, "no-such.json")])
        self.assertEqual(code, 2)
        emergency_cls.assert_not_called()


if __name__ == "__main__":
    unittest.main()
