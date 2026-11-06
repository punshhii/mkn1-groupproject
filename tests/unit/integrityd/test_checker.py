import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from fw_integrityd import checker, hasher
from fw_integrityd import __main__ as main

KEY = b"k" * 32


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.a = os.path.join(d, "a.json")
        self.b = os.path.join(d, "b.bin")
        for path in (self.a, self.b):
            with open(path, "wb") as f:
                f.write(path.encode())
        self.config = {
            "baseline_path": os.path.join(d, "baseline.json"),
            "backup_dir": os.path.join(d, "backup"),
            "hmac_key_path": os.path.join(d, "hmac.key"),
            "check_period_sec": 60,
            "files": [self.a, self.b],
        }
        with open(self.config["hmac_key_path"], "wb") as f:
            f.write(KEY)
        hasher.save_baseline(self.config["baseline_path"],
                             {p: hasher.sha256_file(p) for p in (self.a, self.b)}, KEY)

    def tearDown(self):
        self.tmp.cleanup()

    def statuses(self, result):
        return {f["path"]: f["status"] for f in result["files"]}


class CheckerTest(Fixture):
    def test_ok(self):
        """Файлы не менялись: все ok, результат передан в on_result и last_result (FR-46)."""
        results = []
        c = checker.Checker(self.config, on_result=results.append)
        self.assertIsNone(c.last_result())
        r = c.check()
        self.assertTrue(r["ok"])
        self.assertIsNone(r["baseline_error"])
        self.assertEqual(self.statuses(r), {self.a: "ok", self.b: "ok"})
        self.assertIs(c.last_result(), r)
        self.assertEqual(results, [r])

    def test_mismatch(self):
        """Изменённый файл получает статус mismatch (FR-46)."""
        with open(self.a, "ab") as f:
            f.write(b"x")
        r = checker.Checker(self.config).check()
        self.assertFalse(r["ok"])
        self.assertEqual(self.statuses(r), {self.a: "mismatch", self.b: "ok"})

    def test_missing(self):
        """Удалённый файл получает статус missing (FR-46)."""
        os.remove(self.b)
        r = checker.Checker(self.config).check()
        self.assertFalse(r["ok"])
        self.assertEqual(self.statuses(r), {self.a: "ok", self.b: "missing"})

    def test_not_in_baseline(self):
        """Файл, которого нет в эталоне, получает статус mismatch."""
        extra = os.path.join(self.tmp.name, "c")
        open(extra, "wb").close()
        self.config["files"].append(extra)
        r = checker.Checker(self.config).check()
        self.assertFalse(r["ok"])
        self.assertEqual(self.statuses(r)[extra], "mismatch")

    def test_bad_hmac(self):
        """Чужой ключ: эталон не принят, нарушение (FR-47)."""
        with open(self.config["hmac_key_path"], "wb") as f:
            f.write(b"x" * 32)
        r = checker.Checker(self.config).check()
        self.assertFalse(r["ok"])
        self.assertTrue(r["baseline_error"])
        self.assertEqual(r["files"], [])

    def test_no_key(self):
        """Нет ключа HMAC: эталон не проверить, нарушение (FR-47)."""
        os.remove(self.config["hmac_key_path"])
        r = checker.Checker(self.config).check()
        self.assertFalse(r["ok"])
        self.assertTrue(r["baseline_error"])


class NotSavedTest(Fixture):
    def setUp(self):
        super().setUp()
        self.saved = os.path.join(self.tmp.name, "saved.json")
        self.config["files"].append(self.saved)
        patcher = mock.patch.object(checker, "SAVED_FILES", (self.saved,))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_not_saved(self):
        """Первый запуск: сохранённого файла и записи в эталоне нет — это не нарушение (FR-04)."""
        r = checker.Checker(self.config).check()
        self.assertTrue(r["ok"])
        self.assertEqual(self.statuses(r)[self.saved], "not_saved")

    def test_planted(self):
        """Файл появился без записи в эталоне: подложен, нарушение."""
        with open(self.saved, "wb") as f:
            f.write(b"{}")
        r = checker.Checker(self.config).check()
        self.assertFalse(r["ok"])
        self.assertEqual(self.statuses(r)[self.saved], "mismatch")

    def test_deleted_after_save(self):
        """Запись в эталоне есть, файла нет: удаление сохранённого файла — нарушение."""
        key = hasher.load_key(self.config["hmac_key_path"])
        baseline = hasher.load_baseline(self.config["baseline_path"], key)
        hasher.save_baseline(self.config["baseline_path"], dict(baseline, **{self.saved: "0" * 64}), key)
        r = checker.Checker(self.config).check()
        self.assertFalse(r["ok"])
        self.assertEqual(self.statuses(r)[self.saved], "missing")

    def test_unreadable(self):
        """Файл не читается (например, потерян ACL): это не not_saved, а нарушение."""
        with mock.patch.object(hasher, "sha256_file", side_effect=PermissionError("нет доступа")):
            self.assertEqual(checker.compare([self.saved], {}), [{"path": self.saved, "status": "missing"}])

    def test_other_file_without_baseline(self):
        """Статус not_saved только у файлов config save: другой файл без эталона — нарушение."""
        other = os.path.join(self.tmp.name, "other.bin")
        self.assertEqual(checker.compare([other], {}), [{"path": other, "status": "missing"}])


class UpdateBaselineTest(Fixture):
    def setUp(self):
        super().setUp()
        self.saved = os.path.join(self.tmp.name, "saved.json")
        self.config["files"].append(self.saved)
        patchers = (mock.patch.object(checker, "SAVED_FILES", (self.saved,)),
                    mock.patch.dict(checker.UPDATED_FILES, {"cli": (self.saved, self.a), "web": (self.saved, self.a),
                                                            "authd": (self.b,)}))
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.checker = checker.Checker(self.config)

    def write(self, path, data):
        with open(path, "wb") as f:
            f.write(data)

    def baseline(self):
        return hasher.load_baseline(self.config["baseline_path"], KEY)

    def backup(self, path):
        return os.path.join(self.config["backup_dir"], path.lstrip("/"))

    @unittest.skipIf(os.name == "nt", "пути POSIX")
    def test_first_save(self):
        """Первый config save: появляются запись и копия, затем удаление файла — нарушение (FR-41a, FR-50)."""
        self.assertEqual(self.statuses(self.checker.check())[self.saved], "not_saved")
        self.write(self.saved, b"{}")
        self.checker.update_baseline("cli")
        self.assertEqual(self.baseline()[self.saved], hasher.sha256_file(self.saved))
        self.assertEqual(hasher.sha256_file(self.backup(self.saved)), self.baseline()[self.saved])
        self.assertTrue(self.checker.check()["ok"])
        os.remove(self.saved)
        self.assertEqual(self.statuses(self.checker.check())[self.saved], "missing")

    @unittest.skipIf(os.name == "nt", "пути POSIX")
    def test_update_changed_file(self):
        """Штатное изменение не вызывает ложной тревоги, копия обновляется (FR-47, FR-50)."""
        self.write(self.saved, b"{}")
        self.write(self.a, b"new")
        self.assertFalse(self.checker.check()["ok"])
        self.checker.update_baseline("web")
        self.assertTrue(self.checker.check()["ok"])
        with open(self.backup(self.a), "rb") as f:
            self.assertEqual(f.read(), b"new")

    @unittest.skipIf(os.name == "nt", "пути POSIX")
    def test_only_files_of_src(self):
        """ПС-5 обновляет только свой файл: посторонняя подмена не становится штатной (FR-47)."""
        self.write(self.a, b"tampered")
        self.write(self.b, b"accounts")
        self.checker.update_baseline("authd")
        r = self.checker.check()
        self.assertEqual(self.statuses(r)[self.a], "mismatch")
        self.assertEqual(self.statuses(r)[self.b], "ok")
        self.assertFalse(os.path.exists(self.backup(self.a)))

    @unittest.skipIf(os.name == "nt", "пути POSIX")
    def test_file_not_controlled(self):
        """Файл источника вне integrityd.files не попадает в эталон."""
        self.config["files"].remove(self.saved)
        self.write(self.saved, b"{}")
        self.checker.update_baseline("cli")
        self.assertNotIn(self.saved, self.baseline())

    def test_bad_hmac(self):
        """Нарушенный HMAC не переподписывается: нарушение остаётся (FR-47)."""
        path = self.config["baseline_path"]
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["files"][self.a] = "0" * 64
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with open(path, "rb") as f:
            before = f.read()
        with self.assertRaises(hasher.BaselineError):
            self.checker.update_baseline("cli")
        with open(path, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertFalse(os.path.exists(self.config["backup_dir"]))

    def test_deleted_file(self):
        """Удалённый файл не исключается из эталона: ни эталон, ни копии не меняются."""
        self.write(self.saved, b"{}")
        os.remove(self.a)
        before = self.baseline()
        with self.assertRaises(OSError):
            self.checker.update_baseline("cli")
        self.assertEqual(self.baseline(), before)
        self.assertFalse(os.path.exists(self.config["backup_dir"]))

    def test_lock(self):
        """Эталон меняется под блокировкой: сервер многопоточный, проверка не видит середину обновления."""
        self.write(self.saved, b"{}")
        real_save, real_compare = hasher.save_baseline, checker.compare
        locked = []

        def save(*args):
            locked.append(self.checker._lock.locked())
            real_save(*args)

        def compare(*args):
            locked.append(self.checker._lock.locked())
            return real_compare(*args)

        with mock.patch.object(hasher, "save_baseline", save), mock.patch.object(checker, "compare", compare), \
                mock.patch.object(checker.restore, "update_backup"):
            self.checker.update_baseline("cli")
            self.checker.check()
        self.assertEqual(locked, [True, True])


class ViolationsTest(Fixture):
    def test_only_violations(self):
        """В нарушения попадают только файлы с нарушением, not_saved и ok нет."""
        result = {"baseline_error": None, "files": [{"path": "/a", "status": "ok"}, {"path": "/b", "status": "missing"},
                                                    {"path": "/c", "status": "not_saved"},
                                                    {"path": "/d", "status": "mismatch"}]}
        self.assertEqual(checker.violations(result),
                         {"baseline_error": None, "files": [{"path": "/b", "status": "missing"},
                                                            {"path": "/d", "status": "mismatch"}]})

    def test_baseline_error(self):
        """Нарушенный эталон виден в причине."""
        self.assertEqual(checker.violations({"baseline_error": "HMAC", "files": []})["baseline_error"], "HMAC")


class OnResultLockTest(Fixture):
    def test_on_result_under_lock(self):
        """Реакция идёт под блокировкой: устаревшее нарушение не включит режим после восстановления."""
        c = checker.Checker(self.config)
        locked = []
        c.on_result = lambda result: locked.append(c._lock.locked())
        c.check()
        self.assertEqual(locked, [True])

    def test_restore_rechecks(self):
        """После восстановления проверка повторяется, результат передан в on_result (с. 21)."""
        results = []
        c = checker.Checker(self.config, on_result=results.append)
        with mock.patch.object(checker.restore, "restore_file"):
            result, errors = c.restore_files(self.a)
        self.assertEqual(errors, [])
        self.assertEqual(results, [result])
        self.assertIs(c.last_result(), result)


class PeriodicTest(Fixture):
    def start(self, period=0.01):
        self.config["check_period_sec"] = period
        self.done = threading.Semaphore(0)
        self.results = []

        def on_result(result):
            self.results.append(result)
            self.done.release()

        c = checker.Checker(self.config, on_result=on_result)
        c.start_periodic()
        self.addCleanup(self.stop, c)
        return c

    def stop(self, c):
        if c._thread.is_alive():
            c.stop()

    def test_runs_repeatedly(self):
        """Проверка выполняется автоматически с заданным периодом (FR-46)."""
        self.start()
        for _ in range(3):
            self.assertTrue(self.done.acquire(timeout=5))

    def test_first_run_after_period(self):
        """Первая проверка таймера — через период: при запуске её уже выполнила служба."""
        self.start(period=3600)
        self.assertFalse(self.done.acquire(timeout=0.05))

    def test_detects_violation(self):
        """Таймер обнаруживает изменение файла без запроса администратора (FR-46)."""
        c = self.start()
        with open(self.a, "ab") as f:
            f.write(b"x")
        for _ in range(100):
            self.assertTrue(self.done.acquire(timeout=5))
            if not self.results[-1]["ok"]:
                break
        self.assertFalse(c.last_result()["ok"])

    def test_stop(self):
        """После stop проверок нет."""
        c = self.start()
        self.assertTrue(self.done.acquire(timeout=5))
        c.stop()
        count = len(self.results)
        self.assertFalse(self.done.acquire(timeout=0.05) and len(self.results) > count + 1)
        self.assertFalse(c._thread.is_alive())

    def test_survives_failure(self):
        """Сбой одной проверки не прекращает контроль."""
        err = io.StringIO()
        with mock.patch.object(hasher, "load_key", side_effect=[RuntimeError("сбой"), KEY, KEY, KEY]), \
                contextlib.redirect_stderr(err):
            self.start()
            self.assertTrue(self.done.acquire(timeout=5))


class MainCheckTest(Fixture):
    def write_config(self, **section):
        path = os.path.join(self.tmp.name, "config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"integrityd": dict(self.config, **section)}, f)
        return path

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = main.main(list(argv))
        return code, out.getvalue()

    def test_check_ok(self):
        """python -m fw_integrityd check: таблица файлов, код 0."""
        code, out = self.run_main("check", "--config", self.write_config())
        self.assertEqual(code, 0)
        self.assertIn("Файл", out)
        self.assertIn(self.a, out)

    def test_check_violation(self):
        """python -m fw_integrityd check при нарушении: статус в таблице, код 1."""
        os.remove(self.a)
        code, out = self.run_main("check", "--config", self.write_config())
        self.assertEqual(code, 1)
        self.assertIn("missing", out)

    def test_check_bad_hmac(self):
        """python -m fw_integrityd check при неверном HMAC: причина вместо таблицы, код 1."""
        with open(self.config["hmac_key_path"], "wb") as f:
            f.write(b"x" * 32)
        code, out = self.run_main("check", "--config", self.write_config())
        self.assertEqual(code, 1)
        self.assertIn(self.config["baseline_path"], out)

    def test_bad_config(self):
        """Неверная конфигурация отклоняется: период 10–3600 с, ≤ 64 абсолютных путей; код 2."""
        bad = [{"check_period_sec": 9}, {"check_period_sec": 3601}, {"check_period_sec": True},
               {"files": ["relative/path"]}, {"files": [self.a] * (main.MAX_CONTROLLED_FILES + 1)},
               {"baseline_path": None}]
        for section in bad:
            with self.assertRaises(ValueError, msg=section):
                main.load_config(self.write_config(**section))
        code, _ = self.run_main("check", "--config", self.write_config(check_period_sec=0))
        self.assertEqual(code, 2)

    def test_default_config(self):
        """Сохранённой конфигурации нет: читается конфигурация по умолчанию (FR-04)."""
        saved = os.path.join(self.tmp.name, "no-such-config.json")
        default = self.write_config()
        with mock.patch.object(main, "CONFIG_PATH", saved), mock.patch.object(main, "DEFAULT_CONFIG_PATH", default):
            self.assertEqual(main.load_config(saved)["files"], self.config["files"])
            code, _ = self.run_main("check", "--config", saved)
        self.assertEqual(code, 0)

    def test_saved_config_preferred(self):
        """Сохранённая конфигурация важнее конфигурации по умолчанию."""
        saved = self.write_config()
        default = os.path.join(self.tmp.name, "no-such-default.json")
        with mock.patch.object(main, "CONFIG_PATH", saved), mock.patch.object(main, "DEFAULT_CONFIG_PATH", default):
            self.assertEqual(main.load_config(saved)["check_period_sec"], 60)

    def test_other_path_no_default(self):
        """Значения по умолчанию заменяют только сохранённую конфигурацию, не любой неверный путь."""
        other = os.path.join(self.tmp.name, "no-such-config.json")
        with mock.patch.object(main, "DEFAULT_CONFIG_PATH", self.write_config()):
            with self.assertRaises(FileNotFoundError):
                main.load_config(other)


if __name__ == "__main__":
    unittest.main()
