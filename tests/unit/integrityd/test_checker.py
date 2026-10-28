import contextlib
import io
import json
import os
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
