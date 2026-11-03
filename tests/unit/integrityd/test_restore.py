"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      test_restore
Назначение:  unit-тесты резервных копий и восстановления (FR-49, FR-50)
Методы:
  - VerifyTest — сверка копии с эталоном, замена файла через sudo
  - UpdateBackupTest — копия создаётся, заменяется, частичных файлов не остаётся
"""
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from fw_integrityd import hasher, restore


@unittest.skipIf(os.name == "nt", "пути POSIX")
class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.backup_dir = os.path.join(self.tmp.name, "backup")
        self.path = os.path.join(self.tmp.name, "etc", "config.json")
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("good")
        restore.update_backup(self.backup_dir, self.path)
        self.baseline = {self.path: hasher.sha256_file(self.path)}
        self.copy = restore.backup_path(self.backup_dir, self.path)

    def spoil_copy(self):
        with open(self.copy, "a", encoding="utf-8") as f:
            f.write("x")

    def test_verify(self):
        """Копия совпала с эталоном."""
        self.assertTrue(restore.verify_backup(self.backup_dir, self.path, self.baseline))

    def test_verify_changed_copy(self):
        """Копия изменена: не совпала (FR-49)."""
        self.spoil_copy()
        self.assertFalse(restore.verify_backup(self.backup_dir, self.path, self.baseline))

    def test_verify_no_copy(self):
        """Копии нет или нет записи в эталоне: не совпала."""
        self.assertFalse(restore.verify_backup(self.backup_dir, self.path, {}))
        os.remove(self.copy)
        self.assertFalse(restore.verify_backup(self.backup_dir, self.path, self.baseline))

    def test_restore_uses_sudo(self):
        """Файл заменяется через sudo, скрипт получает только путь (с. 29, 30)."""
        with mock.patch.object(restore.subprocess, "run") as run:
            restore.restore_file(self.backup_dir, self.path, self.baseline)
        run.assert_called_once_with(("sudo", "-n", "/usr/lib/fw/bin/fw-restore", self.path),
                                    check=True, capture_output=True)

    def test_bad_copy_not_used(self):
        """Копия не совпала: скрипт не вызывается (FR-49)."""
        self.spoil_copy()
        with mock.patch.object(restore.subprocess, "run") as run:
            with self.assertRaises(restore.RestoreError):
                restore.restore_file(self.backup_dir, self.path, self.baseline)
        run.assert_not_called()

    def test_sudo_failure(self):
        """Сбой sudo или скрипта: RestoreError, а не необработанное исключение."""
        failures = (OSError("нет sudo"), subprocess.CalledProcessError(2, "sudo"))
        for failure in failures:
            with mock.patch.object(restore.subprocess, "run", side_effect=failure):
                with self.assertRaises(restore.RestoreError):
                    restore.restore_file(self.backup_dir, self.path, self.baseline)


@unittest.skipIf(os.name == "nt", "пути POSIX")
class UpdateBackupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.backup_dir = os.path.join(self.tmp.name, "backup")
        self.path = os.path.join(self.tmp.name, "etc", "config.json")
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("old")
        self.copy = os.path.join(self.backup_dir, self.path.lstrip("/"))

    def test_create(self):
        """Копии ещё нет: каталоги создаются, путь зеркалируется (как в mkbaseline)."""
        restore.update_backup(self.backup_dir, self.path)
        with open(self.copy, encoding="utf-8") as f:
            self.assertEqual(f.read(), "old")

    def test_replace(self):
        """Существующая копия заменяется, временный файл не остаётся (FR-50)."""
        restore.update_backup(self.backup_dir, self.path)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("new")
        restore.update_backup(self.backup_dir, self.path)
        with open(self.copy, encoding="utf-8") as f:
            self.assertEqual(f.read(), "new")
        self.assertEqual(os.listdir(os.path.dirname(self.copy)), ["config.json"])

    def test_missing_source(self):
        """Исходного файла нет: ошибка, прежняя копия не портится."""
        restore.update_backup(self.backup_dir, self.path)
        os.remove(self.path)
        with self.assertRaises(OSError):
            restore.update_backup(self.backup_dir, self.path)
        with open(self.copy, encoding="utf-8") as f:
            self.assertEqual(f.read(), "old")


if __name__ == "__main__":
    unittest.main()
