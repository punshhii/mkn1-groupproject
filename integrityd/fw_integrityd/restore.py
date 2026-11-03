"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      restore
Назначение:  восстановление файлов из резервных копий с проверкой эталона (FR-49, FR-50)
Методы:
  - backup_path — путь резервной копии файла
  - verify_backup — сверить резервную копию с эталоном
  - restore_file — восстановить файл из резервной копии
  - update_backup — обновить резервную копию после штатного изменения
"""
import os
import shutil
import subprocess

from . import hasher

RESTORE_CMD = ("sudo", "-n", "/usr/lib/fw/bin/fw-restore")  # путь из шаблона etc/sudoers.d/fw


class RestoreError(Exception):
    """Копия не совпала с эталоном или восстановление не выполнено."""


def backup_path(backup_dir: str, path: str) -> str:
    """Путь резервной копии: пути зеркалируются как в mkbaseline."""
    return os.path.join(backup_dir, path.lstrip("/"))


def verify_backup(backup_dir: str, path: str, baseline: dict) -> bool:
    """True, если SHA-256 резервной копии файла совпадает с эталоном."""
    try:
        return hasher.sha256_file(backup_path(backup_dir, path)) == baseline.get(path)
    except OSError:
        return False


def restore_file(backup_dir: str, path: str, baseline: dict) -> None:
    """Сверить копию с эталоном и заменить файл через sudo.
    Копия с несовпадающей контрольной суммой не используется (FR-49).
    Подложенный файл без записи в эталоне не удаляется: RestoreError, режим остаётся аварийным."""
    if not verify_backup(backup_dir, path, baseline):
        raise RestoreError(f"{path}: копия отсутствует или не совпала с эталоном")
    try:
        subprocess.run((*RESTORE_CMD, path), check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as e:
        raise RestoreError(f"{path}: замена файла не выполнена: {e}") from e


def update_backup(backup_dir: str, path: str) -> None:
    """Обновить резервную копию файла (/var/lib/fw/backup/, fw-integrityd, 0700) после штатного изменения (FR-50).
    Пути зеркалируются как в mkbaseline; копия заменяется целиком через временный файл."""
    dst = backup_path(backup_dir, path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".tmp"
    shutil.copy2(path, tmp)
    os.replace(tmp, dst)
