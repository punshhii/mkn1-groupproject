"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      mkbaseline
Назначение:  формирование эталонов, резервных копий и ключа HMAC при сборке
установочного пакета в доверенной среде (FR-50); на устройстве не запускается
Методы:
  - staged — путь внутри каталога сборки
  - build — сформировать ключ HMAC, резервные копии и файл эталонов
  - main — запуск из командной строки
"""
import argparse
import os
import secrets
import shutil
import sys

from . import hasher
from .__main__ import load_config

KEY_BYTES = 32


def staged(root: str, path: str) -> str:
    """Путь файла path ПО МЭ внутри каталога root (корень ФС будущего пакета)."""
    return os.path.join(root, path.lstrip("/"))


def build(root: str, config: dict) -> dict:
    """Для каждого файла config["files"] из каталога root вычислить SHA-256, положить копию
    в backup_dir (зеркало путей) и записать файл эталонов под HMAC; вернуть {путь: хэш}.
    Ключ HMAC создаётся, если его ещё нет в root, иначе используется существующий."""
    if not config["files"]:
        raise ValueError("список integrityd.files пуст")

    key_path = staged(root, config["hmac_key_path"])
    if os.path.exists(key_path):
        key = hasher.load_key(key_path)
    else:
        key = secrets.token_bytes(KEY_BYTES)
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, "wb") as f:
            f.write(key)

    backup_dir = staged(root, config["backup_dir"])
    os.makedirs(backup_dir, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    files = {}
    for path in config["files"]:
        src = staged(root, path)
        files[path] = hasher.sha256_file(src)
        dst = staged(backup_dir, path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)

    baseline_path = staged(root, config["baseline_path"])
    os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
    hasher.save_baseline(baseline_path, files, key)
    return files


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fw_integrityd.mkbaseline",
                                     description="Эталоны и резервные копии ПС-6 при сборке пакета (FR-50)")
    parser.add_argument("--root", required=True, help="каталог сборки (корень ФС пакета)")
    parser.add_argument("--config", required=True, help="конфигурация с разделом integrityd")
    args = parser.parse_args(argv)
    try:
        files = build(args.root, load_config(args.config))
    except (OSError, ValueError) as e:
        print(f"mkbaseline: {e}", file=sys.stderr)
        return 1
    print(f"mkbaseline: эталонов {len(files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
