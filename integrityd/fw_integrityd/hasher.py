"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      hasher
Назначение:  SHA-256 контролируемых файлов, файл эталонов под HMAC-SHA-256 (FR-46, FR-47)
Методы:
  - sha256_file — хэш SHA-256 файла
  - load_key — прочитать ключ HMAC
  - load_baseline — прочитать файл эталонов и проверить HMAC
  - save_baseline — записать файл эталонов с новым HMAC
"""
import hashlib
import hmac
import json
import os

CHUNK_SIZE = 65536


class BaselineError(Exception):
    """Файл эталонов недоступен, повреждён или HMAC не совпал — нарушение целостности (FR-47)."""


def sha256_file(path: str) -> str:
    """Вернуть хэш SHA-256 файла (FR-46)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(block)
    return h.hexdigest()


def load_key(path: str) -> bytes:
    """Прочитать ключ HMAC (/etc/fw/hmac.key, fw-integrity, 0400)."""
    with open(path, "rb") as f:
        return f.read()


def _mac(files: dict, key: bytes) -> str:
    """HMAC-SHA-256 от канонического JSON {путь: хэш}."""
    data = json.dumps(files, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def load_baseline(path: str, key: bytes) -> dict:
    """Прочитать файл эталонов {"files": {путь: хэш}, "hmac": ...}, проверить HMAC-SHA-256; вернуть {путь: хэш}.
    BaselineError — файл недоступен, повреждён или HMAC не совпал (FR-47)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        files, mac = data["files"], data["hmac"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise BaselineError(f"файл эталонов не прочитан: {e}") from e
    if not isinstance(files, dict) or not isinstance(mac, str) \
            or not hmac.compare_digest(_mac(files, key).encode(), mac.encode()):
        raise BaselineError("HMAC файла эталонов не совпал")
    return files


def save_baseline(path: str, files: dict, key: bytes) -> None:
    """Записать файл эталонов {путь: хэш} с новым HMAC-SHA-256 (/var/lib/fw/baseline.json, fw-integrity, 0600)."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"files": files, "hmac": _mac(files, key)}, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
