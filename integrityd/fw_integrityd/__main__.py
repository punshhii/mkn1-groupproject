"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      main
Назначение:  точка входа fw-integrityd: конфигурация, сервер на /run/fw/integrityd.sock, диспетчер команд integrity.*
Методы:
  - load_config — прочитать конфигурацию ПС-6
  - handle — обработать запрос (integrity.check, integrity.status, integrity.restore, integrity.update_baseline)
  - format_table — таблица «файл / статус» по результату проверки
  - run_check — разовая проверка (python -m fw_integrityd check)
  - main — запуск подсистемы
"""
import argparse
import json
import os
import sys

from .checker import Checker

SOCK_PATH = "/run/fw/integrityd.sock"
CONFIG_PATH = "/etc/fw/config.json"  # допущение: имя файла в спецификации не задано, только /etc/fw/*.json

COMMANDS = ("integrity.check", "integrity.status", "integrity.restore", "integrity.update_baseline")

# Источники команд (таблица «Входящие команды ПС-6»)
ALLOWED_SRC = {
    "integrity.check": ("cli", "web"),
    "integrity.status": ("cli", "web"),
    "integrity.restore": ("cli", "web"),
    "integrity.update_baseline": ("cli", "web", "authd"),
}

CHECK_PERIOD_MIN_SEC = 10
CHECK_PERIOD_MAX_SEC = 3600
MAX_CONTROLLED_FILES = 64


def load_config(path: str) -> dict:
    """Прочитать конфигурацию ПС-6 из JSON в /etc/fw/ (baseline_path, backup_dir, hmac_key_path, check_period_sec, files).
    ValueError — раздел integrityd отсутствует или значения вне допустимых."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    cfg = data.get("integrityd") if isinstance(data, dict) else None
    if not isinstance(cfg, dict):
        raise ValueError("нет раздела integrityd")
    for name in ("baseline_path", "backup_dir", "hmac_key_path"):
        if not isinstance(cfg.get(name), str) or not os.path.isabs(cfg[name]):
            raise ValueError(f"integrityd.{name}: нужен абсолютный путь")
    period = cfg.get("check_period_sec")
    if type(period) is not int or not CHECK_PERIOD_MIN_SEC <= period <= CHECK_PERIOD_MAX_SEC:
        raise ValueError(f"integrityd.check_period_sec: {CHECK_PERIOD_MIN_SEC}–{CHECK_PERIOD_MAX_SEC} с")
    files = cfg.get("files")
    if not isinstance(files, list) or len(files) > MAX_CONTROLLED_FILES \
            or not all(isinstance(p, str) and os.path.isabs(p) for p in files):
        raise ValueError(f"integrityd.files: не более {MAX_CONTROLLED_FILES} абсолютных путей")
    return cfg


def handle(msg: dict):
    """Вернуть (status, payload, error_code, error_message) для fwcommon.protocol.serve.
    integrity.update_baseline принимает пустой payload."""
    raise NotImplementedError("main.handle")


def format_table(result: dict, baseline_path: str) -> str:
    """Таблица «файл / статус»; при ошибке файла эталонов — одна строка с причиной."""
    if result["baseline_error"]:
        return f"{baseline_path}: {result['baseline_error']}"
    rows = [("Файл", "Статус")] + [(f["path"], f["status"]) for f in result["files"]]
    width = max(len(path) for path, _ in rows)
    return "\n".join(f"{path:<{width}}  {status}" for path, status in rows)


def run_check(config_path: str) -> int:
    """Разовая проверка без перехода в аварийный режим: 0 — всё совпало, 1 — нарушение, 2 — ошибка конфигурации."""
    try:
        config = load_config(config_path)
    except (OSError, ValueError) as e:
        print(f"fw-integrityd: {config_path}: {e}", file=sys.stderr)
        return 2
    result = Checker(config).check()
    print(format_table(result, config["baseline_path"]))
    return 0 if result["ok"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m fw_integrityd")
    parser.add_argument("command", nargs="?", choices=["check"], help="check — разовая проверка целостности")
    parser.add_argument("--config", default=CONFIG_PATH, help=f"конфигурация (по умолчанию {CONFIG_PATH})")
    args = parser.parse_args(argv)
    if args.command == "check":
        return run_check(args.config)
    # TODO: load_config -> проверка при запуске -> периодическая проверка
    #       -> protocol.serve(SOCK_PATH, "integrityd", handle)
    print("fw-integrityd: skeleton, not implemented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
