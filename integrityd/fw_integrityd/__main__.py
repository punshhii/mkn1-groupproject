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
  - run_daemon — работа службы: проверка при запуске, таймер, сервер на сокете
  - main — запуск подсистемы
"""
import argparse
import json
import os
import sys

from fwcommon import codes, protocol

from . import hasher
from .checker import Checker, violations
from .emergency import Emergency

SOCK_PATH = os.path.join(os.environ.get("FW_RUN_DIR", "/run/fw"), "integrityd.sock")
CONFIG_PATH = "/etc/fw/config.json"  # допущение: имя файла в спецификации не задано, только /etc/fw/*.json
DEFAULT_CONFIG_PATH = "/etc/fw/default/config.json"  # допущение: в спецификации задан только каталог (с. 30)

COMMANDS = ("integrity.check", "integrity.status", "integrity.restore", "integrity.update_baseline")

# Источники команд
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
    Если сохранённой конфигурации нет (первый запуск), читается конфигурация по умолчанию (FR-04).
    ValueError - раздел integrityd отсутствует или значения вне допустимых."""
    if path == CONFIG_PATH and not os.path.exists(path):
        path = DEFAULT_CONFIG_PATH
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


def _error(code: str, payload: dict = None, **kw):
    return "error", payload if payload is not None else {}, code, codes.message_text(code, **kw)


def _view(result: dict, em: Emergency) -> dict:
    """Результат проверки и режим: normal или emergency (с. 26), значения как ждёт ПС-3."""
    return dict(result, mode="emergency" if em.is_active() else "normal")


def _restore(payload, checker: Checker, em: Emergency):
    """integrity.restore: {"file": путь|"all"} -> результат повторной проверки; при успехе выход из режима.
    Статус ответа определяет повторная проверка; файлы, которые не удалось восстановить, — в поле errors."""
    target = payload.get("file") if isinstance(payload, dict) else None
    if target != "all" and target not in checker.config["files"]:
        return _error("M06", field="file", allowed="контролируемый файл или all")
    result, errors = checker.restore_files(target)
    if result["ok"]:
        em.leave()
        return "ok", dict(_view(result, em), errors=errors), None, None
    return _error("M08", dict(_view(result, em), errors=errors))


def handle(msg: dict, checker: Checker, em: Emergency):
    """Вернуть (status, payload, error_code, error_message) для fwcommon.protocol.serve.
    integrity.status только читает последний результат: её вызывают ПС-3 перед каждой командой и ПС-4
    при каждом web-запросе (с. 34, 35). integrity.update_baseline принимает пустой payload."""
    cmd = msg.get("cmd")
    if msg.get("src") not in ALLOWED_SRC.get(cmd, ()):
        return _error("M14")
    if cmd == "integrity.status":
        return "ok", _view(checker.last_result(), em), None, None
    if cmd == "integrity.check":
        result = checker.check()
        em.log_event("E42", result["ok"], violations(result), command=cmd)
        return "ok", _view(result, em), None, None
    if cmd == "integrity.restore":
        return _restore(msg.get("payload"), checker, em)
    if em.is_active():
        return _error("M10")
    try:
        checker.update_baseline(msg["src"])
    except (hasher.BaselineError, OSError) as e:
        return "error", {}, None, str(e)
    return "ok", {}, None, None


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


def run_daemon(config_path: str) -> int:
    """Работа службы. Сервер запускается после первой проверки, поэтому integrity.status всегда отдаёт результат;
    до этого ПС-3 и ПС-4 получают M16 и считают режим аварийным (с. 34). Без конфигурации проверки нет,
    и ПС-1 остаётся в режиме drop-all (FR-04): код 2."""
    try:
        config = load_config(config_path)
    except (OSError, ValueError) as e:
        print(f"fw-integrityd: {config_path}: {e}", file=sys.stderr)
        return 2
    em = Emergency()
    em.start()
    checker = Checker(config, on_result=em.on_check)
    checker.check()
    server = protocol.serve(SOCK_PATH, "integrityd", lambda msg: handle(msg, checker, em))
    checker.start_periodic()
    server.serve_forever()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m fw_integrityd")
    parser.add_argument("command", nargs="?", choices=["check"], help="check — разовая проверка целостности")
    parser.add_argument("--config", default=CONFIG_PATH, help=f"конфигурация (по умолчанию {CONFIG_PATH})")
    args = parser.parse_args(argv)
    if args.command == "check":
        return run_check(args.config)
    return run_daemon(args.config)


if __name__ == "__main__":
    sys.exit(main())
