#!/usr/bin/env bash
# Система:     ПО межсетевого экрана (ПО МЭ)
# Подсистема:  ПС-6 Целостность
# Модуль:      break_integrity.sh
# Назначение:  повреждение контролируемого файла на стенде для вызова режима
#              аварийной поддержки одной командой (FR-46, FR-48)
# Использование:
#   ./tests/stand/break_integrity.sh [--config ПУТЬ] [--file ПУТЬ] [--no-check]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CONFIG_PATH="${FW_CONFIG:-}"
TARGET_FILE=""
TRIGGER_CHECK=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--config)
            CONFIG_PATH="$2"
            shift 2
            ;;
        -f|--file)
            TARGET_FILE="$2"
            shift 2
            ;;
        --no-check)
            TRIGGER_CHECK=0
            shift
            ;;
        -h|--help)
            echo "Использование: $0 [--config ПУТЬ_К_КОНФИГУ] [--file КОНТРОЛИРУЕМЫЙ_ФАЙЛ] [--no-check]"
            exit 0
            ;;
        *)
            if [[ -z "$CONFIG_PATH" && -f "$1" ]]; then
                CONFIG_PATH="$1"
                shift
            else
                echo "break_integrity.sh: неизвестный аргумент: $1" >&2
                exit 2
            fi
            ;;
    esac
done

# Поиск конфигурационного файла (стенд в /tmp, /etc/fw или default)
if [[ -z "$CONFIG_PATH" ]]; then
    for candidate in \
        "/etc/fw/config.json" \
        "/etc/fw/default/config.json" \
        "/tmp/fwdemo/target/etc/fw/config.json" \
        "${REPO_ROOT}/etc/default/config.json"; do
        if [[ -f "$candidate" ]]; then
            CONFIG_PATH="$candidate"
            break
        fi
    done
fi

if [[ -z "$CONFIG_PATH" || ! -f "$CONFIG_PATH" ]]; then
    echo "break_integrity.sh: конфигурационный файл не найден (укажите --config или FW_CONFIG)" >&2
    exit 2
fi

export PYTHONPATH="${REPO_ROOT}/common:${REPO_ROOT}/integrityd${PYTHONPATH:+:$PYTHONPATH}"

# Выбор контролируемого файла из раздела integrityd.files конфигурации
if [[ -z "$TARGET_FILE" ]]; then
    TARGET_FILE="$(python3 - "$CONFIG_PATH" <<'PY'
import json
import os
import sys

cfg_path = sys.argv[1]
with open(cfg_path, encoding="utf-8") as f:
    data = json.load(f)

files = data.get("integrityd", {}).get("files", [])
if not files:
    sys.exit(1)

# Предпочитаем существующий файл, отличный от config.json (например, policy.json или fw-filter),
# чтобы не ломать чтение конфигурации при перезапуске службы
existing = [p for p in files if os.path.exists(p)]
non_cfg = [p for p in existing if not p.endswith("/config.json")]
chosen = (non_cfg or existing or files)[0]
print(chosen)
PY
)" || {
        echo "break_integrity.sh: в $CONFIG_PATH пуст список integrityd.files" >&2
        exit 2
    }
fi

if [[ ! -e "$TARGET_FILE" ]]; then
    echo "break_integrity.sh: контролируемый файл '$TARGET_FILE' не существует" >&2
    exit 1
fi

# Изменяем содержимое файла (добавляем перевод строки: SHA-256 меняется, а JSON остаётся валидным)
printf '\n' >> "$TARGET_FILE"
echo "break_integrity.sh: нарушена целостность файла: $TARGET_FILE"

# Если запущен демон fw-integrityd, инициируем внеочередную проверку,
# чтобы аварийный режим включился сразу, без ожидания таймера check_period_sec
if [[ "$TRIGGER_CHECK" -eq 1 ]]; then
    python3 - <<'PY' || true
import os
import time
from fwcommon import protocol

run_dir = os.environ.get("FW_RUN_DIR", "/run/fw")
sock = os.path.join(run_dir, "integrityd.sock")

if os.path.exists(sock):
    msg = protocol.make_msg("request", "cli", "integrityd", "integrity.check")
    msg["msg_id"] = int(time.time() * 1000) & 0x7FFFFFFF
    try:
        resp = protocol._exchange(sock, msg, protocol.TIMEOUT_SEC)
        mode = resp.get("payload", {}).get("mode", "unknown")
        print(f"break_integrity.sh: запрос integrity.check выполнен, режим МЭ: {mode}")
    except Exception as e:
        print(f"break_integrity.sh: сокет найден, но демон не ответил ({e}); нарушение обнаружится при проверке")
else:
    print(f"break_integrity.sh: сокет {sock} не найден (демон не запущен); нарушение обнаружится при старте")
PY
fi
