#!/bin/bash
# ==============================================================================
# Система:     ПО межсетевого экрана (ПО МЭ)
# Подсистема:  тестовый стенд (tests/stand)
# Модуль:      run_stand.sh
# Назначение:  стенд для всех команд: поднимает выбранные настоящие подсистемы
#              (код из рабочей копии: authd/, logd/, integrityd/, filter/),
#              остальные заменяет заглушками tests/stand/mock_core.py в том же
#              каталоге сокетов. Заглушка «os» (if, route) поднимается всегда.
#              По желанию — web ПС-4: приёмник web.sock и php -S.
#              Ctrl+C — остановка всех процессов и удаление сокетов.
# Запуск:      tests/stand/run_stand.sh [--real authd,logd] [--run-dir /tmp/fw]
#                                       [--config ФАЙЛ] [--web 8080] [--web-host 127.0.0.1]
#                                       [--filter-config ФАЙЛ]
#              --real all — все четыре настоящие; без --real — только заглушки.
#              --config — config.json для настоящих authd и integrityd; без него
#              в каталоге сокетов создаётся минимальный: интерфейсы eth0
#              (управляющий), eth1, eth2 и authd.accounts_path в каталоге стенда.
#              Настоящей integrityd нужен config.json с разделом integrityd
#              (эталоны и ключ HMAC — см. integrityd/README.md).
#              --web-host 0.0.0.0 — открыть web снаружи стенда (по умолчанию только 127.0.0.1).
#              Переменные: PYTHON (python3), PHP (php).
# ==============================================================================

set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-python3}"
PHP="${PHP:-php}"
RUN_DIR="/tmp/fw"
REAL=""
WEB_PORT=""
WEB_HOST="127.0.0.1"
FILTER_CONFIG="$REPO/filter/stand_config.json"
CONFIG=""
ALL="authd logd integrityd filter"
PIDS=()

usage() {
    sed -n '/^# Запуск:/,/^# ====/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --real)          REAL="$2"; shift 2 ;;
        --run-dir)       RUN_DIR="$2"; shift 2 ;;
        --web)           WEB_PORT="$2"; shift 2 ;;
        --web-host)      WEB_HOST="$2"; shift 2 ;;
        --config)        CONFIG="$2"; shift 2 ;;
        --filter-config) FILTER_CONFIG="$2"; shift 2 ;;
        -h|--help)       usage 0 ;;
        *)               echo "run_stand: неизвестный аргумент $1" >&2; usage 2 ;;
    esac
done

[ "$REAL" = "all" ] && REAL="${ALL// /,}"
REAL_LIST=" ${REAL//,/ } "
for n in $REAL_LIST; do
    case " $ALL " in *" $n "*) ;; *) echo "run_stand: неизвестная подсистема $n (есть: $ALL)" >&2; exit 2 ;; esac
done
MOCKS=""
for n in $ALL; do
    case "$REAL_LIST" in *" $n "*) ;; *) MOCKS="$MOCKS,$n" ;; esac
done
MOCKS="${MOCKS#,},os"
MOCKS="${MOCKS#,}"

mkdir -p "$RUN_DIR"
LOGS="$RUN_DIR/logs"
mkdir -p "$LOGS"
if [ -z "$CONFIG" ]; then  # минимальная конфигурация стенда
    CONFIG="$RUN_DIR/config.json"
    cat >"$CONFIG" <<CFG
{
  "ifaces": [
    {"name": "eth0", "enabled": true, "is_mgmt": true},
    {"name": "eth1", "enabled": true, "is_mgmt": false},
    {"name": "eth2", "enabled": true, "is_mgmt": false}
  ],
  "authd": {"accounts_path": "$RUN_DIR/accounts.json"}
}
CFG
fi
CONFIG="$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")"

stop() {
    trap - INT TERM EXIT
    echo
    echo "run_stand: остановка..."
    for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null; done
    wait 2>/dev/null
    rm -f "$RUN_DIR"/*.sock
    echo "run_stand: остановлено, сокеты удалены"
}
trap 'stop; exit 0' INT TERM
trap stop EXIT

wait_sock() {  # wait_sock ИМЯ PID — дождаться сокета ИМЯ.sock до 10 с
    local i
    for i in $(seq 1 100); do
        [ -S "$RUN_DIR/$1.sock" ] && return 0
        kill -0 "$2" 2>/dev/null || break
        sleep 0.1
    done
    echo "run_stand: $1 не поднялась (сокет $RUN_DIR/$1.sock не появился). Журнал $LOGS/$1.log:" >&2
    tail -n 20 "$LOGS/$1.log" >&2
    exit 1
}

start_real() {  # start_real ИМЯ
    local n="$1" pkg="fw_$1"
    if [ "$n" = "filter" ]; then
        [ -f "$REPO/filter/Makefile" ] || { echo "run_stand: нет filter/Makefile" >&2; exit 1; }
        if [ "$(id -u)" -ne 0 ]; then
            echo "run_stand: настоящему filter нужен root (сырые сокеты): sudo $0 ..." >&2; exit 1
        fi
        [ -x "$REPO/filter/fw-filter" ] || make -C "$REPO/filter" >"$LOGS/filter-build.log" 2>&1 \
            || { echo "run_stand: сборка filter не удалась, см. $LOGS/filter-build.log" >&2; exit 1; }
        [ -f "$FILTER_CONFIG" ] || { echo "run_stand: нет конфигурации filter $FILTER_CONFIG (--filter-config)" >&2; exit 1; }
        "$REPO/filter/fw-filter" --config "$FILTER_CONFIG" --sock "$RUN_DIR/filter.sock" \
            --logd "$RUN_DIR/logd.sock" >"$LOGS/filter.log" 2>&1 &
    else
        if [ ! -f "$REPO/$n/$pkg/__main__.py" ]; then
            echo "run_stand: настоящей $n нет в $REPO/$n/$pkg (её ветка ещё не влита в эту рабочую копию)" >&2
            exit 1
        fi
        local args=()
        if [ "$n" = "integrityd" ]; then
            grep -q '"integrityd"' "$CONFIG" || {
                echo "run_stand: в $CONFIG нет раздела integrityd (эталоны, ключ HMAC): --config ФАЙЛ" >&2
                exit 1; }
            args=(--config "$CONFIG")
        fi
        (cd "$REPO" && FW_RUN_DIR="$RUN_DIR" FW_CONFIG="$CONFIG" PYTHONPATH="common:$n" \
            exec "$PYTHON" -m "$pkg" "${args[@]}") >"$LOGS/$n.log" 2>&1 &
    fi
    PIDS+=("$!")
    wait_sock "$n" "$!"
    echo "  настоящая  $n  (журнал $LOGS/$n.log)"
}

echo "run_stand: каталог сокетов $RUN_DIR"
# заглушки — первыми: настоящие подсистемы при старте обращаются к соседям (logd, integrityd)
(cd "$REPO" && PYTHONPATH=common exec "$PYTHON" tests/stand/mock_core.py "$RUN_DIR" --only "$MOCKS") \
    >"$LOGS/mock_core.log" 2>&1 &
PIDS+=("$!")
for n in ${MOCKS//,/ }; do wait_sock "$n" "${PIDS[0]}"; done
echo "  заглушки   ${MOCKS//,/, }  (журнал $LOGS/mock_core.log, pid ${PIDS[0]})"
for n in $REAL_LIST; do
    rm -f "$RUN_DIR/$n.sock"
    start_real "$n"
done

if [ -n "$WEB_PORT" ]; then
    command -v "$PHP" >/dev/null || { echo "run_stand: нет php ($PHP)" >&2; exit 1; }
    "$PHP" "$REPO/web/src/listener.php" "$RUN_DIR" >"$LOGS/web-listener.log" 2>&1 &
    PIDS+=("$!")
    wait_sock web "$!"
    FW_RUN_DIR="$RUN_DIR" FW_CONFIG="$CONFIG" FW_NET=stand "$PHP" -S "$WEB_HOST:$WEB_PORT" -t "$REPO/web/public" \
        >"$LOGS/web.log" 2>&1 &
    PIDS+=("$!")
    echo "  web        http://$WEB_HOST:$WEB_PORT/  (приёмник web.sock, журнал $LOGS/web.log)"
fi

case "$REAL_LIST" in
    *" authd "*) ACCOUNTS="Учётные записи — настоящей authd ($CONFIG, раздел authd); при первом запуске admin / Admin_12345." ;;
    *) ACCOUNTS="Учётные записи заглушки authd: admin / admin123 (rw), viewer / viewer123 (ro)." ;;
esac
cat <<EOF

CLI в другом терминале:
  cd $REPO && PYTHONPATH=common:cli $PYTHON -m fw_cli --run-dir $RUN_DIR --config $CONFIG --net stand
$ACCOUNTS
Аварийный режим (если integrityd — заглушка): kill -USR1 ${PIDS[0]} / kill -USR2 ${PIDS[0]}.
Ctrl+C — остановить стенд.
EOF

wait -n 2>/dev/null
echo "run_stand: один из процессов завершился, см. $LOGS" >&2
