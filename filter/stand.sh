#!/bin/bash
# ==============================================================================
# Скрипт поднятия тестового стенда для fw-filter на Linux
# Создаёт виртуальные пространства имён (netns), интерфейсы (veth) и
# запускает fw-filter, передавая управление пользователю.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCK_PATH="/tmp/filter.sock"
CONFIG_FILE="${SCRIPT_DIR}/stand_config.json"
PID_FILE="/tmp/fw-filter.pid"
LOG_FILE="/tmp/fw-filter.log"

if [ "$EUID" -ne 0 ]; then
    echo "Ошибка: скрипт должен быть запущен с правами root: sudo $0"
    exit 1
fi

# Очистка стенда по запросу
if [ "$1" = "down" ] || [ "$1" = "clean" ] || [ "$1" = "stop" ]; then
    echo "[*] Остановка fw-filter и удаление тестового стенда..."
    if [ -f "$PID_FILE" ]; then
        kill -TERM "$(cat "$PID_FILE")" 2>/dev/null || true
        rm -f "$PID_FILE"
    else
        killall -q fw-filter 2>/dev/null || true
    fi
    ip netns del client 2>/dev/null || true
    ip netns del server 2>/dev/null || true
    ip link del fw-in 2>/dev/null || true
    ip link del fw-out 2>/dev/null || true
    rm -f "$SOCK_PATH"
    echo "==> Стенд полностью очищен."
    exit 0
fi

echo "=================================================================="
echo "           ПОДНЯТИЕ ТЕСТОВОГО СТЕНДА FW-FILTER                    "
echo "=================================================================="

# 1. Создание конфигурационного файла стенда
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[1/5] Создание ${CONFIG_FILE}..."
    cat > "$CONFIG_FILE" <<EOF
{
  "conntrack": {
    "conntrack_enabled": true,
    "arp_forwarding": true,
    "tcp_syn_timeout_sec": 5,
    "tcp_est_timeout_sec": 3600,
    "tcp_fin_timeout_sec": 10,
    "udp_timeout_no_reply": 10,
    "udp_timeout_reply": 30,
    "icmp_timeout_sec": 5,
    "state_table_size": 65536
  },
  "ifaces": [
    { "name": "fw-in",  "enabled": true, "is_mgmt": false },
    { "name": "fw-out", "enabled": true, "is_mgmt": false }
  ]
}
EOF
fi

# 2. Сборка fw-filter при необходимости
if [ ! -f "${SCRIPT_DIR}/filter/fw-filter" ]; then
    echo "[2/5] Сборка fw-filter..."
    make -C "${SCRIPT_DIR}/filter"
fi

# 3. Настройка сетевых пространств имён
echo "[3/5] Настройка пространств имён (client, server)..."
ip netns del client 2>/dev/null || true
ip netns del server 2>/dev/null || true
ip link del fw-in 2>/dev/null || true
ip link del fw-out 2>/dev/null || true

ip netns add client
ip netns add server

# 4. Создание и привязка veth интерфейсов
echo "[4/5] Поднятие L2-моста (veth-c <-> fw-in, fw-out <-> veth-s)..."
ip link add veth-c type veth peer name fw-in
ip link add fw-out type veth peer name veth-s

ip link set veth-c netns client
ip link set veth-s netns server

ip netns exec client ip addr add 192.168.1.10/24 dev veth-c
ip netns exec client ip link set veth-c up
ip netns exec client ip link set lo up

ip netns exec server ip addr add 192.168.1.20/24 dev veth-s
ip netns exec server ip link set veth-s up
ip netns exec server ip link set lo up

ip link set fw-in up promisc on
ip link set fw-out up promisc on

# 5. Запуск демона
rm -f "$SOCK_PATH"
if [ "$1" = "--foreground" ] || [ "$1" = "-f" ]; then
    echo "[5/5] Запуск fw-filter на переднем плане (Ctrl+C для завершения)..."
    exec "${SCRIPT_DIR}/filter/fw-filter" --config "$CONFIG_FILE" --sock "$SOCK_PATH"
else
    echo "[5/5] Запуск fw-filter в фоновом режиме..."
    "${SCRIPT_DIR}/filter/fw-filter" --config "$CONFIG_FILE" --sock "$SOCK_PATH" > "$LOG_FILE" 2>&1 &
    PID=$!
    echo $PID > "$PID_FILE"

    # Ожидание сокета
    for i in {1..30}; do
        if [ -S "$SOCK_PATH" ]; then
            break
        fi
        sleep 0.1
    done

    # Обеспечиваем полный доступ к сокету для всех локальных пользователей
    chmod 0666 "$SOCK_PATH" 2>/dev/null || true

    echo ""
    echo "=================================================================="
    echo "  СТЕНД ГОТОВ. УПРАВЛЕНИЕ ПЕРЕДАНО ПОЛЬЗОВАТЕЛЮ!                  "
    echo "=================================================================="
    echo "  * Клиент:           192.168.1.10 (netns: client)"
    echo "  * Сервер:           192.168.1.20 (netns: server)"
    echo "  * Демон fw-filter:  PID $PID (лог: $LOG_FILE)"
    echo "  * Сокет IPC:        $SOCK_PATH (доступен для чтения и записи)"
    echo ""
    echo "  Полезные команды:"
    echo "    - Пинг с клиента:       sudo ip netns exec client ping 192.168.1.20"
    echo "    - Войти в шелл клиента: sudo ip netns exec client bash"
    echo "    - Войти в шелл сервера: sudo ip netns exec server bash"
    echo "    - Логи демона в реале:  tail -f $LOG_FILE"
    echo "    - Сбросить стенд:       sudo $0 down"
    echo "=================================================================="
fi
