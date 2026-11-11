#!/bin/bash
# ==============================================================================
# Система:     ПО межсетевого экрана (ПО МЭ)
# Подсистема:  тестовый стенд (tests/stand)
# Модуль:      topology.sh
# Назначение:  развертывание сетевой топологии на 5 портов:
#              - 5 пространств имен (netns): h1..h5 (10.10.0.1..10.10.0.5/24)
#              - 5 интерфейсов МЭ: eth1..eth5 (в promisc-режиме, без IP)
#              - выключение offload (gro/gso/tso/lro)
#              - поддержка локального режима (veth) и режима реальных ВМ (--stand)
# Использование:
#              sudo tests/stand/topology.sh up [--stand]
#              sudo tests/stand/topology.sh down [--stand]
#              sudo tests/stand/topology.sh status
# ==============================================================================

set -euo pipefail

STAND_MODE=0
IFACE_PREFIX="eth"
HOST_PREFIX="veth-h"
NETNS_PREFIX="h"
SUBNET_BASE="10.10.0"

for arg in "$@"; do
    if [ "$arg" = "--stand" ]; then
        STAND_MODE=1
    fi
done

CMD="${1:-help}"

check_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        echo "Ошибка: topology.sh требует прав суперпользователя: sudo $0 $CMD" >&2
        exit 1
    fi
}

do_down() {
    echo "[*] Удаление сетевой топологии стенда..."
    for i in 1 2 3 4 5; do
        ns="${NETNS_PREFIX}${i}"
        fw_if="${IFACE_PREFIX}${i}"

        # Удаление пространства имен (также удалит привязанный veth-конец)
        if ip netns list 2>/dev/null | grep -qw "$ns"; then
            ip netns del "$ns" 2>/dev/null || true
            echo "  - netns $ns удален"
        fi

        # В локальном режиме удаляем оставшийся veth со стороны МЭ
        if [ "$STAND_MODE" -eq 0 ]; then
            if ip link show "$fw_if" >/dev/null 2>&1; then
                ip link del "$fw_if" 2>/dev/null || true
                echo "  - интерфейс $fw_if удален"
            fi
        fi
    done
    echo "[+] Сетевая топология очищена."
}

do_up() {
    echo "[*] Развертывание топологии стенда (5 портов)..."
    do_down >/dev/null 2>&1 || true

    for i in 1 2 3 4 5; do
        ns="${NETNS_PREFIX}${i}"
        cl_if="${HOST_PREFIX}${i}"
        fw_if="${IFACE_PREFIX}${i}"
        ip_addr="${SUBNET_BASE}.${i}/24"
        mac_addr=$(printf "02:00:00:00:00:%02x" "$i")

        echo "  [Порт $i] Настройка $cl_if ($ip_addr) <-> МЭ $fw_if..."

        # 1. Создание netns для нагрузочного хоста
        ip netns add "$ns"

        if [ "$STAND_MODE" -eq 0 ]; then
            # 2. Локальный режим: создание пары veth
            ip link add "$cl_if" type veth peer name "$fw_if"

            # Перенос клиентского конца в netns
            ip link set "$cl_if" netns "$ns"

            # Настройка клиентского конца
            ip netns exec "$ns" ip link set dev "$cl_if" address "$mac_addr"
            ip netns exec "$ns" ip addr add "$ip_addr" dev "$cl_if"
            ip netns exec "$ns" ip link set dev "$cl_if" up
            ip netns exec "$ns" ip link set dev lo up

            # Настройка фильтрующего интерфейса МЭ (на хосте)
            ip link set dev "$fw_if" up promisc on
            if command -v ethtool >/dev/null 2>&1; then
                ethtool -K "$fw_if" gro off gso off tso off lro off 2>/dev/null || true
            fi
        else
            # 2. Режим реального стенда (--stand): интерфейсы уже существуют физически
            # Если скрипт запущен на НК, переносим физический интерфейс в netns
            if ip link show "$cl_if" >/dev/null 2>&1; then
                ip link set "$cl_if" netns "$ns"
                ip netns exec "$ns" ip link set dev "$cl_if" address "$mac_addr"
                ip netns exec "$ns" ip addr add "$ip_addr" dev "$cl_if"
                ip netns exec "$ns" ip link set dev "$cl_if" up
                ip netns exec "$ns" ip link set dev lo up
            fi
            # Если запущен на МЭ, выключаем offload на fw_if
            if ip link show "$fw_if" >/dev/null 2>&1; then
                ip link set dev "$fw_if" up promisc on
                if command -v ethtool >/dev/null 2>&1; then
                    ethtool -K "$fw_if" gro off gso off tso off lro off 2>/dev/null || true
                fi
            fi
        fi
    done

    echo ""
    echo "=================================================================="
    echo " ТОПОЛОГИЯ УСПЕШНО РАЗВЕРНУТА                                    "
    echo "=================================================================="
    echo "  Порты МЭ (P1..P5):  eth1 .. eth5 (без IP, promisc on, offload off)"
    echo "  Хосты НК (h1..h5):  netns h1..h5 (10.10.0.1/24 .. 10.10.0.5/24)"
    echo ""
    echo "  Проверка связности (после запуска fw-filter с разрешением ICMP):"
    echo "    sudo ip netns exec h1 ping -c 3 10.10.0.2"
    echo "=================================================================="
}

do_status() {
    echo "=== Пространства имен (netns) ==="
    ip netns list 2>/dev/null || true
    echo ""
    echo "=== Фильтрующие интерфейсы МЭ ==="
    for i in 1 2 3 4 5; do
        fw_if="${IFACE_PREFIX}${i}"
        if ip link show "$fw_if" >/dev/null 2>&1; then
            ip -brief link show "$fw_if"
        else
            echo "$fw_if: отсутствует"
        fi
    done
}

case "$CMD" in
    up)
        check_root
        do_up
        ;;
    down)
        check_root
        do_down
        ;;
    status)
        do_status
        ;;
    *)
        echo "Использование: $0 {up|down|status} [--stand]"
        exit 1
        ;;
esac
