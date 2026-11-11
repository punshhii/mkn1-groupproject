#!/usr/bin/env python3
"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  тестовый стенд (tests/traffic/scenarios)
Модуль:      demo_scenario.py
Назначение:  набор проверочных сценариев для демонстрации взаимодействия (чт 12.11)
             согласно tasks-2026-11-06.md:
               - Шаг 1: Аварийный режим при старте (traffic.block / drop-all)
               - Шаг 4: ICMP 1->2 pass, TCP/23 1->3 drop, TCP ACK без SYN drop
               - Шаг 7: Аварийная блокировка при сбое целостности
"""

import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TRAFFIC_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, TRAFFIC_DIR)

import traffic  # noqa: E402


def run_test(name, func):
    print(f"[*] Запуск: {name}...")
    try:
        res = func()
        status = res.get("status")
        expected = res.get("expected")
        if status == expected:
            print(f"    ==> PASSED ({status})")
            return True
        else:
            print(f"    ==> FAILED: ожидалось {expected}, получено {status}")
            return False
    except Exception as e:
        print(f"    ==> ERROR: {e}")
        return False


def test_step1_initial_drop():
    """Шаг 1 демо: трафик полностью блокируется до снятия аварийного режима."""
    res = traffic.check_packet(src_port=1, dst_port=2, proto="icmp", timeout=0.8)
    res["expected"] = "DROP"
    return res


def test_step4_icmp_pass():
    """Шаг 4 демо: ICMP 1 -> 2 разрешен политикой."""
    res = traffic.check_packet(src_port=1, dst_port=2, proto="icmp", timeout=1.0)
    res["expected"] = "PASS"
    return res


def test_step4_tcp_port23_drop():
    """Шаг 4 демо: TCP/23 (telnet) 1 -> 3 отбрасывается политикой."""
    res = traffic.check_packet(src_port=1, dst_port=3, proto="tcp", dport=23, tcp_flags="S", timeout=0.8)
    res["expected"] = "DROP"
    return res


def test_step4_tcp_ack_without_syn_drop():
    """Шаг 4 демо: TCP ACK без предварительного SYN отбрасывается conntrack."""
    res = traffic.check_packet(src_port=1, dst_port=2, proto="tcp", dport=80, tcp_flags="A", timeout=0.8)
    res["expected"] = "DROP"
    return res


def test_step7_emergency_break_drop():
    """Шаг 7 демо: при сбое целостности (break_integrity.sh) трафик блокируется."""
    res = traffic.check_packet(src_port=1, dst_port=2, proto="icmp", timeout=0.8)
    res["expected"] = "DROP"
    return res


def main():
    if not traffic.HAVE_SCAPY:
        print("Ошибка: Scapy не установлен в системе (apt install python3-scapy).", file=sys.stderr)
        sys.exit(1)

    print("==================================================================")
    print("      ДЕМОНСТРАЦИОННЫЙ СЦЕНАРИЙ ГЕНЕРАЦИИ ТРАФИКА (12.11)         ")
    print("==================================================================")

    tests = [
        ("Шаг 1: Блокировка трафика при старте (emergency_mode=1)", test_step1_initial_drop),
        ("Шаг 4а: Разрешенный ICMP 1 -> 2", test_step4_icmp_pass),
        ("Шаг 4б: Запрещенный TCP порт 23 1 -> 3 (drop)", test_step4_tcp_port23_drop),
        ("Шаг 4в: Аномальный TCP ACK без SYN (drop conntrack)", test_step4_tcp_ack_without_syn_drop),
        ("Шаг 7: Блокировка при нарушении целостности", test_step7_emergency_break_drop),
    ]

    passed = 0
    total = len(tests)

    for name, func in tests:
        if run_test(name, func):
            passed += 1

    print("==================================================================")
    print(f" Результат: {passed}/{total} тестов пройдено")
    print("==================================================================")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
