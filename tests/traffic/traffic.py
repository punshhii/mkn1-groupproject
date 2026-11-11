#!/usr/bin/env python3
"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  тестовый стенд (tests/traffic)
Модуль:      traffic.py
Назначение:  генератор и анализатор сетевого трафика на базе Scapy для проверки
             работы прозрачного МЭ (L2).
Команды:
  send   - сборка и отправка произвольного кадра с порта N
  check  - отправка маркированного кадра с порта N и проверка его выхода на других портах
  run    - запуск набора сценариев для демонстрации

Использование:
  sudo python3 tests/traffic/traffic.py send --src-port 1 --dst-port 2 --proto icmp
  sudo python3 tests/traffic/traffic.py check --src-port 1 --dst-port 2 --proto tcp --dport 80
  sudo python3 tests/traffic/traffic.py run tests/traffic/scenarios/demo_scenario.py
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time

try:
    from scapy.all import (
        AsyncSniffer,
        Ether,
        IP,
        TCP,
        UDP,
        ICMP,
        ARP,
        Raw,
        sendp,
        conf
    )
    conf.verb = 0
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOPOLOGY_FILE = os.path.join(SCRIPT_DIR, "topology.json")


def load_topology(path=None):
    top_path = path or TOPOLOGY_FILE
    if not os.path.exists(top_path):
        raise FileNotFoundError(f"Файл топологии не найден: {top_path}")
    with open(top_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if not k.startswith("_")}


def craft_packet(src_info, dst_info, proto="icmp", sport=None, dport=None,
                 tcp_flags="S", bad_csum=False, payload_data=b"",
                 ip_id=None):
    if not HAVE_SCAPY:
        raise RuntimeError("Для работы генератора требуется библиотека Scapy: apt install python3-scapy")

    smac = src_info.get("mac", "02:00:00:00:00:01")
    dmac = dst_info.get("mac", "02:00:00:00:00:02")
    sip = src_info.get("ip", "10.10.0.1")
    dip = dst_info.get("ip", "10.10.0.2")

    eth = Ether(src=smac, dst=dmac)

    if proto.lower() == "arp":
        pkt = eth / ARP(op=1, hwsrc=smac, psrc=sip, hwdst=dmac, pdst=dip)
        return pkt

    if ip_id is None:
        ip_id = random.randint(10000, 60000)

    ip_layer = IP(src=sip, dst=dip, id=ip_id)
    if bad_csum:
        ip_layer.chksum = 0xBADC

    l4 = None
    proto_l = proto.lower()
    if proto_l == "icmp":
        l4 = ICMP(type=8, code=0)
    elif proto_l == "tcp":
        sp = sport or random.randint(1024, 65535)
        dp = dport or 80
        l4 = TCP(sport=sp, dport=dp, flags=tcp_flags, seq=1000)
    elif proto_l == "udp":
        sp = sport or random.randint(1024, 65535)
        dp = dport or 53
        l4 = UDP(sport=sp, dport=dp)
    else:
        l4 = Raw(load=payload_data)

    if payload_data and proto_l != "raw":
        pkt = eth / ip_layer / l4 / Raw(load=payload_data)
    else:
        pkt = eth / ip_layer / l4

    return pkt


def run_in_netns(netns, cmd):
    if not netns:
        return subprocess.run(cmd, check=True)
    full_cmd = ["ip", "netns", "exec", netns] + cmd
    return subprocess.run(full_cmd, check=True)


def send_packet(src_port, dst_port, proto="icmp", sport=None, dport=None,
                tcp_flags="S", bad_csum=False, count=1, payload=""):
    topology = load_topology()
    src_info = topology[str(src_port)]
    dst_info = topology[str(dst_port)]

    pkt = craft_packet(src_info, dst_info, proto=proto, sport=sport, dport=dport,
                       tcp_flags=tcp_flags, bad_csum=bad_csum, payload_data=payload.encode("utf-8"))

    iface = src_info.get("iface", f"veth-h{src_port}")
    netns = src_info.get("netns")

    # Если мы запускаемся внутри netns или на хосте
    for _ in range(count):
        sendp(pkt, iface=iface, verbose=False)

    return {"status": "SENT", "src_port": src_port, "dst_port": dst_port, "count": count}


def check_packet(src_port, dst_port, proto="icmp", sport=None, dport=None,
                 tcp_flags="S", bad_csum=False, timeout=1.5):
    """
    Отправляет зондирующий пакет с уникальной меткой и прослушивает интерфейсы
    всех остальных портов на предмет выхода пакета.
    """
    topology = load_topology()
    src_info = topology[str(src_port)]
    dst_info = topology[str(dst_port)]

    marker = f"FW_MARK_{random.randint(100000, 999999)}"
    test_id = random.randint(20000, 65000)

    pkt = craft_packet(src_info, dst_info, proto=proto, sport=sport, dport=dport,
                       tcp_flags=tcp_flags, bad_csum=bad_csum,
                       payload_data=marker.encode("utf-8"), ip_id=test_id)

    # Определяем интерфейсы для прослушивания (порты МЭ на хосте: eth1..eth5)
    listen_ifaces = []
    iface_to_port = {}
    for p_id, p_info in topology.items():
        if int(p_id) != int(src_port):
            # Слушаем либо на fw_iface (хост-сторона), либо на iface
            fw_if = p_info.get("fw_iface", f"eth{p_id}")
            listen_ifaces.append(fw_if)
            iface_to_port[fw_if] = int(p_id)

    captured_ports = set()

    def packet_filter(p):
        if Raw in p and marker.encode("utf-8") in p[Raw].load:
            return True
        if IP in p and p[IP].id == test_id:
            return True
        return False

    def handle_packet(p):
        sniff_iface = getattr(p, "sniffed_on", None)
        if sniff_iface in iface_to_port:
            captured_ports.add(iface_to_port[sniff_iface])
        else:
            captured_ports.add(int(dst_port))

    # Запуск параллельного сниффера
    sniffer = None
    try:
        # Проверяем, доступны ли интерфейсы для прослушивания
        sniffer = AsyncSniffer(iface=listen_ifaces, prn=handle_packet, lfilter=packet_filter, store=False)
        sniffer.start()
    except Exception as e:
        # Fallback: если не удается слушать массив интерфейсов, пробуем целевой интерфейс
        fw_target = dst_info.get("fw_iface", f"eth{dst_port}")
        sniffer = AsyncSniffer(iface=fw_target, prn=handle_packet, lfilter=packet_filter, store=False)
        sniffer.start()

    time.sleep(0.1)  # Даем снифферу время запуститься

    # Отправляем зондирующий кадр со стороны источника
    src_iface = src_info.get("iface", f"veth-h{src_port}")
    sendp(pkt, iface=src_iface, verbose=False)

    time.sleep(timeout)
    if sniffer:
        sniffer.stop()

    received_list = sorted(list(captured_ports))
    if received_list:
        return {
            "status": "PASS",
            "received_on": received_list,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "proto": proto
        }
    else:
        return {
            "status": "DROP",
            "received_on": [],
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "proto": proto
        }


def main():
    parser = argparse.ArgumentParser(description="Scapy Traffic Generator & Verifier for fw-filter")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: send
    p_send = subparsers.add_parser("send", help="Отправить пакет")
    p_send.add_argument("--src-port", type=int, default=1, help="Номер порта источника (1..5)")
    p_send.add_argument("--dst-port", type=int, default=2, help="Номер порта назначения (1..5)")
    p_send.add_argument("--proto", choices=["icmp", "tcp", "udp", "arp"], default="icmp")
    p_send.add_argument("--sport", type=int, default=None)
    p_send.add_argument("--dport", type=int, default=None)
    p_send.add_argument("--tcp-flags", default="S")
    p_send.add_argument("--bad-csum", action="store_true")
    p_send.add_argument("--count", type=int, default=1)
    p_send.add_argument("--payload", default="TEST_PAYLOAD")

    # Subcommand: check
    p_check = subparsers.add_parser("check", help="Отправить пакет и проверить прохождение")
    p_check.add_argument("--src-port", type=int, default=1, help="Номер порта источника (1..5)")
    p_check.add_argument("--dst-port", type=int, default=2, help="Номер порта назначения (1..5)")
    p_check.add_argument("--proto", choices=["icmp", "tcp", "udp", "arp"], default="icmp")
    p_check.add_argument("--sport", type=int, default=None)
    p_check.add_argument("--dport", type=int, default=None)
    p_check.add_argument("--tcp-flags", default="S")
    p_check.add_argument("--bad-csum", action="store_true")
    p_check.add_argument("--timeout", type=float, default=1.0)
    p_check.add_argument("--expect", choices=["PASS", "DROP"], default=None)

    # Subcommand: run
    p_run = subparsers.add_parser("run", help="Запустить сценарий проверки")
    p_run.add_argument("scenario", help="Путь к файлу сценария .py")

    args = parser.parse_args()

    if not HAVE_SCAPY:
        print(json.dumps({
            "status": "ERROR",
            "error": "Scapy is not installed. Run: apt install python3-scapy"
        }))
        sys.exit(1)

    if args.subcommand == "send":
        res = send_packet(args.src_port, args.dst_port, proto=args.proto, sport=args.sport,
                          dport=args.dport, tcp_flags=args.tcp_flags, bad_csum=args.bad_csum,
                          count=args.count, payload=args.payload)
        print(json.dumps(res, indent=2))
        sys.exit(0)

    elif args.subcommand == "check":
        res = check_packet(args.src_port, args.dst_port, proto=args.proto, sport=args.sport,
                           dport=args.dport, tcp_flags=args.tcp_flags, bad_csum=args.bad_csum,
                           timeout=args.timeout)
        print(json.dumps(res, indent=2))
        if args.expect:
            if res["status"] != args.expect:
                sys.exit(1)
        sys.exit(0 if res["status"] == "PASS" else 1)

    elif args.subcommand == "run":
        if not os.path.exists(args.scenario):
            print(f"Ошибка: сценарий {args.scenario} не найден", file=sys.stderr)
            sys.exit(1)
        # Запуск сценария как отдельного процесса Python
        res = subprocess.run([sys.executable, args.scenario])
        sys.exit(res.returncode)


if __name__ == "__main__":
    main()
