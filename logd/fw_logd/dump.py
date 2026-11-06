"""Отображать бинарный журнал пакетов в виде таблицы."""

import argparse
import ipaddress
from pathlib import Path

from fw_logd.packet_log import PacketLog, RECORD_SIZE


def format_action(action: int) -> str:
    """Преобразовать код действия в текст."""
    actions = {
        0: "ACCEPT",
        1: "DROP",
    }
    return actions.get(action, f"UNKNOWN({action})")


def format_protocol(eth_proto: int, ip_proto: int) -> str:
    """Сформировать строку протоколов."""
    if eth_proto == 0:
        ip_protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }
        transport = ip_protocols.get(
            ip_proto, f"IP({ip_proto})"
        )
        return f"Ethernet/IPv4/{transport}"

    if eth_proto == 1:
        return "Ethernet/ARP"

    if eth_proto == 2:
        return "Ethernet/Other"

    return f"Ethernet/Unknown({eth_proto})"


def format_ipv4(value: int) -> str:
    """Отобразить IPv4-адрес."""
    return str(ipaddress.IPv4Address(value))


def format_mac(value: int) -> str:
    """Отобразить MAC-значение в hex-формате."""
    return f"0x{value:016x}"


def format_timestamp(ts_us: int) -> str:
    """Отобразить метку времени в микросекундах."""
    return str(ts_us)


def print_records(records: list[dict]) -> None:
    """Вывести записи в виде таблицы."""
    columns = [
        ("TIME (us)", lambda r: format_timestamp(r["ts_us"])),
        ("ACTION", lambda r: format_action(r["action"])),
        ("IN", lambda r: str(r["in_iface"])),
        ("OUT", lambda r: str(r["out_ifaces"][:r["out_count"]].hex())),
        ("PROTOCOL", lambda r: format_protocol(
            r["eth_proto"], r["ip_proto"]
        )),
        ("SOURCE", lambda r: format_ipv4(r["src_ip"])),
        ("DESTINATION", lambda r: format_ipv4(r["dst_ip"])),
        ("SPORT", lambda r: str(r["sport"])),
        ("DPORT", lambda r: str(r["dport"])),
        ("RULE", lambda r: str(r["rule_id"])),
    ]

    headers = [title for title, _ in columns]
    rows = [
        [formatter(record) for _, formatter in columns]
        for record in records
    ]

    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows))
        if rows else len(headers[i])
        for i in range(len(headers))
    ]

    print(" | ".join(headers[i].ljust(widths[i])
                      for i in range(len(headers))))
    print("-+-".join("-" * width for width in widths))

    for row in rows:
        print(" | ".join(row[i].ljust(widths[i])
                          for i in range(len(row))))

    print(f"\nTotal: {len(records)} packet(s)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Отображать бинарный журнал пакетов."
    )
    parser.add_argument(
        "path",
        help="Путь к файлу журнала, например packets.bin",
    )
    args = parser.parse_args()

    path = Path(args.path)

    if not path.exists():
        print(f"Журнал не найден: {path}")
        return 1

    if path.stat().st_size % RECORD_SIZE != 0:
        print(
            f"Журнал недействителен: размер должен быть кратным "
            f"{RECORD_SIZE} байтам."
        )
        return 1

    log = PacketLog(str(path), limit_bytes=max(
        RECORD_SIZE, path.stat().st_size
    ))

    try:
        records = log.read_all()
    except (OSError, ValueError) as exc:
        print(f"Ошибка чтения: {exc}")
        return 1

    if not records:
        print("Журнал не содержит пакетов.")
        return 0

    print_records(records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
