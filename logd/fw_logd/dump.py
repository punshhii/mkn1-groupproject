
"""Afficher le journal binaire des paquets sous forme de tableau."""

import argparse
import ipaddress
from pathlib import Path

from fw_logd.packet_log import PacketLog, RECORD_SIZE


def format_action(action: int) -> str:
    """Convertir le code d'action en texte."""
    actions = {
        0: "ACCEPT",
        1: "DROP",
    }
    return actions.get(action, f"UNKNOWN({action})")


def format_protocol(eth_proto: int, ip_proto: int) -> str:
    """Construire la chaîne de protocoles."""
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
    """Afficher une adresse IPv4."""
    return str(ipaddress.IPv4Address(value))


def format_mac(value: int) -> str:
    """Afficher la valeur MAC en hexadécimal."""
    return f"0x{value:016x}"


def format_timestamp(ts_us: int) -> str:
    """Afficher l'horodatage en microsecondes."""
    return str(ts_us)


def print_records(records: list[dict]) -> None:
    """Afficher les enregistrements dans un tableau."""
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
        description="Afficher le journal binaire des paquets."
    )
    parser.add_argument(
        "path",
        help="Chemin du fichier du journal, par exemple packets.bin",
    )
    args = parser.parse_args()

    path = Path(args.path)

    if not path.exists():
        print(f"Journal introuvable : {path}")
        return 1

    if path.stat().st_size % RECORD_SIZE != 0:
        print(
            f"Journal invalide : la taille doit être un multiple "
            f"de {RECORD_SIZE} octets."
        )
        return 1

    log = PacketLog(str(path), limit_bytes=max(
        RECORD_SIZE, path.stat().st_size
    ))

    try:
        records = log.read_all()
    except (OSError, ValueError) as exc:
        print(f"Erreur de lecture : {exc}")
        return 1

    if not records:
        print("Le journal ne contient aucun paquet.")
        return 0

    print_records(records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
