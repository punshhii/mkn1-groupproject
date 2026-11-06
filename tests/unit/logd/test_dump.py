"""Тесты для проверки отображения журнала пакетов."""

import contextlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fw_logd import dump
from fw_logd.packet_log import RECORD_FMT


def make_record(
    ts_us=1_000_000,
    action=0,
    rule_id=1,
    eth_proto=0,
    ip_proto=6,
    src_ip=0xC0A80101,
    dst_ip=0xC0A80102,
    sport=12345,
    dport=443,
):
    """Создать бинарную тестовую запись длиной 55 байт."""
    return struct.pack(
        RECORD_FMT,
        ts_us,                  # timestamp
        action,                 # действие
        1,                      # входящий интерфейс
        0,                      # количество исходящих интерфейсов
        bytes([255] * 6),       # неиспользуемые исходящие интерфейсы
        rule_id,                # идентификатор правила
        0,                      # идентификатор соединения
        eth_proto,              # протокол Ethernet
        ip_proto,               # протокол IP
        0,                      # MAC-адрес источника
        0,                      # MAC-адрес назначения
        src_ip,
        dst_ip,
        sport,
        dport,
        8 if ip_proto == 1 else 0,  # тип ICMP
        0,                      # код ICMP
    )


class TestDump(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.directory = Path(self.temp_dir.name)

    def run_dump(self, path):
        """Выполнить main() и захватить вывод."""
        output = io.StringIO()

        with (
            patch.object(sys, "argv", ["fw_logd.dump", str(path)]),
            contextlib.redirect_stdout(output),
        ):
            exit_code = dump.main()

        return exit_code, output.getvalue()

    def test_display_multiple_packets(self):
        """Корректно отображать несколько протоколов."""
        path = self.directory / "packets.bin"
        records = [
            make_record(),
            make_record(
                ts_us=2_000_000,
                action=1,
                rule_id=2,
                ip_proto=17,
                src_ip=0xC0A80103,
                dst_ip=0xC0A80104,
                sport=53000,
                dport=53,
            ),
            make_record(
                ts_us=3_000_000,
                rule_id=3,
                ip_proto=1,
                src_ip=0xC0A80105,
                dst_ip=0xC0A80106,
                sport=0,
                dport=0,
            ),
        ]
        path.write_bytes(b"".join(records))

        exit_code, output = self.run_dump(path)

        self.assertEqual(exit_code, 0)
        self.assertIn("Ethernet/IPv4/TCP", output)
        self.assertIn("Ethernet/IPv4/UDP", output)
        self.assertIn("Ethernet/IPv4/ICMP", output)
        self.assertIn("192.168.1.1", output)
        self.assertIn("192.168.1.4", output)
        self.assertIn("12345", output)
        self.assertIn("53000", output)
        self.assertIn("ACCEPT", output)
        self.assertIn("DROP", output)
        self.assertIn("Total: 3 packet(s)", output)

    def test_empty_journal(self):
        """Сообщать, что пустой журнал не содержит пакетов."""
        path = self.directory / "empty.bin"
        path.write_bytes(b"")

        exit_code, output = self.run_dump(path)

        self.assertEqual(exit_code, 0)
        self.assertIn("Журнал не содержит пакетов.", output)

    def test_invalid_file_size(self):
        """Отказывать файлу, размер которого не кратен 55."""
        path = self.directory / "invalid.bin"
        path.write_bytes(b"test")

        exit_code, output = self.run_dump(path)

        self.assertEqual(exit_code, 1)
        self.assertIn("Журнал недействителен", output)

    def test_missing_file(self):
        """Сообщать об отсутствии файла."""
        path = self.directory / "missing.bin"

        exit_code, output = self.run_dump(path)

        self.assertEqual(exit_code, 1)
        self.assertIn("Журнал не найден", output)


if __name__ == "__main__":
    unittest.main()
