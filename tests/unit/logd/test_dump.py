
"""Tests unitaires pour l'affichage du journal de paquets."""

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
    """Créer un enregistrement binaire de test de 55 octets."""
    return struct.pack(
        RECORD_FMT,
        ts_us,                  # timestamp
        action,                 # action
        1,                      # interface d'entrée
        0,                      # nombre d'interfaces de sortie
        bytes([255] * 6),       # interfaces de sortie inutilisées
        rule_id,                # identifiant de règle
        0,                      # identifiant de connexion
        eth_proto,              # protocole Ethernet
        ip_proto,               # protocole IP
        0,                      # adresse MAC source
        0,                      # adresse MAC destination
        src_ip,
        dst_ip,
        sport,
        dport,
        8 if ip_proto == 1 else 0,  # type ICMP
        0,                      # code ICMP
    )


class TestDump(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.directory = Path(self.temp_dir.name)

    def run_dump(self, path):
        """Exécuter main() et capturer son affichage."""
        output = io.StringIO()

        with (
            patch.object(sys, "argv", ["fw_logd.dump", str(path)]),
            contextlib.redirect_stdout(output),
        ):
            exit_code = dump.main()

        return exit_code, output.getvalue()

    def test_display_multiple_packets(self):
        """Afficher correctement plusieurs protocoles."""
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
        """Signaler qu'un journal vide ne contient aucun paquet."""
        path = self.directory / "empty.bin"
        path.write_bytes(b"")

        exit_code, output = self.run_dump(path)

        self.assertEqual(exit_code, 0)
        self.assertIn("Le journal ne contient aucun paquet.", output)

    def test_invalid_file_size(self):
        """Refuser un fichier dont la taille n'est pas un multiple de 55."""
        path = self.directory / "invalid.bin"
        path.write_bytes(b"test")

        exit_code, output = self.run_dump(path)

        self.assertEqual(exit_code, 1)
        self.assertIn("Journal invalide", output)

    def test_missing_file(self):
        """Signaler un fichier inexistant."""
        path = self.directory / "missing.bin"

        exit_code, output = self.run_dump(path)

        self.assertEqual(exit_code, 1)
        self.assertIn("Journal introuvable", output)


if __name__ == "__main__":
    unittest.main()
