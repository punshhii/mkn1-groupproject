import os
import struct
import tempfile
import unittest

from fw_logd.packet_log import (
    PacketLog,
    RECORD_FMT,
    RECORD_SIZE,
    unpack_record,
)


def make_record(ts_us: int) -> bytes:
    """Создать бинарную тестовую запись размером 55 байт."""
    return struct.pack(
        RECORD_FMT,
        ts_us,          # ts_us
        1,              # action
        0,              # in_iface
        0,              # out_count
        bytes(6),       # out_ifaces
        1,              # rule_id
        1,              # conn_id
        0,              # eth_proto
        6,              # ip_proto
        0,              # smac
        0,              # dmac
        0,              # src_ip
        0,              # dst_ip
        80,             # sport
        443,            # dport
        0,              # icmp_type
        0,              # icmp_code
    )


class TestUnpackRecord(unittest.TestCase):

    def test_record_size(self):
        raw = make_record(100)
        self.assertEqual(len(raw), RECORD_SIZE)
        self.assertEqual(RECORD_SIZE, 55)

    def test_unpack_valid_record(self):
        record = unpack_record(make_record(12345))

        self.assertIsInstance(record, dict)
        self.assertEqual(record["ts_us"], 12345)
        self.assertEqual(record["action"], 1)
        self.assertEqual(record["sport"], 80)
        self.assertEqual(record["dport"], 443)
        self.assertEqual(record["ip_proto"], 6)

    def test_unpack_record_too_short(self):
        with self.assertRaises(ValueError):
            unpack_record(b"\x00" * 3)

    def test_unpack_record_too_long(self):
        with self.assertRaises(ValueError):
            unpack_record(b"\x00" * 56)

    def test_unpack_record_wrong_type(self):
        with self.assertRaises(TypeError):
            unpack_record("not bytes")


class TestPacketLog(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(
            self.temp_dir.name,
            "packets.bin",
        )
        self.log = PacketLog(
            self.path,
            limit_bytes=10 * RECORD_SIZE,
        )

    def tearDown(self):
        self.log.stop_flusher()
        self.temp_dir.cleanup()

    def test_append_and_read_all(self):
        self.log.append(make_record(100))
        self.log.append(make_record(200))

        records = self.log.read_all()

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["ts_us"], 100)
        self.assertEqual(records[1]["ts_us"], 200)

    def test_append_wrong_size(self):
        with self.assertRaises(ValueError):
            self.log.append(b"\x00" * 3)

    def test_append_wrong_type(self):
        with self.assertRaises(TypeError):
            self.log.append("not bytes")

    def test_flush_writes_file(self):
        self.log.append(make_record(100))
        self.log.append(make_record(200))

        self.log.flush()

        self.assertTrue(os.path.exists(self.path))
        self.assertEqual(
            os.path.getsize(self.path),
            2 * RECORD_SIZE,
        )
        self.assertEqual(len(self.log.buffer), 0)

        records = self.log.read_all()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["ts_us"], 100)
        self.assertEqual(records[1]["ts_us"], 200)

    def test_flush_respects_size_limit(self):
        log = PacketLog(
            self.path,
            limit_bytes=2 * RECORD_SIZE,
        )

        log.append(make_record(100))
        log.append(make_record(200))
        log.append(make_record(300))
        log.flush()

        records = log.read_all()

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["ts_us"], 200)
        self.assertEqual(records[1]["ts_us"], 300)

    def test_read_all_missing_file(self):
        records = self.log.read_all()
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
