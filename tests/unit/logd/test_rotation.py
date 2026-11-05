
import os
import tempfile
import unittest

from fw_logd.packet_log import PacketLog
from fw_logd.rotation import enforce_packet_limit, clear_packets


class TestRotation(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.temp_dir.name, "packets.bin")

        # Limite volontairement petite : deux enregistrements de 55 octets.
        self.plog = PacketLog(self.log_path, limit_bytes=110)
        self.events = []

    def tearDown(self):
        self.temp_dir.cleanup()

    def emit_event(self, code):
        self.events.append(code)

    def test_no_packet_overflow(self):
        """Без переполнения событие E36 не регистрируется."""
        self.plog.append(b"A" * 55)
        self.plog.flush()

        result = enforce_packet_limit(self.plog, self.emit_event)

        self.assertFalse(result)
        self.assertEqual(self.events, [])

    def test_packet_overflow(self):
        """При переполнении регистрируется событие E36."""
        for _ in range(3):
            self.plog.append(b"A" * 55)

        self.plog.flush()

        result = enforce_packet_limit(self.plog, self.emit_event)

        self.assertTrue(result)
        self.assertEqual(self.events, ["E36"])
        self.assertEqual(self.plog.count(), 2)

    def test_overflow_event_is_not_repeated(self):
        """Одно переполнение не должно регистрировать E36 повторно."""
        for _ in range(3):
            self.plog.append(b"A" * 55)

        self.plog.flush()

        first_result = enforce_packet_limit(self.plog, self.emit_event)
        second_result = enforce_packet_limit(self.plog, self.emit_event)

        self.assertTrue(first_result)
        self.assertFalse(second_result)
        self.assertEqual(self.events, ["E36"])

    def test_clear_packets(self):
        """Очистка журнала удаляет записи и регистрирует E34."""
        self.plog.append(b"A" * 55)
        self.plog.flush()

        # Добавляем также запись, которая ещё находится в буфере.
        self.plog.append(b"B" * 55)

        clear_packets(self.plog, {"role": "rw"}, self.emit_event)

        self.assertEqual(self.plog.count(), 0)
        self.assertEqual(os.path.getsize(self.log_path), 0)
        self.assertEqual(self.events, ["E34"])


if __name__ == "__main__":
    unittest.main()
