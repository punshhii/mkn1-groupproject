"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-2 Регистрация
Модуль:      test_query
Назначение:  Unit-тесты для модуля query
"""

import unittest
import sqlite3
from fw_logd.query import validate_event_filter, validate_packet_filter, query_events, match_packet, query_packets

class TestValidateEventFilter(unittest.TestCase):

    def test_valid_filter_interval(self):
        """Успешный сценарий: начало периода раньше конца."""
        valid_filter = {
            "event_code": "EVT_ADMIN_LOGIN",
            "from_ts": "2026-10-27T10:00:00Z",
            "to_ts": "2026-10-27T12:00:00Z"
        }
        try:
            validate_event_filter(valid_filter)
        except ValueError:
            self.fail("validate_event_filter поднял ValueError на корректных данных")

    def test_invalid_filter_interval(self):
        """Ошибка: начало периода позже конца (должен вернуть ValueError с кодом M06)."""
        invalid_filter = {
            "event_code": "EVT_ADMIN_LOGIN",
            "from_ts": "2026-10-27T15:00:00Z",
            "to_ts": "2026-10-27T12:00:00Z"
        }
        with self.assertRaises(ValueError) as context:
            validate_event_filter(invalid_filter)
        
        self.assertIn("M06", str(context.exception))

    def test_missing_one_interval_bound(self):
        """Успешный сценарий: указана только одна из границ времени."""
        partial_filter = {
            "event_code": "EVT_POLICY_CHANGE",
            "from_ts": "2026-10-27T15:00:00Z"
        }
        try:
            validate_event_filter(partial_filter)
        except ValueError:
            self.fail("validate_event_filter упал при частичном указании интервала")

class TestValidatePacketFilter(unittest.TestCase):

    def test_valid_packet_filter(self):
        """Успешный сценарий: все сетевые параметры указаны корректно."""
        valid_f = {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.5",
            "sport": 443,
            "dport": 80,
            "smac": "00:0C:29:AB:CD:EF",
            "from_ts": "2026-10-27T10:00:00Z",
            "to_ts": "2026-10-27T12:00:00Z"
        }
        try:
            validate_packet_filter(valid_f)
        except ValueError:
            self.fail("validate_packet_filter упал на корректных сетевых данных")

    def test_invalid_packet_ip(self):
        """Ошибка: передан некорректный IP-адрес."""
        invalid_f = {"src_ip": "999.1.1.1"}
        with self.assertRaises(ValueError):
            validate_packet_filter(invalid_f)

    def test_invalid_packet_port(self):
        """Ошибка: передан порт вне диапазона 1-65535."""
        invalid_f = {"dport": 99999}
        with self.assertRaises(ValueError):
            validate_packet_filter(invalid_f)

    def test_invalid_packet_mac(self):
        """Ошибка: передан некорректный MAC-адрес."""
        invalid_f = {"smac": "ЗДЕСЬ-НЕ-MAC-АДРЕС"}
        with self.assertRaises(ValueError):
            validate_packet_filter(invalid_f)

class TestQueryEvents(unittest.TestCase):

    def setUp(self):
        # Создаем временную БД в памяти для тестов
        self.conn = sqlite3.connect(":memory:")
        self.cursor = self.conn.cursor()
        # Создаем таблицу событий на основе структуры проекта
        self.cursor.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT,
                timestamp TEXT,
                description TEXT
            )
        """)
        # Наполняем тестовыми данными
        self.cursor.executemany("""
            INSERT INTO events (code, timestamp, description) VALUES (?, ?, ?)
        """, [
            ("EVT_ADMIN_LOGIN", "2026-10-27T10:00:00Z", "Login success"),
            ("EVT_POLICY_CHANGE", "2026-10-27T11:00:00Z", "Policy updated"),
            ("EVT_ADMIN_LOGIN", "2026-10-27T12:00:00Z", "Login 2 success")
        ])
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_query_events_all(self):
        """Тест: выборка без фильтров должна вернуть все записи."""
        result = query_events(self.conn, {}, page=1, page_size=10)
        self.assertEqual(result["total"], 3)
        self.assertEqual(len(result["items"]), 3)

    def test_query_events_filter_by_code(self):
        """Тест: фильтрация по коду события."""
        result = query_events(self.conn, {"event_code": "EVT_POLICY_CHANGE"}, page=1, page_size=10)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["code"], "EVT_POLICY_CHANGE")

    def test_query_events_pagination(self):
        """Тест: постраничный вывод (FR-39) — 1 элемент на страницу."""
        result = query_events(self.conn, {}, page=2, page_size=1)
        self.assertEqual(result["total"], 3)
        self.assertEqual(len(result["items"]), 1)

    def test_query_events_invalid_filter_raises(self):
        """Тест: некорректный фильтр должен вызывать ValueError (M06)."""
        bad_filter = {"from_ts": "2026-10-27T15:00:00Z", "to_ts": "2026-10-27T10:00:00Z"}
        with self.assertRaises(ValueError):
            query_events(self.conn, bad_filter, page=1, page_size=10)

class TestMatchPacket(unittest.TestCase):

    def setUp(self):
        # Эмулируем типичную запись пакета из лога МЭ
        self.sample_packet = {
            "timestamp": "2026-10-27T12:00:00Z",
            "action": "DROP",
            "rule_id": 5,
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "sport": 49152,
            "dport": 80,
            "smac": "00:0C:29:AB:CD:EF",
            "dmac": "00:0C:29:12:34:56"
        }

    def test_match_all_criteria(self):
        """Тест: полное совпадение по всем критериям."""
        filt = {"action": "DROP", "src_ip": "192.168.1.50", "dport": 80}
        self.assertTrue(match_packet(self.sample_packet, filt))

    def test_mismatch_single_criterion(self):
        """Тест: одно из полей не совпало (должно вернуть False)."""
        filt = {"action": "DROP", "src_ip": "192.168.1.50", "dport": 443} # Не тот порт
        self.assertFalse(match_packet(self.sample_packet, filt))

    def test_match_time_bounds(self):
        """Тест: запись успешно попадает во временной диапазон."""
        filt = {
            "from_ts": "2026-10-27T10:00:00Z",
            "to_ts": "2026-10-27T14:00:00Z"
        }
        self.assertTrue(match_packet(self.sample_packet, filt))

    def test_mismatch_time_bounds(self):
        """Тест: запись находится вне временного диапазона фильтра."""
        filt = {
            "from_ts": "2026-10-27T13:00:00Z" # Запись сделана раньше начала фильтра
        }
        self.assertFalse(match_packet(self.sample_packet, filt))

class MockPacketLog:
    """Заглушка журнала пакетов для имитации метода read_all."""
    def __init__(self, records):
        self.records = records
        
    def read_all(self):
        return self.records

class TestQueryPackets(unittest.TestCase):

    def setUp(self):
        # Наполняем фейковый журнал тестовыми пакетами
        self.mock_records = [
            {"timestamp": "2026-10-27T10:00:00Z", "protocol": "TCP", "dport": 80, "action": "ACCEPT"},
            {"timestamp": "2026-10-27T11:00:00Z", "protocol": "UDP", "dport": 53, "action": "DROP"},
            {"timestamp": "2026-10-27T12:00:00Z", "protocol": "TCP", "dport": 443, "action": "ACCEPT"}
        ]
        self.plog = MockPacketLog(self.mock_records)

    def test_query_packets_no_filter(self):
        """Тест: выборка всех пакетов без фильтра (сортировка от новых к старым)."""
        result = query_packets(self.plog, {}, page=1, page_size=10)
        self.assertEqual(result["total"], 3)
        # Проверяем, что первый элемент на выдаче — самый свежий (12:00:00)
        self.assertEqual(result["items"][0]["dport"], 443)

    def test_query_packets_with_filter(self):
        """Тест: фильтрация пакетов по действию DROP."""
        result = query_packets(self.plog, {"action": "DROP"}, page=1, page_size=10)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["protocol"], "UDP")

    def test_query_packets_paging(self):
        """Тест: пагинация пакетов — вторая страница при размере 1."""
        result = query_packets(self.plog, {}, page=2, page_size=1)
        self.assertEqual(result["total"], 3)
        self.assertEqual(len(result["items"]), 1)
        # Вторая запись с конца — это UDP (11:00:00)
        self.assertEqual(result["items"][0]["protocol"], "UDP")


if __name__ == "__main__":
    unittest.main()
