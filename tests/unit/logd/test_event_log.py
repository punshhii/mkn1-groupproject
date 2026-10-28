import unittest

from fw_logd import event_log, rotation


def fresh_db():
    return event_log.init_db(":memory:")


class EventLogTest(unittest.TestCase):
    def test_init_creates_table(self):
        db = fresh_db()
        self.assertEqual(event_log.count_events(db), 0)

    def test_write_returns_increasing_id(self):
        db = fresh_db()
        a = event_log.write_event(db, {"event_code": "E01", "result": 1})
        b = event_log.write_event(db, {"event_code": "E02", "result": 0})
        self.assertEqual(b, a + 1)

    def test_fields_are_saved(self):
        db = fresh_db()
        event_log.write_event(db, {"event_code": "E01", "result": 1, "actor_id": "admin",
                                   "actor_ip": "10.0.0.5", "ts_us": 123})
        row = db.execute("SELECT ts_us, event_code, result, actor_id, actor_ip FROM events").fetchone()
        self.assertEqual(row, (123, "E01", 1, "admin", "10.0.0.5"))

    def test_bad_code_rejected_and_not_written(self):
        db = fresh_db()
        with self.assertRaises(ValueError):
            event_log.write_event(db, {"event_code": "E99"})
        self.assertEqual(event_log.count_events(db), 0)

    def test_delete_oldest_removes_first_records(self):
        db = fresh_db()
        for i in range(5):
            event_log.write_event(db, {"event_code": "E01", "result": 1, "ts_us": i})
        self.assertEqual(event_log.delete_oldest(db, 2), 2)
        left = [r[0] for r in db.execute("SELECT ts_us FROM events ORDER BY id")]
        self.assertEqual(left, [2, 3, 4])


class SelectTest(unittest.TestCase):
    def _db(self):
        db = fresh_db()
        for ts, code in [(10, "E01"), (20, "E02"), (30, "E01"), (40, "E02")]:
            event_log.write_event(db, {"event_code": code, "result": 1, "ts_us": ts})
        return db

    def test_no_filter_returns_all_newest_first(self):
        rows = event_log.select_events(self._db())
        self.assertEqual([r["ts_us"] for r in rows], [40, 30, 20, 10])

    def test_by_code(self):
        rows = event_log.select_events(self._db(), event_code="E01")
        self.assertEqual([r["ts_us"] for r in rows], [30, 10])

    def test_by_interval(self):
        rows = event_log.select_events(self._db(), from_ts=20, to_ts=30)
        self.assertEqual([r["ts_us"] for r in rows], [30, 20])

    def test_code_and_interval(self):
        rows = event_log.select_events(self._db(), event_code="E02", from_ts=15)
        self.assertEqual([r["ts_us"] for r in rows], [40, 20])

    def test_empty_result(self):
        self.assertEqual(event_log.select_events(self._db(), event_code="E05"), [])

    def test_paging(self):
        rows = event_log.select_events(self._db(), limit=2, offset=1)
        self.assertEqual([r["ts_us"] for r in rows], [30, 20])

    def test_bad_interval(self):
        with self.assertRaises(ValueError):
            event_log.select_events(self._db(), from_ts=50, to_ts=10)


class EventLimitTest(unittest.TestCase):
    def _fill(self, db, n):
        for i in range(n):
            event_log.write_event(db, {"event_code": "E01", "result": 1, "details": "x" * 200})

    def test_under_limit_nothing_deleted(self):
        db = fresh_db()
        self._fill(db, 3)
        seen = []
        self.assertEqual(rotation.enforce_event_limit(db, 10_000_000, seen.append), 0)
        self.assertEqual(seen, [])
        self.assertEqual(event_log.count_events(db), 3)

    def test_over_limit_deletes_old_and_emits_e37(self):
        db = fresh_db()
        self._fill(db, 300)
        seen = []
        deleted = rotation.enforce_event_limit(db, 60_000, seen.append)
        self.assertGreater(deleted, 0)
        self.assertEqual(seen, ["E37"])
        self.assertEqual(event_log.count_events(db), 300 - deleted)
        self.assertGreater(event_log.count_events(db), 0)
        self.assertLessEqual(rotation._used_bytes(db), 60_000)


if __name__ == "__main__":
    unittest.main()
