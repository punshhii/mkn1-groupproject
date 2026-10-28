"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-2 Регистрация
Модуль:      event_log
Назначение:  журнал событий в SQLite (схема events, FR-24, FR-25, FR-27, FR-28)
Методы:
  - init_db — открыть/создать базу и таблицу events с индексами
  - write_event — добавить запись в журнал событий
  - count_events — число записей (для rotation)
  - delete_oldest — удалить n самых старых записей (E37)
  - select_events — выборка по коду и интервалу времени (FR-39)
"""
import sqlite3
import time

from fwcommon.codes import EVENTS

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_us      INTEGER NOT NULL,
    event_code TEXT    NOT NULL,
    result     INTEGER NOT NULL,
    actor_type INTEGER NOT NULL,
    actor_id   TEXT,
    actor_ip   TEXT,
    command    TEXT,
    details    TEXT,
    error_code TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts_us);
CREATE INDEX IF NOT EXISTS idx_events_code  ON events(event_code);
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id);
"""


def init_db(path: str) -> sqlite3.Connection:
    """Открыть базу журнала событий, создать схему при первом запуске."""
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def write_event(conn: sqlite3.Connection, event: dict) -> int:
    """Записать событие (поля как в таблице events, payload log.write.event).
    Проверяет event_code (E01..E52); возвращает id записи."""
    code = event.get("event_code")
    if code not in EVENTS:
        raise ValueError("неизвестный код события: %r" % (code,))
    cur = conn.execute(
        "INSERT INTO events (ts_us, event_code, result, actor_type, actor_id, actor_ip,"
        " command, details, error_code) VALUES (?,?,?,?,?,?,?,?,?)",
        (event.get("ts_us", int(time.time() * 1_000_000)), code,
         int(event.get("result", 0)), int(event.get("actor_type", 0)),
         event.get("actor_id"), event.get("actor_ip"), event.get("command"),
         event.get("details"), event.get("error_code")))
    conn.commit()
    return cur.lastrowid


def count_events(conn: sqlite3.Connection) -> int:
    """Вернуть число записей в журнале событий."""
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def delete_oldest(conn: sqlite3.Connection, n: int) -> int:
    """Удалить n самых старых записей; вернуть число удалённых."""
    cur = conn.execute(
        "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT ?)", (n,))
    conn.commit()
    return cur.rowcount


def select_events(conn: sqlite3.Connection, event_code: str = None, from_ts: int = None,
                  to_ts: int = None, limit: int = 100, offset: int = 0) -> list:
    """Выборка событий (FR-39). Критерии необязательны и сочетаются по И:
    event_code — код события; from_ts, to_ts — границы времени в микросекундах (включительно).
    Результат: список словарей от новых к старым; limit/offset — для постраничного вывода."""
    if from_ts is not None and to_ts is not None and from_ts > to_ts:
        raise ValueError("начало интервала позже конца")
    where, args = [], []
    if event_code is not None:
        where.append("event_code = ?")
        args.append(event_code)
    if from_ts is not None:
        where.append("ts_us >= ?")
        args.append(from_ts)
    if to_ts is not None:
        where.append("ts_us <= ?")
        args.append(to_ts)
    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts_us DESC, id DESC LIMIT ? OFFSET ?"
    cur = conn.execute(sql, args + [limit, offset])
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]
