"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-2 Регистрация
Модуль:      query
Назначение:  выборки по FR-39 с постраничным выводом; проверка критериев на входе
Методы:
  - validate_event_filter — проверить критерии выборки событий (код, интервал времени)
  - validate_packet_filter — проверить критерии выборки пакетов (адреса, порты, интервал)
  - query_events — страница событий из SQLite
  - match_packet — подходит ли запись пакета под фильтр
  - query_packets — страница пакетов (линейный проход по журналу)
"""

import re
import json
import sqlite3
from datetime import datetime, timezone
from fw_logd import event_log

def _parse_ts_to_us(val) -> int:
    """Перевести строку времени YYYY-MM-DD hh:mm:ss (или ISO) в микросекунды."""
    if isinstance(val, (int, float)):
        return int(val)
    if not isinstance(val, str):
        raise ValueError("M06")

    s = val.strip()
    try:
        # Поддержка строгого формата YYYY-MM-DD hh:mm:ss и ISO-строк
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1_000_000)
    except ValueError:
        raise ValueError("M06")

def _extract_time_bounds(f: dict):
    """Извлечь и перевести в микросекунды границы времени (поддержка from/to и from_ts/to_ts)."""
    raw_from = f.get("from_ts") if f.get("from_ts") not in (None, "") else f.get("from")
    raw_to = f.get("to_ts") if f.get("to_ts") not in (None, "") else f.get("to")

    start_us = _parse_ts_to_us(raw_from) if raw_from not in (None, "") else None
    end_us = _parse_ts_to_us(raw_to) if raw_to not in (None, "") else None

    if start_us is not None and end_us is not None and start_us > end_us:
        raise ValueError("M06")

    return start_us, end_us

def validate_event_filter(f: dict) -> None:
    """Критерии: code/event_code, from/from_ts, to/to_ts. Начало не позже конца; иначе ValueError (M06)."""
    if not isinstance(f, dict):
        raise ValueError("M06")
    _extract_time_bounds(f)
    
# Вспомогательная функция для чтения паттернов из common/validation.json
def _get_validation_patterns() -> dict:
    try:
        with open("common/validation.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            return {
                "ip": data.get("ip_pattern", r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"),
                "mac": data.get("mac_pattern", r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
            }
    except Exception:
        # Если файл еще не создан, используем стандартные регулярные выражения
        return {
            "ip": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
            "mac": r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        }

def validate_packet_filter(f: dict) -> None:
    """Критерии: action, in_iface, out_iface, rule_id, smac, dmac, src_ip, dst_ip, sport, dport,
    from_ts, to_ts; форматы по common/validation.json. ValueError (M06) при ошибке."""
    if not isinstance(f, dict):
        raise ValueError("M06")

    _extract_time_bounds(f)
    # Проверка временного интервала (from_ts не позже to_ts)
    from_ts = f.get("from_ts")
    to_ts = f.get("to_ts")

    start_us = _parse_ts_to_us(from_ts) if from_ts is not None and from_ts != "" else None
    end_us = _parse_ts_to_us(to_ts) if to_ts is not None and to_ts != "" else None

    if start_us is not None and end_us is not None and start_us > end_us:
        raise ValueError("M06")

    # Загружаем регулярные выражения из общего файла
    patterns = _get_validation_patterns()

    # Проверка форматов IP-адресов (Строго 0-255 для каждого октета)
    for ip_field in ["src_ip", "dst_ip"]:
        ip_val = f.get(ip_field)
        if ip_val:
            ip_str = str(ip_val)
            # Базовая проверка по маске регулярного выражения
            if not re.match(patterns["ip"], ip_str):
                raise ValueError("M06")
            # Строгая проверка числовых диапазонов октетов (0-255)
            try:
                parts = [int(p) for p in ip_str.split(".")]
                if len(parts) != 4 or any(not (0 <= p <= 255) for p in parts):
                    raise ValueError("M06")
            except (ValueError, TypeError):
                raise ValueError("M06")


    # Проверка форматов MAC-адресов
    for mac_field in ["smac", "dmac"]:
        mac_val = f.get(mac_field)
        if mac_val and not re.match(patterns["mac"], str(mac_val)):
            raise ValueError("M06")

    # Проверка числовых диапазонов портов (sport, dport должны быть от 1 до 65535)
    for port_field in ["sport", "dport"]:
        port_val = f.get(port_field)
        if port_val is not None:
            try:
                port_num = int(port_val)
                if not (1 <= port_num <= 65535):
                    raise ValueError("M06")
            except (ValueError, TypeError):
                raise ValueError("M06")

    # Проверка rule_id (идентификатор правила должен быть положительным числом)
    rule_id = f.get("rule_id")
    if rule_id is not None:
        try:
            if int(rule_id) < 0:
                raise ValueError("M06")
        except (ValueError, TypeError):
            raise ValueError("M06")

def query_events(conn: sqlite3.Connection, f: dict, page: int, page_size: int) -> dict:
    """Вернуть {'items': [...], 'total': N}; пустая выборка — items=[] (клиент покажет M13)."""
    validate_event_filter(f)

    page = max(1, int(page))
    page_size = max(1, int(page_size))
    offset = (page - 1) * page_size

    event_code = f.get("event_code") or f.get("code")
    from_us, to_us = _extract_time_bounds(f)

    conditions = []
    params = []

    if event_code:
        conditions.append("event_code = ?")
        params.append(event_code)

    if from_us is not None:
        conditions.append("ts_us >= ?")
        params.append(from_us)

    if to_us is not None:
        conditions.append("ts_us <= ?")
        params.append(to_us)

    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
    cursor = conn.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM events{where_clause}", params)
    row = cursor.fetchone()
    total_count = row[0] if row else 0

    items = event_log.select_events(
        conn,
        event_code=event_code,
        from_ts=from_us,
        to_ts=to_us,
        limit=page_size,
        offset=offset
    )

    return {
        "items": items,
        "total": total_count
    }


def match_packet(rec: dict, f: dict) -> bool:
    """True, если запись удовлетворяет всем заданным критериям (критерии сочетаются по И)."""
    if not isinstance(f, dict) or not isinstance(rec, dict):
        return False

    rec_ts_us = rec.get("ts_us")
    if rec_ts_us is None and rec.get("timestamp"):
        rec_ts_us = _parse_ts_to_us(rec["timestamp"])

    if rec_ts_us is not None:
        from_us, to_us = _extract_time_bounds(f)
        if from_us is not None and int(rec_ts_us) < from_us:
            return False
        if to_us is not None and int(rec_ts_us) > to_us:
            return False

    fields_to_check = [
        "action", "in_iface", "out_iface", "rule_id",
        "smac", "dmac", "src_ip", "dst_ip", "sport", "dport"
    ]

    for field in fields_to_check:
        filter_value = f.get(field)
        if filter_value is not None:
            if str(rec.get(field)) != str(filter_value):
                return False

    return True

def query_packets(plog, f: dict, page: int, page_size: int) -> dict:
    """Вернуть {'items': [...], 'total': N} по журналу пакетов (файл + буфер)."""
    validate_packet_filter(f)

    page = max(1, int(page))
    page_size = max(1, int(page_size))
    offset = (page - 1) * page_size

    try:
        all_records = plog.read_all()
    except Exception:
        all_records = []

    filtered_items = []
    for rec in all_records[::-1]:
        if match_packet(rec, f):
            filtered_items.append(rec)

    total_count = len(filtered_items)
    page_items = filtered_items[offset:offset + page_size]

    # Перед ответом превращаем out_ifaces (bytes) в список чисел
    formatted_items = []
    for rec in page_items:
        item = dict(rec)
        out_raw = item.get("out_ifaces")
        if isinstance(out_raw, (bytes, bytearray)):
            out_count = item.get("out_count")
            if isinstance(out_count, int):
                item["out_ifaces"] = list(out_raw[:out_count])
            else:
                item["out_ifaces"] = list(out_raw)
        formatted_items.append(item)

    return {
        "items": formatted_items,
        "total": total_count
    }
