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
from datetime import datetime

def validate_event_filter(f: dict) -> None:
    """Критерии: event_code, from_ts, to_ts. Начало интервала не позже конца; иначе ValueError (M06)."""
    if not isinstance(f, dict):
        raise ValueError("M06: Неверный формат фильтра")

    from_ts = f.get("from_ts")
    to_ts = f.get("to_ts")

    # Проверяем временной интервал, только если заданы обе границы
    if from_ts and to_ts:
        try:
            # Преобразуем строки формата ISO 8601 в объекты datetime
            start_dt = datetime.fromisoformat(str(from_ts).replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(str(to_ts).replace("Z", "+00:00"))
            
            # Логика: начало интервала не может быть строго позже конца
            if start_dt > end_dt:
                raise ValueError("M06")
        except ValueError as e:
            # Если это созданная ошибка M06 — пробрасываем её дальше
            if str(e) == "M06":
                raise
            # Если даты просто не распарсились — сигнализируем о неверном формате даты
            raise ValueError("M06: Некорректный формат даты")

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

    # Проверка временного интервала (from_ts не позже to_ts)
    from_ts = f.get("from_ts")
    to_ts = f.get("to_ts")
    if from_ts and to_ts:
        try:
            start_dt = datetime.fromisoformat(str(from_ts).replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(str(to_ts).replace("Z", "+00:00"))
            if start_dt > end_dt:
                raise ValueError("M06")
        except ValueError:
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
    # Валидируем входящий фильтр
    validate_event_filter(f)

    # Защита параметров пагинации (FR-39)
    page = max(1, int(page))
    page_size = max(1, int(page_size))
    offset = (page - 1) * page_size

    # Формируем динамический SQL-запрос на основе фильтров
    conditions = []
    params = []

    if f.get("event_code"):
        conditions.append("code = ?")
        params.append(f["event_code"])

    if f.get("from_ts"):
        conditions.append("timestamp >= ?")
        params.append(f["from_ts"])

    if f.get("to_ts"):
        conditions.append("timestamp <= ?")
        params.append(f["to_ts"])

    # Собираем блок WHERE, если есть фильтры
    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

    cursor = conn.cursor()

    # Запрос №1: Считаем общее количество записей под этот фильтр
    count_query = f"SELECT COUNT(*) FROM events{where_clause}"
    cursor.execute(count_query, params)
    total_count = cursor.fetchone()[0]

    # Запрос №2: Получаем записи для конкретной страницы (сортировка от новых к старым согласно FR-40)
    data_query = f"SELECT * FROM events{where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    cursor.execute(data_query, params + [page_size, offset])
    
    # Чтобы вернуть список словарей, преобразуем row в dict
    columns = [col[0] for col in cursor.description]
    items = [dict(zip(columns, row)) for row in cursor.fetchall()]

    return {
        "items": items,
        "total": total_count
    }

def match_packet(rec: dict, f: dict) -> bool:
    """True, если запись удовлетворяет всем заданным критериям (критерии сочетаются по И)."""
    if not isinstance(f, dict) or not isinstance(rec, dict):
        return False

    # Проверяем временной интервал (запись пакета должна попадать в диапазон)
    rec_ts = rec.get("timestamp") or rec.get("datetime")
    if rec_ts:
        if f.get("from_ts") and rec_ts < f["from_ts"]:
            return False
        if f.get("to_ts") and rec_ts > f["to_ts"]:
            return False

    # Проверяем точное совпадение строковых и числовых полей
    # Список полей для автоматического сопоставления
    fields_to_check = [
        "action", "in_iface", "out_iface", "rule_id", 
        "smac", "dmac", "src_ip", "dst_ip", "sport", "dport"
    ]

    for field in fields_to_check:
        filter_value = f.get(field)
        # Если критерий в фильтре задан, он должен строго совпадать с полем в записи
        if filter_value is not None:
            # Приводим к строкам для безопасного сравнения (числа/строки)
            if str(rec.get(field)) != str(filter_value):
                return False

    return True

def query_packets(plog, f: dict, page: int, page_size: int) -> dict:
    """Вернуть {'items': [...], 'total': N} по журналу пакетов (файл + буфер)."""
    # Валидация входящего фильтра пакетов на входе
    validate_packet_filter(f)

    # Защита параметров пагинации (FR-39)
    page = max(1, int(page))
    page_size = max(1, int(page_size))
    offset = (page - 1) * page_size

    # Получаем все записи из журнала (вызываем метод чтения у объекта plog)
    try:
        all_records = plog.read_all()
    except Exception:
        all_records = []

    # Линейный проход и фильтрация с сортировкой от новых к старым (FR-40)
    filtered_items = []
    # Обходим в обратном порядке (срез [::-1]), чтобы свежие записи шли первыми
    for rec in all_records[::-1]:
        if match_packet(rec, f):
            filtered_items.append(rec)

    total_count = len(filtered_items)

    # Выделяем срез данных для конкретной запрошенной страницы
    page_items = filtered_items[offset:offset + page_size]

    return {
        "items": page_items,
        "total": total_count
    }

