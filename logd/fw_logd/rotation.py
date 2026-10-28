"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-2 Регистрация
Модуль:      rotation
Назначение:  ограничение размера журналов: E36 (пакеты), E37 (события); очистка пакетов E34 (FR-29, FR-40)
Методы:
  - enforce_event_limit — удалить старые события при превышении предела
  - enforce_packet_limit — зафиксировать переполнение кольца пакетов
  - clear_packets — очистить журнал пакетов и зарегистрировать E34
"""


def _used_bytes(conn) -> int:
    """Сколько байт занимают данные базы (пустые страницы после удаления не считаются)."""
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    return (pages - free) * page_size


def enforce_event_limit(conn, limit_bytes: int, emit_event) -> int:
    """При превышении предела (по умолчанию 50 МБ) удалить самые старые записи и вызвать emit_event('E37').
    Возвращает число удалённых записей."""
    from fw_logd import event_log
    deleted = 0
    while _used_bytes(conn) > limit_bytes:
        total = event_log.count_events(conn)
        if total == 0:
            break
        deleted += event_log.delete_oldest(conn, max(1, total // 10))  # по 10% за проход
    if deleted:
        emit_event("E37")
    return deleted

def enforce_packet_limit(plog, emit_event) -> bool:
    """Если кольцо перезаписывает старые записи — вызвать emit_event('E36'); вернуть True при переполнении."""
    raise NotImplementedError("rotation.enforce_packet_limit")


def clear_packets(plog, actor: dict, emit_event) -> None:
    """Очистить журнал пакетов (только роль rw — проверяет вызывающий) и зарегистрировать E34."""
    raise NotImplementedError("rotation.clear_packets")
