"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-5 Авторизация
Модуль:      sessions
Назначение:  сеансы, таймаут 15 мин, понижение прав второго RW-сеанса
Методы:
  - create_session — создание нового сеанса с контролем уникальности RW-сессии
  - get_session — получение активного сеанса по идентификатору
  - lookup_session — сеанс по идентификатору с причиной отказа (не найден / бездействие)
  - touch_session — продление активности сеанса (auth.ping)
  - close_session — штатное закрытие сеанса
  - kill_session — принудительный сброс сеанса другим администратором
  - close_sessions_for_user — завершение сеансов при удалении учётной записи
  - list_active_sessions — список всех активных сеансов
  - cleanup_expired_sessions — очистка просроченных по неактивности сеансов
  - has_active_rw_session — проверка наличия активного сеанса с ролью rw
  - clear_all_sessions — сброс всех активных сеансов
"""
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

SESSION_TIMEOUT_SEC = 900  # 15 минут (FR-35)
ROLE_RW = "rw"
ROLE_RO = "ro"

_lock = threading.Lock()
_active_sessions: Dict[str, Dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def has_active_rw_session() -> bool:
    """Проверка наличия активного сеанса с правами rw (FR-34)."""
    with _lock:
        now = time.time()
        for s in _active_sessions.values():
            if s.get("effective_role") == ROLE_RW:
                # Проверяем, не истек ли таймаут
                if now - s.get("last_active_ts", 0) <= SESSION_TIMEOUT_SEC:
                    return True
        return False


def create_session(
    username: str,
    role: str,
    source: str = "cli",
) -> Tuple[Dict[str, Any], Optional[str], Optional[str]]:
    """
    Создание сеанса с проверкой активных RW-сессий (FR-34).
    Если роль rw и уже есть активный rw-сеанс, права понижаются до ro (M04, E04).
    Возвращает (session_dict, warning_code, event_code).
    """
    with _lock:
        session_id = uuid.uuid4().hex
        now_ts = time.time()
        now_str = _now_iso()

        downgraded = False
        warning_code = None
        event_code = "E01"
        effective_role = role

        if role == ROLE_RW:
            # Проверяем, есть ли уже активная сессия rw
            has_rw = any(
                s.get("effective_role") == ROLE_RW
                and (now_ts - s.get("last_active_ts", 0) <= SESSION_TIMEOUT_SEC)
                for s in _active_sessions.values()
            )
            if has_rw:
                effective_role = ROLE_RO
                downgraded = True
                warning_code = "M04"
                event_code = "E04"

        session = {
            "session_id": session_id,
            "username": username,
            "base_role": role,
            "effective_role": effective_role,
            "source": source,
            "created_at": now_str,
            "last_active_iso": now_str,
            "last_active_ts": now_ts,
            "downgraded": downgraded,
        }
        _active_sessions[session_id] = session
        return dict(session), warning_code, event_code


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Получение информации о сеансе, если он активен и не просрочен."""
    with _lock:
        s = _active_sessions.get(session_id)
        if not s:
            return None
        if time.time() - s.get("last_active_ts", 0) > SESSION_TIMEOUT_SEC:
            return None
        return dict(s)


SESSION_NOT_FOUND = "not_found"
SESSION_EXPIRED = "expired"


def lookup_session(session_id: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Сеанс по идентификатору с причиной отказа (FR-35).
    Возвращает (session, None) — сеанс активен;
               (None, SESSION_NOT_FOUND) — сеанса нет;
               (removed, SESSION_EXPIRED) — сеанс просрочен и удалён, removed — его
               копия (имя пользователя для события E07). Вызывающий сначала
               проверяет причину. Удаление сразу гарантирует, что E07 будет один.
    """
    if not isinstance(session_id, str) or not session_id:
        return None, SESSION_NOT_FOUND
    with _lock:
        s = _active_sessions.get(session_id)
        if s is None:
            return None, SESSION_NOT_FOUND
        if time.time() - s.get("last_active_ts", 0) > SESSION_TIMEOUT_SEC:
            del _active_sessions[session_id]
            return dict(s), SESSION_EXPIRED
        return dict(s), None


def touch_session(session_id: str) -> bool:
    """Обновление времени активности сеанса (FR-37a, auth.ping)."""
    with _lock:
        s = _active_sessions.get(session_id)
        if not s:
            return False
        now_ts = time.time()
        if now_ts - s.get("last_active_ts", 0) > SESSION_TIMEOUT_SEC:
            # Сеанс уже протух
            return False
        s["last_active_ts"] = now_ts
        s["last_active_iso"] = _now_iso()
        return True


def close_session(session_id: str, reason: str = "logout") -> Tuple[bool, Optional[str]]:
    """
    Штатное закрытие сеанса (FR-35).
    Возвращает (успех, код_события).
    """
    with _lock:
        s = _active_sessions.pop(session_id, None)
        if s is None:
            return False, None
        return True, "E02"


def kill_session(
    session_id: str,
    killer_username: Optional[str] = None,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Принудительное завершение сеанса другим администратором (FR-35, E05, M15).
    Возвращает (успех, message_code="M15", event_code="E05").
    """
    with _lock:
        s = _active_sessions.pop(session_id, None)
        if s is None:
            return False, "M13", None
        return True, "M15", "E05"


def close_sessions_for_user(username: str, reason: str = "user_deleted") -> List[str]:
    """
    Завершение всех сеансов пользователя (например, при удалении учётной записи FR-35).
    Возвращает список ID закрытых сеансов.
    """
    with _lock:
        closed_ids = []
        for sid, s in list(_active_sessions.items()):
            if s.get("username") == username:
                closed_ids.append(sid)
                del _active_sessions[sid]
        return closed_ids


def list_active_sessions() -> List[Dict[str, Any]]:
    """Список всех текущих активных сеансов."""
    with _lock:
        now_ts = time.time()
        res = []
        for s in _active_sessions.values():
            if now_ts - s.get("last_active_ts", 0) <= SESSION_TIMEOUT_SEC:
                res.append({
                    "session_id": s["session_id"],
                    "username": s["username"],
                    "role": s["effective_role"],
                    "base_role": s["base_role"],
                    "source": s["source"],
                    "created_at": s["created_at"],
                    "last_active": s["last_active_iso"],
                    "idle_sec": int(now_ts - s["last_active_ts"]),
                    "downgraded": s.get("downgraded", False),
                })
        return res


def cleanup_expired_sessions(timeout_sec: int = SESSION_TIMEOUT_SEC) -> List[Dict[str, Any]]:
    """
    Поиск и удаление сеансов, неактивных более timeout_sec (FR-35, E07).
    Возвращает список удалённых сеансов.
    """
    with _lock:
        now_ts = time.time()
        expired = []
        for sid, s in list(_active_sessions.items()):
            if now_ts - s.get("last_active_ts", 0) > timeout_sec:
                expired.append(s)
                del _active_sessions[sid]
        return expired


def clear_all_sessions() -> None:
    """Очистить все сеансы (для тестов)."""
    with _lock:
        _active_sessions.clear()
