"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-5 Авторизация
Модуль:      main
Назначение:  точка входа fw-authd, сервер Unix-сокета, маршрутизация команд
Методы:
  - load_config — чтение раздела authd из /etc/fw/config.json
  - apply_config — применение параметров конфигурации к модулям подсистемы
  - dispatch_request — диспетчеризация входящих запросов по протоколу JSON
  - emit_event — отправка события аудита в ПС-2 (logd) с очередью до 1000 событий
  - notify_integrity — уведомление ПС-6 (integrityd) об обновлении эталона (в фоне)
  - housekeeping_tick — периодическая работа: повтор отправки событий, таймаут сеансов
  - handle_auth_login — обработка команды auth.login
  - handle_auth_logout — обработка команды auth.logout
  - handle_auth_ping — обработка команды auth.ping
  - handle_auth_check — обработка команды auth.check
  - handle_user_list — обработка команды user.list
  - handle_user_add — обработка команды user.add
  - handle_user_edit — обработка команды user.edit
  - handle_user_delete — обработка команды user.delete
  - handle_session_list — обработка команды session.list
  - handle_session_kill — обработка команды session.kill
  - start_server — создание сервера Unix-сокета
  - main — точка входа сервиса
"""
import json
import logging
import os
import signal
import socket
import sys
import threading
from typing import Any, Dict, Optional, Tuple

try:
    from fwcommon import codes, protocol
except ImportError:
    # Запасной вариант при запуске без PYTHONPATH=common
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "common")))
    from fwcommon import codes, protocol

from . import accounts, auth, roles, sessions

DEFAULT_RUN_DIR = "/run/fw"
DEFAULT_CONFIG_PATH = "/etc/fw/config.json"

# Пути сокетов; каталог можно переопределить переменной окружения FW_RUN_DIR
# (например, FW_RUN_DIR=/tmp/fw для запуска рядом с клиентом CLI без root).
SOCKET_PATH = os.path.join(DEFAULT_RUN_DIR, "authd.sock")
LOGD_SOCKET = os.path.join(DEFAULT_RUN_DIR, "logd.sock")
INTEGRITYD_SOCKET = os.path.join(DEFAULT_RUN_DIR, "integrityd.sock")

EVENT_QUEUE_MAX = 1000      # FR-28: очередь событий при недоступной ПС-2
EVENT_SEND_TIMEOUT = 0.5    # с: отправка события не должна задерживать ответ клиенту
HOUSEKEEPING_PERIOD = 5.0   # с: PROTOCOL.md — повтор отправки событий каждые 5 с

# Тексты M06 по полям — те же, что в tests/stand/mock_core.py (ветка cli/stand)
_ALLOWED_ID = "от 3 до 32 символов: латиница, цифры, «_»"
_ALLOWED_ID_UNIQUE = "уникальный идентификатор"
_ALLOWED_ID_EXISTING = "существующий идентификатор"
_ALLOWED_PASSWORD = "не менее 8 символов"
_ALLOWED_ROLE = "rw, ro"

logger = logging.getLogger("fw_authd")

Result = Tuple[str, Dict[str, Any], Optional[str], Optional[str]]

_event_queue: list = []
_event_queue_lock = threading.Lock()


# --------------------------------------------------------------------------
# Конфигурация
# --------------------------------------------------------------------------

def load_config(path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """
    Чтение раздела "authd" из /etc/fw/config.json.
    Отсутствующий или повреждённый файл не роняет службу: используются
    значения по умолчанию, в журнал службы пишется предупреждение.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        logger.warning("fw-authd: %s не найден, используются значения по умолчанию", path)
        return {}
    except (OSError, ValueError) as e:
        logger.error("fw-authd: не удалось прочитать %s: %s", path, e)
        return {}
    section = cfg.get("authd") if isinstance(cfg, dict) else None
    return section if isinstance(section, dict) else {}


def apply_config(cfg: Dict[str, Any]) -> None:
    """Применение параметров раздела authd: путь accounts.json и число итераций PBKDF2."""
    path = cfg.get("accounts_path")
    if isinstance(path, str) and path:
        accounts.DEFAULT_ACCOUNTS_PATH = path
    it = cfg.get("hash_iterations")
    if isinstance(it, int) and not isinstance(it, bool) and it >= 100000:
        accounts.DEFAULT_HASH_ITERATIONS = it
    algo = cfg.get("hash_algo")
    if algo not in (None, accounts.DEFAULT_HASH_ALGO):
        logger.warning("fw-authd: hash_algo=%r не поддерживается, используется %s",
                       algo, accounts.DEFAULT_HASH_ALGO)


def set_run_dir(run_dir: str) -> None:
    """Каталог сокетов подсистем (по умолчанию /run/fw)."""
    global SOCKET_PATH, LOGD_SOCKET, INTEGRITYD_SOCKET
    SOCKET_PATH = os.path.join(run_dir, "authd.sock")
    LOGD_SOCKET = os.path.join(run_dir, "logd.sock")
    INTEGRITYD_SOCKET = os.path.join(run_dir, "integrityd.sock")


# --------------------------------------------------------------------------
# Взаимодействие с ПС-2 и ПС-6
# --------------------------------------------------------------------------

def _send_event(msg: Dict[str, Any]) -> None:
    """
    Отправить событие (type=event) без ожидания ответа: по PROTOCOL.md
    события подтверждения не требуют. Если в fwcommon.protocol уже есть
    send_event (ветка cli/stand) — используется он.
    """
    send = getattr(protocol, "send_event", None)
    if send is not None:
        send(LOGD_SOCKET, msg["src"], msg["dst"], msg["cmd"], msg["payload"],
             timeout=EVENT_SEND_TIMEOUT)
        return
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(EVENT_SEND_TIMEOUT)
        s.connect(LOGD_SOCKET)
        s.sendall((json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))


def emit_event(code: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Отправка события в ПС-2 (logd): log.write.event, поля события на верхнем
    уровне payload ({"code": "E01", "actor": "admin", ...}).
    При недоступности ПС-2 события копятся в очереди (до 1000, FR-28)
    и досылаются из housekeeping_tick каждые 5 с.
    Пароли, хэши и идентификаторы сеансов в события не попадают (FR-37).
    """
    payload = {"code": code}
    payload.update(details or {})
    msg = protocol.make_msg("event", "authd", "logd", cmd="log.write.event", payload=payload)
    with _event_queue_lock:
        if len(_event_queue) >= EVENT_QUEUE_MAX:
            logger.error("fw-authd: очередь событий переполнена, событие %s потеряно", code)
            return
        _event_queue.append(msg)
    _flush_event_queue()


def _flush_event_queue() -> None:
    """Попытка отправить накопившиеся события в ПС-2 (по порядку, до первой ошибки)."""
    if not os.path.exists(LOGD_SOCKET):
        return
    with _event_queue_lock:
        while _event_queue:
            try:
                _send_event(_event_queue[0])
            except (OSError, ValueError):
                break
            _event_queue.pop(0)


def notify_integrity() -> None:
    """
    Уведомление ПС-6 (integrityd) об изменении accounts.json:
    integrity.update_baseline с пустым payload (integrityd/README.md).
    Выполняется в фоновом потоке: protocol.request при недоступной ПС-6
    ждёт до 3 × 5 с, а клиент CLI ждёт ответа на user.* только 5 с.
    """
    def _run():
        if not os.path.exists(INTEGRITYD_SOCKET):
            return
        try:
            protocol.request(INTEGRITYD_SOCKET, "authd", "integrityd",
                             "integrity.update_baseline", payload={})
        except Exception as e:  # ПС-6 недоступна — служба продолжает работу
            logger.warning("fw-authd: не удалось уведомить integrityd: %s", e)

    threading.Thread(target=_run, name="notify-integrityd", daemon=True).start()


def housekeeping_tick() -> None:
    """
    Периодическая работа (каждые 5 с):
    - повтор отправки событий из очереди в ПС-2 (PROTOCOL.md, FR-28);
    - завершение сеансов, бездействующих более 15 минут, с событием E07 (FR-35).
    """
    for s in sessions.cleanup_expired_sessions():
        emit_event("E07", {"actor": s.get("username"), "reason": "бездействие"})
    _flush_event_queue()


def _housekeeping_loop(stop: threading.Event) -> None:
    while not stop.wait(HOUSEKEEPING_PERIOD):
        try:
            housekeeping_tick()
        except Exception:  # необработанные исключения не завершают процесс
            logger.exception("fw-authd: ошибка фоновой задачи")


# --------------------------------------------------------------------------
# Общие проверки
# --------------------------------------------------------------------------

def _m(code: str, **kw) -> str:
    return codes.message_text(code, **kw) if kw else codes.message_text(code)


def _err(code: str, payload: Optional[Dict[str, Any]] = None, **kw) -> Result:
    return "error", payload or {}, code, _m(code, **kw)


def _ok(payload: Optional[Dict[str, Any]] = None) -> Result:
    return "ok", payload or {}, None, None


def _bad(field: str, allowed: str) -> Result:
    return _err("M06", field=field, allowed=allowed)


def _require_session(payload: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Result]]:
    """
    Сеанс инициатора запроса по session_id.
    Нет сеанса — M15 «сеанс не найден»; истёк таймаут — M15 и событие E07 (FR-35).
    """
    sess, reason = sessions.lookup_session(payload.get("session_id"))
    if reason is None:
        return sess, None
    if reason == sessions.SESSION_EXPIRED:
        emit_event("E07", {"actor": sess.get("username"), "reason": "бездействие"})
        return None, _err("M15", reason="бездействие более 15 минут")
    return None, _err("M15", reason="сеанс не найден")


def _require_permission(payload: Dict[str, Any], cmd: str) -> Tuple[Optional[Dict[str, Any]], Optional[Result]]:
    """
    Сеанс инициатора и право его роли на команду cmd.
    Отказ по роли — M03 и событие E50 с именем команды (FR-32, FR-37b).
    """
    sess, err = _require_session(payload)
    if err:
        return None, err
    allowed, err_c, ev_c = roles.check_permission(sess.get("effective_role", "ro"), cmd)
    if not allowed:
        emit_event(ev_c or "E50", {"actor": sess.get("username"), "cmd": cmd})
        return None, _err(err_c or "M03")
    return sess, None


# --------------------------------------------------------------------------
# Обработчики команд ПС-5
# --------------------------------------------------------------------------

def handle_auth_login(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """Обработка команды auth.login (FR-30, FR-31, FR-34)."""
    uid = payload.get("id")
    password = payload.get("password")
    source = payload.get("source") or msg.get("src") or "cli"
    if not isinstance(uid, str) or not isinstance(password, str):
        return _err("M02")

    ok, session, msg_code, event_code = auth.authenticate(uid, password, source=source)
    if not ok:
        if event_code == "E06":
            # 5-я неудача подряд: сама попытка неуспешна (E03) и включена блокировка (E06)
            emit_event("E03", {"actor": uid, "source": source})
        if event_code:
            emit_event(event_code, {"actor": uid, "source": source})
        return _err(msg_code or "M02")

    if session.get("downgraded"):
        emit_event("E04", {"actor": uid, "source": source})
    emit_event("E01", {"actor": uid, "source": source, "role": session["effective_role"]})

    out = {
        "session_id": session["session_id"],
        "username": session["username"],
        "role": session["effective_role"],
        "downgraded": bool(session.get("downgraded", False)),
    }
    if msg_code:
        out["warning"] = msg_code
        out["warning_message"] = _m(msg_code)
    return _ok(out)


def handle_auth_logout(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """Обработка команды auth.logout (FR-35, E02)."""
    sess, err = _require_session(payload)
    if err:
        return err
    auth.logout(sess["session_id"])
    emit_event("E02", {"actor": sess.get("username")})
    return _ok({"status": "logged_out"})


def handle_auth_ping(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """Обработка команды auth.ping (FR-37a)."""
    sess, err = _require_session(payload)
    if err:
        return err
    if not sessions.touch_session(sess["session_id"]):
        return _err("M15", reason="сеанс не найден")
    return _ok({"status": "pong"})


def handle_auth_check(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """
    Обработка команды auth.check (FR-32, FR-37b).
    Право проверяется только по сеансу: роль из запроса не принимается,
    иначе клиент мог бы сам назначить себе rw.
    """
    target_cmd = payload.get("cmd")
    sess, err = _require_session(payload)
    if err:
        return err
    if not isinstance(target_cmd, str) or not target_cmd:
        return _bad("cmd", "имя команды")
    allowed, err_c, ev_c = roles.check_permission(sess.get("effective_role", "ro"), target_cmd)
    if not allowed:
        emit_event(ev_c or "E50", {"actor": sess.get("username"), "cmd": target_cmd})
        return _err(err_c or "M03", {"allowed": False})
    return _ok({"allowed": True})


def handle_user_list(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """Обработка команды user.list: [{id, role}] без паролей и хэшей (FR-37)."""
    _, err = _require_permission(payload, "user.list")
    if err:
        return err
    return _ok({"users": accounts.list_users()})


def handle_user_add(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """Обработка команды user.add (FR-36, E32)."""
    sess, err = _require_permission(payload, "user.add")
    if err:
        return err
    uid, pwd, role = payload.get("id"), payload.get("password"), payload.get("role")

    if not accounts.validate_username(uid)[0]:
        return _bad("id", _ALLOWED_ID)
    if accounts.get_user(uid) is not None:
        return _bad("id", _ALLOWED_ID_UNIQUE)
    if not accounts.validate_password(pwd)[0]:
        return _bad("password", _ALLOWED_PASSWORD)
    if not accounts.validate_role(role)[0]:
        return _bad("role", _ALLOWED_ROLE)

    ok, code = accounts.add_user(uid, pwd, role)
    if not ok:
        return _bad("id", _ALLOWED_ID_UNIQUE) if code == "M06" else _err(code)

    emit_event("E32", {"actor": sess.get("username"), "target": uid, "op": "add"})
    notify_integrity()
    return _ok()


def handle_user_edit(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """Обработка команды user.edit (FR-33, FR-36, E32)."""
    sess, err = _require_permission(payload, "user.edit")
    if err:
        return err
    uid, pwd, role = payload.get("id"), payload.get("password"), payload.get("role")

    if not isinstance(uid, str) or accounts.get_user(uid) is None:
        return _bad("id", _ALLOWED_ID_EXISTING)
    if role is not None:
        if not accounts.validate_role(role)[0]:
            return _bad("role", _ALLOWED_ROLE)
        if uid == accounts.BUILTIN_ADMIN_ID and role != "rw":
            return _err("M05")
    if pwd is not None and not accounts.validate_password(pwd)[0]:
        return _bad("password", _ALLOWED_PASSWORD)

    ok, code = accounts.edit_user(uid, new_password=pwd, new_role=role)
    if not ok:
        return _err(code) if code == "M05" else _bad("id", _ALLOWED_ID_EXISTING)

    emit_event("E32", {"actor": sess.get("username"), "target": uid, "op": "edit"})
    notify_integrity()
    return _ok()


def handle_user_delete(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """Обработка команды user.delete (FR-33, FR-35, E07, E32)."""
    sess, err = _require_permission(payload, "user.delete")
    if err:
        return err
    uid = payload.get("id")

    if uid == accounts.BUILTIN_ADMIN_ID:
        return _err("M05")
    ok, code = accounts.delete_user(uid) if isinstance(uid, str) else (False, "M06")
    if not ok:
        return _err(code) if code == "M05" else _bad("id", _ALLOWED_ID_EXISTING)

    # Сеансы удалённого пользователя завершаются (FR-35, E07)
    for _ in sessions.close_sessions_for_user(uid, reason="user_deleted"):
        emit_event("E07", {"actor": uid, "reason": "учётная запись удалена"})

    emit_event("E32", {"actor": sess.get("username"), "target": uid, "op": "delete"})
    notify_integrity()
    return _ok()


def _mask_sid(sid: str) -> str:
    return sid[:8] + "…" if isinstance(sid, str) else sid


def handle_session_list(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """
    Обработка команды session.list.
    Поля элемента: session_id, username, role, source, idle_sec, downgraded
    (+ base_role, created_at, last_active). Полный session_id видит только rw —
    он нужен для session.kill. Роли ro идентификатор маскируется: иначе
    оператор ro мог бы подставить чужой session_id и действовать с правами rw.
    """
    sess, err = _require_permission(payload, "session.list")
    if err:
        return err
    items = sessions.list_active_sessions()
    if sess.get("effective_role") != roles.ROLE_RW:
        for it in items:
            it["session_id"] = _mask_sid(it["session_id"])
    return _ok({"sessions": items})


def handle_session_kill(payload: Dict[str, Any], msg: Dict[str, Any]) -> Result:
    """Обработка команды session.kill (FR-35, E05; у сброшенного клиента — M15)."""
    sess, err = _require_permission(payload, "session.kill")
    if err:
        return err
    target_id = payload.get("target_session_id")
    victim = sessions.get_session(target_id) if isinstance(target_id, str) else None
    if victim is None:
        return _err("M13")
    ok, _, ev_c = sessions.kill_session(target_id, killer_username=sess.get("username"))
    if not ok:
        return _err("M13")
    emit_event(ev_c or "E05", {"actor": sess.get("username"), "target": victim.get("username")})
    return _ok({"killed": target_id})


DISPATCH_MAP = {
    "auth.login": handle_auth_login,
    "auth.logout": handle_auth_logout,
    "auth.ping": handle_auth_ping,
    "auth.check": handle_auth_check,
    "user.list": handle_user_list,
    "user.add": handle_user_add,
    "user.edit": handle_user_edit,
    "user.delete": handle_user_delete,
    "session.list": handle_session_list,
    "session.kill": handle_session_kill,
}


def dispatch_request(msg: Dict[str, Any]) -> Result:
    """
    Диспетчеризация входящего сообщения:
    handler(payload, msg) -> (status, payload, error_code, error_message).
    Неизвестная команда — M14. payload, не являющийся объектом JSON, считается пустым.
    """
    if not isinstance(msg, dict):
        return _err("M14")
    handler = DISPATCH_MAP.get(msg.get("cmd"))
    if handler is None:
        return _err("M14")
    payload = msg.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    return handler(payload, msg)


# --------------------------------------------------------------------------
# Запуск службы
# --------------------------------------------------------------------------

def _init_default_admin() -> None:
    """Создание предустановленного администратора admin при первом запуске (FR-33)."""
    if accounts.get_user(accounts.BUILTIN_ADMIN_ID) is None:
        # Пароль по умолчанию фиксируется в ПМИ; его нужно сменить после установки
        accounts.add_user(accounts.BUILTIN_ADMIN_ID, "Admin_12345", "rw")
        logger.warning("fw-authd: создан admin с паролем по умолчанию — смените его (user edit)")


def start_server(socket_path: Optional[str] = None):
    """Создание сервера Unix-сокета fw-authd (права сокета 0600 задаёт protocol.serve)."""
    _init_default_admin()
    srv = protocol.serve(socket_path or SOCKET_PATH, "authd", dispatch_request)
    emit_event("E12", {"subsystem": "authd"})
    return srv


def _on_sigterm(signum, frame):
    # systemctl stop шлёт SIGTERM: штатно выходим из serve_forever через тот же путь, что Ctrl+C
    raise KeyboardInterrupt


def main() -> int:
    """
    Точка входа fw-authd:
    конфигурация -> сервер на /run/fw/authd.sock -> фоновые задачи -> обслуживание.
    Код возврата 1, если сокет создать не удалось: systemd (Restart=on-failure)
    перезапустит службу. При остановке регистрируется E13.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    apply_config(load_config(os.environ.get("FW_CONFIG", DEFAULT_CONFIG_PATH)))
    set_run_dir(os.environ.get("FW_RUN_DIR", DEFAULT_RUN_DIR))

    logger.info("fw-authd: запуск службы авторизации")
    try:
        srv = start_server()
    except OSError as e:
        logger.error("fw-authd: не удалось создать сокет %s: %s", SOCKET_PATH, e)
        return 1

    signal.signal(signal.SIGTERM, _on_sigterm)
    stop = threading.Event()
    threading.Thread(target=_housekeeping_loop, args=(stop,), name="housekeeping", daemon=True).start()

    logger.info("fw-authd: прослушивание сокета %s", SOCKET_PATH)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        logger.info("fw-authd: остановка службы")
    finally:
        stop.set()
        emit_event("E13", {"subsystem": "authd"})
        srv.server_close()
        try:
            os.unlink(SOCKET_PATH)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
