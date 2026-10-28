"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      session
Назначение:  сеанс администратора: однократный вход через ПС-5 (FR-37a),
             локальный кэш роли, уведомления об активности auth.ping не чаще
             ping_interval_sec, выход; IP-адрес администратора из SSH (FR-02).
Методы:
  - Session — сеанс: id, роль, источник, IP-адрес, время последнего ping
  - client_ip — IP-адрес администратора по переменным SSH (None — консоль)
  - login — auth.login в ПС-5 -> Session (ProtocolError M02, M12, M16)
  - ping — auth.ping: продлить сеанс (ProtocolError M15 — сеанс завершён)
  - ping_if_due — auth.ping, если с прошлого прошло не меньше интервала
  - logout — auth.logout (E02 регистрирует ПС-5)
"""
import os
import time
from dataclasses import dataclass, field

from fwcommon import protocol

PING_INTERVAL_SEC = 60  # config.json: cli.ping_interval_sec


@dataclass
class Session:
    session_id: str
    username: str
    role: str                 # rw | ro — после возможного понижения (FR-34)
    source: str = "cli"       # cli | web
    ip: str = None            # None — локальная консоль
    downgraded: bool = False
    warning: str = None       # M04 при понижении прав
    last_ping: float = field(default_factory=time.monotonic)

    @property
    def is_rw(self):
        return self.role == "rw"


def client_ip(environ=None):
    """IP-адрес администратора: первое поле SSH_CONNECTION или SSH_CLIENT; None — консоль."""
    env = os.environ if environ is None else environ
    for var in ("SSH_CONNECTION", "SSH_CLIENT"):
        parts = env.get(var, "").split()
        if parts:
            return parts[0]
    return None


def login(authd_path, user_id, password, source="cli", ip=None):
    """auth.login -> Session; ProtocolError M02 / M12 / M16. При понижении прав — warning=M04.

    Ответ ПС-5 проверяется: без session_id или с неизвестной ролью вход не
    выполняется (данным другой подсистемы без проверки не доверяют).
    """
    payload = {"id": user_id, "password": password, "source": source}
    if ip:
        payload["ip"] = ip
    p = protocol.request(authd_path, source, "authd", "auth.login", payload)["payload"]
    sid, role = p.get("session_id"), p.get("role")
    if not isinstance(sid, str) or not sid or role not in ("rw", "ro"):
        raise protocol.ProtocolError("M16", "некорректный ответ ПС-5 на auth.login")
    return Session(session_id=sid, username=p.get("username", user_id), role=role,
                   source=source, ip=ip, downgraded=bool(p.get("downgraded")),
                   warning=p.get("warning"))


def ping(authd_path, session):
    """auth.ping; ProtocolError M15 — сеанс завершён по таймауту или сброшен."""
    protocol.request(authd_path, session.source, "authd", "auth.ping",
                     {"session_id": session.session_id})
    session.last_ping = time.monotonic()


def ping_if_due(authd_path, session, interval=PING_INTERVAL_SEC):
    """auth.ping, если с прошлого прошло не меньше interval секунд (FR-37a)."""
    if time.monotonic() - session.last_ping >= interval:
        ping(authd_path, session)


def logout(authd_path, session):
    """auth.logout; событие E02 регистрирует ПС-5."""
    protocol.request(authd_path, session.source, "authd", "auth.logout",
                     {"session_id": session.session_id})
