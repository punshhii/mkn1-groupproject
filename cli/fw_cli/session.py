"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      session
Назначение:  сеанс администратора: вход через ПС-5 с IP-адресом (FR-02),
             проверка права на каждую команду auth.check (она же продлевает
             сеанс), выход. Роль сеанса хранится только для приглашения
             [rw] / [ro]: право на команду решает ПС-5.
Методы:
  - Session — сеанс: id, роль (для приглашения), источник, IP-адрес
  - client_ip — IP-адрес администратора по переменным SSH (127.0.0.1 — консоль)
  - login — auth.login в ПС-5 -> Session (ProtocolError M02, M12, M16)
  - check — auth.check: право сеанса на команду (ProtocolError M03, M15, M16)
  - logout — auth.logout (E02 регистрирует ПС-5)
"""
import os
from dataclasses import dataclass

from fwcommon import codes, protocol


@dataclass
class Session:
    session_id: str
    username: str
    role: str                 # rw | ro после возможного понижения (FR-34); только для приглашения
    source: str = "cli"       # cli | web
    ip: str = None            # 127.0.0.1 — локальная консоль
    downgraded: bool = False
    warning: str = None       # M04 при понижении прав

    @property
    def is_rw(self):
        return self.role == "rw"


CONSOLE_IP = "127.0.0.1"  # вход с локальной консоли


def client_ip(environ=None):
    """IP-адрес администратора: первое поле SSH_CONNECTION или SSH_CLIENT; консоль — 127.0.0.1."""
    env = os.environ if environ is None else environ
    for var in ("SSH_CONNECTION", "SSH_CLIENT"):
        parts = env.get(var, "").split()
        if parts:
            return parts[0]
    return CONSOLE_IP


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


def check(authd_path, session, cmd_name):
    """auth.check {session_id, cmd}: право сеанса на команду и продление сеанса.

    ProtocolError: M03 — недостаточно прав (E50 регистрирует ПС-5), M15 — сеанс
    завершён, M16 — ПС-5 не отвечает. Ответ без allowed=true — отказ (M03).
    """
    p = protocol.request(authd_path, session.source, "authd", "auth.check",
                         {"session_id": session.session_id, "cmd": cmd_name})["payload"]
    if p.get("allowed") is not True:
        raise protocol.ProtocolError("M03", codes.message_text("M03"))


def logout(authd_path, session):
    """auth.logout; событие E02 регистрирует ПС-5."""
    protocol.request(authd_path, session.source, "authd", "auth.logout",
                     {"session_id": session.session_id})
