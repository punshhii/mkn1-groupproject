"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      listener
Назначение:  приём входящих команд ПС-3 на /run/fw/cli.sock (README, «Принимает»):
             emergency.enter / emergency.exit от ПС-6, session.terminate от ПС-5.
             Процесс CLI запускается на каждый вход, а сокет один: его занимает
             первый процесс, остальные узнают режим запросом integrity.status
             (README, «Режим работы»), а завершение сеанса — по M15 от ПС-5.
Методы:
  - Inbox — режим, сообщённый ПС-6, и завершённые ПС-5 сеансы; handler для protocol.serve;
    listen — занять сокет, если он свободен; close — освободить его
  - socket_busy — сокет уже слушает другой живой процесс
  - start — Inbox для сокета с попыткой сразу его занять
"""
import os
import socket
import threading

from fwcommon import codes, protocol

# Кто вправе присылать входящую команду (данным другой подсистемы без проверки не доверяют)
SENDERS = {"emergency.enter": "integrityd", "emergency.exit": "integrityd",
           "session.terminate": "authd"}


class Inbox:
    """Состояние, которое меняют входящие команды; on_change() — после изменения."""

    def __init__(self, on_change=None, path=None, name="cli"):
        self.emergency = None          # None — уведомлений не было, режим берётся из integrity.status
        self.notice = None             # текст для администратора (M08 из emergency.enter)
        self.terminated = {}           # session_id -> причина завершения от ПС-5
        self.on_change = on_change
        self.srv = None
        self.path = path               # None — приёмник без сокета (тесты, ядро web)
        self.name = name
        self._lock = threading.Lock()

    def listen(self):
        """Занять сокет, если он свободен: при старте и перед каждым приглашением
        (процесс, державший сокет, мог завершиться). True — сокет у этого процесса."""
        if self.srv is not None:
            return True
        if self.path is None or socket_busy(self.path):
            return False
        try:
            srv = protocol.serve(self.path, self.name, self.handler)
        except OSError:
            return False  # нет прав на каталог сокетов: режим узнаётся через integrity.status
        self.srv = srv
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return True

    def handler(self, msg):
        cmd, p = msg.get("cmd"), msg.get("payload") or {}
        if SENDERS.get(cmd) != msg.get("src"):
            return "error", {}, "M14", codes.message_text("M14")
        changed = False
        with self._lock:
            if cmd == "session.terminate":
                sid = p.get("session_id")
                if not isinstance(sid, str) or not sid:
                    return "error", {}, "M06", codes.message_text(
                        "M06", field="session_id", allowed="идентификатор сеанса")
                changed = sid not in self.terminated
                reason = p.get("reason")
                self.terminated.setdefault(sid, reason if isinstance(reason, str) and reason
                                           else "сеанс завершён подсистемой аутентификации")
            else:
                on = cmd == "emergency.enter"
                changed = self.emergency is not on  # повтор не меняет состояния (идемпотентно)
                self.emergency = on
                if changed:
                    self.notice = (p.get("error_message") or codes.message_text("M08")) if on else None
        if changed and self.on_change:
            self.on_change()
        return "ok", {"mode": self.mode()}, None, None

    def mode(self):
        return {True: "emergency", False: "normal"}.get(self.emergency, "unknown")

    def terminated_reason(self, session_id):
        """Причина для M15, если ПС-5 завершила сеанс session_id; иначе None."""
        with self._lock:
            return self.terminated.get(session_id)

    def take_notice(self):
        with self._lock:
            text, self.notice = self.notice, None
        return text

    def close(self):
        """Остановить приёмник и удалить свой сокет."""
        if self.srv is None:
            return
        self.srv.shutdown()
        self.srv.server_close()
        self.srv = None
        try:
            os.unlink(self.path)
        except OSError:
            pass
        self.path = None  # закрытый приёмник сокет больше не занимает


def socket_busy(path):
    """True, если на path отвечает другой процесс (тогда сокет не перехватывается)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(path)
        return True
    except OSError:
        return False  # нет файла или оставлен завершившимся процессом
    finally:
        s.close()


def start(path, name="cli", on_change=None):
    """Inbox для сокета path; занимает его, если сокет свободен (иначе srv = None)."""
    inbox = Inbox(on_change, path, name)
    inbox.listen()
    return inbox
