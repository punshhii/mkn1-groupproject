"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  общее (common/fwcommon)
Модуль:      protocol
Назначение:  обмен JSON-сообщениями по Unix-сокетам (AF_UNIX/SOCK_STREAM, права 0600):
             конверт сообщения и его валидация по common/PROTOCOL.md; клиент с
             тайм-аутом 5 с и до 2 повторов с тем же msg_id (ошибки ответа ->
             ProtocolError с кодами M01..M16, отсутствие ответа -> M16, FR-28);
             сервер с дедупликацией по msg_id (команда выполняется один раз).
             Двоичный канал packet_record_t (55 байт, /run/fw/logd-packets.sock)
             в этом модуле не кодируется — см. common/packet_record.h.
Методы:
- now_iso — метка времени ISO 8601 с миллисекундами (например 2026-03-14T10:21:33.482Z)
- new_id — новый уникальный msg_id (монотонный счётчик со случайным началом, потокобезопасный)
- make_msg — собрать конверт сообщения со значениями по умолчанию
- validate_envelope — проверить конверт по PROTOCOL.md (нарушение — ValueError)
- encode_line — сообщение -> байты UTF-8, одно сообщение на строку (разделитель \n)
- StreamDecoder — сборка сообщений из потока байтов (границ сообщений в потоке нет)
- request — запрос подсистеме: повтор с тем же msg_id, события пропускаются,
            status=error -> ProtocolError(error_code), нет ответа -> ProtocolError("M16")
- send_event — отправить событие (type=event), ответа не ждать
- serve — сервер: handler(msg) -> (status, payload, error_code, error_message);
          повторный (src, msg_id) получает прежний ответ без повторного выполнения;
          для событий handler вызывается, ответ не отправляется
"""
import itertools
import json
import os
import re
import socket
import socketserver
import threading
from datetime import datetime, timezone

try:
    from . import codes as _codes
except ImportError:  # запуск модуля вне пакета fwcommon
    import codes as _codes  # type: ignore

TIMEOUT_SEC = 5      # PROTOCOL.md: тайм-аут ответа, секунд
RETRIES = 2          # PROTOCOL.md: до 2 повторов с тем же msg_id
MSG_TYPES = ("request", "response", "event")
SOURCES = ("cli", "web", "filter", "logd", "authd", "integrityd", "os")
MAX_STRING = 255     # PROTOCOL.md: строки в UTF-8, до 255 символов
MAX_LINE = 65536     # защитный предел длины одной строки сообщения, байт

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_CMD_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")

# Начало счётчика случайное: msg_id разных процессов (два сеанса CLI, CLI и web)
# не совпадают, и сервер не вернёт одному клиенту кэшированный ответ другому.
# Предел 2**52 — число точно представимо в JSON-парсерах с double.
_ids = itertools.count(int.from_bytes(os.urandom(4), "big") << 20)
_id_lock = threading.Lock()


class ProtocolError(ConnectionError):
    """Ошибка ответа подсистемы; code — код из common/messages.json (например M16).

    Наследует ConnectionError, как прежний кодек: подсистемы, которые ловят
    ConnectionError при отсутствии ответа (fw_integrityd.emergency), продолжают
    работать и с отказом status=error.
    """

    def __new__(cls, code, message=""):
        return super().__new__(cls, "%s: %s" % (code, message))

    def __init__(self, code, message=""):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message


def now_iso():
    """Текущее время UTC в формате ISO 8601 с миллисекундами, суффикс Z."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_id():
    """Новый уникальный msg_id."""
    with _id_lock:
        return next(_ids)


def make_msg(type_, src, dst, cmd=None, payload=None, reply_to=None, msg_id=None, **extra):
    """Собрать конверт сообщения; недостающие поля заполняются значениями по умолчанию."""
    msg = {
        "msg_id": msg_id if msg_id is not None else new_id(),
        "type": type_,
        "src": src,
        "dst": dst,
        "cmd": cmd,
        "ts": now_iso(),
        "payload": payload if payload is not None else {},
        "reply_to": reply_to,
    }
    msg.update(extra)
    return msg


def validate_envelope(msg):
    """Проверить конверт по PROTOCOL.md; при нарушении — ValueError с именем поля.

    Для request/event поле cmd обязательно; для response допускается None
    (совместимость с ответами подсистем, собранных на ранней версии модуля).
    Содержимое payload (правила common/validation.json) проверяет подсистема-получатель.
    """
    if not isinstance(msg, dict):
        raise ValueError("сообщение должно быть объектом")
    mid = msg.get("msg_id")
    if not isinstance(mid, int) or isinstance(mid, bool) or mid < 0:
        raise ValueError("msg_id")
    if msg.get("type") not in MSG_TYPES:
        raise ValueError("type")
    if msg.get("src") not in SOURCES:
        raise ValueError("src")
    if msg.get("dst") not in SOURCES:
        raise ValueError("dst")
    cmd = msg.get("cmd")
    if cmd is None:
        if msg["type"] != "response":
            raise ValueError("cmd обязателен для %s" % msg["type"])
    elif not isinstance(cmd, str) or len(cmd) > MAX_STRING or not _CMD_RE.match(cmd):
        raise ValueError("cmd")
    ts = msg.get("ts")
    if not isinstance(ts, str) or not _TS_RE.match(ts):
        raise ValueError("ts")
    if not isinstance(msg.get("payload"), dict):
        raise ValueError("payload")
    rt = msg.get("reply_to")
    if rt is not None and (not isinstance(rt, int) or isinstance(rt, bool)):
        raise ValueError("reply_to")
    for field in ("src", "dst", "ts"):
        if len(msg[field]) > MAX_STRING:
            raise ValueError("%s: строка длиннее %d символов" % (field, MAX_STRING))
    if msg["type"] == "response":
        if msg["reply_to"] is None:
            raise ValueError("response: reply_to обязателен")
        if msg.get("status") not in ("ok", "error"):
            raise ValueError("status")
        if msg["status"] == "error":
            if not isinstance(msg.get("error_code"), str):
                raise ValueError("error_code")
            if not isinstance(msg.get("error_message"), str):
                raise ValueError("error_message")
    return msg


def encode_line(msg):
    """Сообщение -> байты UTF-8; одно сообщение на строку, разделитель \n."""
    return (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")


class StreamDecoder:
    """Сборка сообщений из потока байтов.

    SOCK_STREAM не передаёт границ сообщений, поэтому данные накапливаются
    и делятся по \n. feed() возвращает список полностью принятых сообщений;
    незавершённый хвост остаётся в буфере до следующих данных. Пустые строки
    пропускаются, некорректный JSON и превышение MAX_LINE — ValueError.
    """

    def __init__(self, max_line=MAX_LINE):
        self._buf = b""
        self._max = max_line

    def feed(self, data):
        """Добавить байты, вернуть список целых сообщений (dict)."""
        self._buf += data
        if len(self._buf) > self._max and b"\n" not in self._buf:
            raise ValueError("строка сообщения длиннее %d байт" % self._max)
        out = []
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                break
            line, self._buf = self._buf[:nl], self._buf[nl + 1:]
            if not line.strip():
                continue
            try:
                out.append(json.loads(line.decode("utf-8")))
            except (UnicodeDecodeError, ValueError) as e:
                raise ValueError("некорректная строка сообщения: %s" % e)
        return out


def _exchange(path, msg, timeout):
    """Одно соединение: отправить сообщение и дождаться response с reply_to==msg_id.

    События (type=event) и чужие/старые ответы пропускаются. Некорректный
    конверт запроса или ответа — ValueError (клиент выполнит повтор).
    """
    validate_envelope(msg)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(encode_line(msg))
        dec = StreamDecoder()
        while True:
            chunk = s.recv(65536)
            if not chunk:
                raise ConnectionError("соединение закрыто без ответа")
            for m in dec.feed(chunk):
                if not isinstance(m, dict) or m.get("type") == "event":
                    continue  # события подтверждения не требуют, ответ ждём отдельно
                try:
                    validate_envelope(m)
                except ValueError as e:
                    raise ValueError("некорректный ответ подсистемы: %s" % e)
                if m.get("type") == "response" and m.get("reply_to") == msg["msg_id"]:
                    return m
                # чужой или старый ответ — продолжаем ждать свой


def _m16_text(dst):
    """Текст M16 из common/messages.json; резервный вариант без codes."""
    try:
        return _codes.message_text("M16", name=dst)
    except Exception:
        return "Ошибка: подсистема «%s» не отвечает. Операция не выполнена" % dst


def request(path, src, dst, cmd, payload=None, timeout=TIMEOUT_SEC, retries=RETRIES):
    """Запрос подсистеме по пути path (например /run/fw/cli.sock).

    До retries повторов с тем же msg_id: получатель по msg_id возвращает прежний
    ответ и не выполняет команду повторно (PROTOCOL.md). Ответ status=error
    поднимает ProtocolError с error_code из messages.json. Ответа нет после
    повторов — ProtocolError("M16"); вызывающий обязан записать неуспешное
    событие в журнал (FR-28). Успех — полный конверт ответа (dict).
    """
    msg = make_msg("request", src, dst, cmd, payload)
    last = None
    for _ in range(retries + 1):
        try:
            resp = _exchange(path, msg, timeout)
        except (OSError, ValueError) as e:
            last = e
            continue
        if resp.get("status") == "error":
            raise ProtocolError(resp.get("error_code") or "M14",
                                resp.get("error_message") or "")
        return resp
    raise ProtocolError("M16", "%s (%s)" % (_m16_text(dst), last))


def send_event(path, src, dst, cmd, payload=None, timeout=TIMEOUT_SEC):
    """Отправить событие (type=event, например log.write.event); подтверждения нет.

    Ошибка соединения — OSError: очередь до 1000 событий и повтор каждые 5 с
    (PROTOCOL.md) ведёт вызывающая подсистема.
    """
    msg = make_msg("event", src, dst, cmd, payload)
    validate_envelope(msg)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(encode_line(msg))
    return msg


def serve(path, name, handler, cache_size=1024):
    """Поднять сервер на Unix-сокете path от имени подсистемы name.

    handler(msg) -> (status, payload, error_code, error_message). Повторный
    запрос с тем же (src, msg_id) получает прежний ответ без повторного
    выполнения handler, в том числе при параллельных повторах. Для событий
    (type=event) handler вызывается, ответ не отправляется, результат
    отбрасывается. Необработанное исключение handler не
    завершает процесс — ответ error с error_code="M14" и текстом исключения.
    Возвращает srv (socketserver): srv.serve_forever() / srv.shutdown() /
    srv.server_close(). Сокет создаётся с правами 0600 (PROTOCOL.md).
    """
    cache = {}
    order = []
    inflight = {}
    lock = threading.Lock()

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            dec = StreamDecoder()
            while True:
                try:
                    data = self.request.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    msgs = dec.feed(data)
                except ValueError:
                    continue  # мусор в потоке не роняет сервер
                for msg in msgs:
                    resp = self._process(msg)
                    if resp is None:
                        continue
                    try:
                        self.request.sendall(encode_line(resp))
                    except OSError:
                        return

        def _process(self, msg):
            try:
                validate_envelope(msg)
            except ValueError:
                return None  # некорректный конверт — строка игнорируется
            if msg["type"] == "event":
                try:
                    handler(msg)  # событие: обработать, подтверждения не требует
                except Exception:  # необработанные исключения не завершают процесс
                    pass
                return None
            if msg["type"] != "request":
                return None  # ответы серверу не адресуются
            # Ключ — пара (src, msg_id): одинаковые msg_id от разных подсистем не смешиваются
            mid = (msg["src"], msg["msg_id"])
            with lock:
                hit = cache.get(mid)
                if hit is not None:
                    return hit  # повтор: прежний ответ, handler не вызывается
                ev = inflight.get(mid)
                owner = ev is None
                if owner:
                    inflight[mid] = threading.Event()
            if not owner:
                ev.wait(TIMEOUT_SEC)  # параллельный повтор: дождаться владельца
                with lock:
                    return cache.get(mid)
            resp = None
            try:
                try:
                    status, payload, ec, em = handler(msg)
                except Exception as e:  # необработанные исключения не завершают процесс
                    status, payload, ec, em = "error", {}, "M14", str(e)
                if not isinstance(payload, dict):
                    payload = {}
                src_name = msg.get("dst") if msg.get("dst") in SOURCES else name
                resp = make_msg("response", src_name, msg.get("src"), cmd=msg.get("cmd"),
                                reply_to=msg["msg_id"], status=status, error_code=ec,
                                error_message=em, payload=payload)
                return resp
            finally:
                with lock:
                    if resp is None:
                        resp = make_msg("response", name, msg.get("src"), reply_to=msg["msg_id"],
                                        status="error", error_code="M16",
                                        error_message="внутренняя ошибка сервера", payload={})
                    cache[mid] = resp
                    order.append(mid)
                    while len(order) > cache_size:
                        cache.pop(order.pop(0), None)
                    waiter = inflight.pop(mid, None)
                    if waiter is not None:
                        waiter.set()

    if os.path.exists(path):
        os.unlink(path)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    srv = socketserver.ThreadingUnixStreamServer(path, H)
    srv.daemon_threads = True
    os.chmod(path, 0o600)
    return srv
