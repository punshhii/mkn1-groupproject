"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      emergency
Назначение:  режим аварийной поддержки: блокировка трафика, E40, M08; выход из режима, E41 (FR-48, FR-49);
доставка команд режима в ПС-1, ПС-3, ПС-4 и событий в ПС-2
Методы:
  - sock_path — путь сокета подсистемы
  - send_event — отправить событие без ожидания ответа
  - Emergency.start — запустить потоки доставки
  - Emergency.stop — остановить потоки доставки
  - Emergency.is_active — включён ли режим аварийной поддержки
  - Emergency.on_check — реакция на результат проверки
  - Emergency.enter — войти в режим: traffic.block и state.clear в ПС-1, emergency.enter в ПС-3 и ПС-4, E40, M08
  - Emergency.leave — выйти из режима: traffic.unblock в ПС-1, emergency.exit в ПС-3 и ПС-4, E41
  - Emergency.allow_traffic — traffic.unblock после успешной проверки (FR-04)
  - Emergency.log_event — поставить событие log.write.event в очередь на отправку в ПС-2
"""
import collections
import json
import os
import queue
import socket
import sys
import threading

from fwcommon import codes, protocol

from . import checker

EVENT_QUEUE_MAX = 1000  # очередь событий при недоступной ПС-2
EVENT_RETRY_SEC = 5
DELIVERY_RETRY_SEC = 5  # допущение: период повтора в спецификации не задан, взят как у событий (с. 32)

SRC = "integrityd"
RUN_DIR = os.environ.get("FW_RUN_DIR", "/run/fw")
CLIENTS = ("cli", "web")  # emergency.enter и emergency.exit всегда уходят обеим подсистемам (с. 36)


def sock_path(dst: str) -> str:
    """Путь сокета подсистемы: /run/fw/<subsystem>.sock (с. 31)."""
    return os.path.join(RUN_DIR, dst + ".sock")


def send_event(msg: dict) -> None:
    """Отправить событие в ПС-2 без ожидания ответа: подтверждения оно не требует (с. 32).
    OSError - ПС-2 недоступна."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(protocol.TIMEOUT_SEC)
        s.connect(sock_path("logd"))
        s.sendall((json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))


class _Delivery:
    """Доставка команд одной подсистеме. У каждого получателя свой поток, поэтому его недоступность
    не задерживает других, а команды одного получателя не обгоняют друг друга. Команды идемпотентны:
    задача повторяется до подтверждения, новая задача заменяет недоставленную (важен последний режим)."""

    def __init__(self, dst: str):
        self.dst = dst
        self._cond = threading.Condition()
        self._task = None  # (команды, payload)
        self._seq = 0  # номер последней задачи
        self._tried = 0  # номер задачи, для которой завершилась первая попытка
        self._error = None  # причина неудачи этой попытки
        self._closed = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()
        self._thread.join()

    def post(self, cmds: tuple, payload: dict = None) -> None:
        """Заменить задачу; отправка идёт в потоке получателя."""
        with self._cond:
            self._task = (cmds, payload)
            self._seq += 1
            self._cond.notify_all()

    def wait_tried(self):
        """Дождаться конца первой попытки последней задачи (запрос и его повторы);
        вернуть причину неудачи или None. Сама доставка при неудаче продолжается."""
        with self._cond:
            seq = self._seq
            self._cond.wait_for(lambda: self._closed or self._tried >= seq)
            return self._error

    def _send(self, cmds: tuple, payload: dict):
        """Отправить команды по порядку; вернуть причину неудачи или None.
        protocol.request сам повторяет запрос с тем же msg_id (до двух раз, с. 32)."""
        for cmd in cmds:
            try:
                resp = protocol.request(sock_path(self.dst), SRC, self.dst, cmd, payload)
            except ConnectionError as e:
                return str(e)
            if not isinstance(resp, dict) or resp.get("status") != "ok":
                return f"{cmd}: режим не подтверждён"
        return None

    def _run(self) -> None:
        confirmed = 0
        while True:
            with self._cond:
                self._cond.wait_for(lambda: self._closed or self._seq != confirmed)
                if self._closed:
                    return
                seq, (cmds, payload) = self._seq, self._task
            error = self._send(cmds, payload)
            with self._cond:
                if self._tried != seq:
                    self._tried, self._error = seq, error
                    self._cond.notify_all()
                if error is None:
                    confirmed = seq
                else:
                    self._cond.wait_for(lambda: self._closed or self._seq != seq, DELIVERY_RETRY_SEC)


class Emergency:
    def __init__(self):
        self._active = False
        self._lock = threading.Lock()
        self._filter = _Delivery("filter")
        self._clients = [_Delivery(dst) for dst in CLIENTS]
        self._jobs = queue.Queue()  # переходы между режимами идут по очереди: leave не обгонит незавершённый enter
        self._events = collections.deque(maxlen=EVENT_QUEUE_MAX)
        self._events_ready = threading.Event()
        self._closed = threading.Event()
        self._threads = [threading.Thread(target=self._run_jobs, daemon=True),
                         threading.Thread(target=self._send_events, daemon=True)]

    def start(self) -> None:
        """Запустить потоки: по одному на получателя, переходы между режимами, отправка событий."""
        for delivery in (self._filter, *self._clients):
            delivery.start()
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        """Остановить потоки; недоставленные команды и события не сохраняются."""
        for delivery in (self._filter, *self._clients):
            delivery.close()
        self._jobs.put(None)
        self._closed.set()
        self._events_ready.set()
        for thread in self._threads:
            thread.join()

    def is_active(self) -> bool:
        """Вернуть True, если МЭ в режиме аварийной поддержки. Режим меняется сразу, ещё до рассылки команд."""
        return self._active

    def on_check(self, result: dict) -> None:
        """Реакция на результат проверки (не блокирует: команды уходят в других потоках).
        Нарушение — аварийный режим. Успех в штатном режиме — traffic.unblock: ПС-1 после запуска или
        перезапуска работает в режиме drop-all (с. 22). Из аварийного режима выводит только восстановление."""
        if not result["ok"]:
            self.enter(checker.violations(result))
        elif not self.is_active():
            self.allow_traffic()

    def enter(self, violations: dict) -> None:
        """Заблокировать трафик, очистить таблицу состояний, перевести ПС-3 и ПС-4 в режим аварийной поддержки,
        E40, M08 (FR-48). Повторный вызов в аварийном режиме ничего не меняет."""
        with self._lock:
            if self._active:
                return
            self._active = True
        self._jobs.put(lambda: self._enter(violations))

    def leave(self) -> None:
        """После успешной повторной проверки снять блокировку, вернуть штатный режим, E41.
        Повторный вызов в штатном режиме ничего не меняет."""
        with self._lock:
            if not self._active:
                return
            self._active = False
        self._jobs.put(self._leave)

    def allow_traffic(self) -> None:
        """Включить обработку трафика в ПС-1 после успешной проверки (FR-04). ПС-1 стартует позже ПС-6 (с. 22),
        поэтому команда повторяется, пока не будет подтверждена; событие не регистрируется: на этот случай его нет."""
        self._jobs.put(self._allow_traffic)

    def log_event(self, code: str, result: bool, details: dict = None, command: str = None, actor_type: int = 1,
                  actor_id: str = "integrityd", actor_ip: str = None, error_code: str = None) -> None:
        """Отправить log.write.event в ПС-2 (поля таблицы events, с. 41).
        Если ПС-2 недоступна — хранить в очереди (до EVENT_QUEUE_MAX), повторять каждые EVENT_RETRY_SEC."""
        self._events.append(protocol.make_msg("event", SRC, "logd", "log.write.event", {
            "event_code": code, "result": int(result), "actor_type": actor_type, "actor_id": actor_id,
            "actor_ip": actor_ip, "command": command, "details": details, "error_code": error_code}))
        self._events_ready.set()

    def _notify(self, filter_cmds: tuple, client_cmd: str, payload: dict = None) -> dict:
        """Первая попытка: сначала ПС-1, затем обе клиентские подсистемы; вернуть {получатель: причина неудачи}."""
        self._filter.post(filter_cmds)
        errors = {"filter": self._filter.wait_tried()}
        for delivery in self._clients:
            delivery.post((client_cmd,), payload)
        for delivery in self._clients:
            errors[delivery.dst] = delivery.wait_tried()
        return {dst: reason for dst, reason in errors.items() if reason}

    def _report(self, code: str, details: dict, failed: dict) -> None:
        """Зарегистрировать переход один раз; если первая попытка не удалась, результат неуспешный
        с причиной (FR-28), а доставка продолжается до подтверждения."""
        if failed:
            self.log_event(code, False, dict(details, failed=failed), error_code="M16")
        else:
            self.log_event(code, True, details)

    def _enter(self, violations: dict) -> None:
        failed = self._notify(("traffic.block", "state.clear"), "emergency.enter",
                              {"error_code": "M08", "error_message": codes.message_text("M08")})
        self._report("E40", violations, failed)
        print(codes.message_text("M08"), file=sys.stderr)

    def _leave(self) -> None:
        self._report("E41", {}, self._notify(("traffic.unblock",), "emergency.exit"))

    def _allow_traffic(self) -> None:
        if not self._active:
            self._filter.post(("traffic.unblock",))

    def _run_jobs(self) -> None:
        for job in iter(self._jobs.get, None):
            job()

    def _send_events(self) -> None:
        while not self._closed.is_set():
            if not self._events:
                self._events_ready.wait()
                self._events_ready.clear()
                continue
            msg = self._events.popleft()
            try:
                send_event(msg)
            except (OSError, ValueError):
                self._events.appendleft(msg)
                self._closed.wait(EVENT_RETRY_SEC)
