"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      test_emergency
Назначение:  unit-тесты аварийного режима и доставки команд (FR-04, FR-28, FR-48)
Методы:
  - Net — подсистемы-заглушки вместо protocol.request и send_event
  - OrderTest — порядок команд при входе в режим и выходе из него
  - UnavailableTest — недоступность одного из получателей
  - ResendTest — повторная отправка и идемпотентность
  - StartupTest — запуск: traffic.unblock только после успешной проверки
  - EventQueueTest — очередь событий при недоступной ПС-2
  - SocketTest — настоящие сокеты: type=request, тот же msg_id при повторах
"""
import contextlib
import io
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from fwcommon import codes, protocol
from fw_integrityd import emergency

OK_RESULT = {"ok": True, "baseline_error": None, "files": [{"path": "/a", "status": "ok"}]}
BAD_RESULT = {"ok": False, "baseline_error": None, "files": [{"path": "/a", "status": "mismatch"},
                                                              {"path": "/b", "status": "ok"}]}
BAD_FILES = {"baseline_error": None, "files": [{"path": "/a", "status": "mismatch"}]}


def wait_until(condition, timeout=30):  # запас для медленной ВМ: при успехе ожидание заканчивается сразу
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("условие не выполнено за отведённое время")
        time.sleep(0.005)


class Net:
    """Журнал обмена: записи (dst, cmd) и event_code в порядке отправки."""

    def __init__(self):
        self.lock = threading.Lock()
        self.log = []
        self.events = []
        self.acks = []  # подтверждённые команды
        self.payloads = {}
        self.down = set()  # не отвечают: исключение down_error
        self.down_error = ConnectionError  # как в common/ ветки main; в cli/stand — ProtocolError(Exception)
        self.hang = {}  # dst -> Event: ответ задержан до установки Event
        self.errors = set()  # отвечают status=error

    def request(self, path, src, dst, cmd, payload=None):
        if dst in self.hang:
            self.hang[dst].wait()
        with self.lock:
            self.log.append((dst, cmd))
            self.payloads[(dst, cmd)] = payload
            if dst in self.down:
                raise self.down_error(f"subsystem {dst} does not respond")
            if dst in self.errors:
                return {"status": "error"}
            self.acks.append((dst, cmd))
            return {"status": "ok"}

    def send_event(self, msg):
        with self.lock:
            if "logd" in self.down:
                raise OSError("logd unavailable")
            self.events.append(msg["payload"])

    def sent(self, dst=None):
        with self.lock:
            return [item for item in self.log if dst is None or item[0] == dst]

    def event(self, code):
        with self.lock:
            return [e for e in self.events if e["event_code"] == code]


class Fixture(unittest.TestCase):
    def setUp(self):
        self.net = Net()
        patchers = (mock.patch.object(emergency.protocol, "request", self.net.request),
                    mock.patch.object(emergency, "send_event", self.net.send_event),
                    mock.patch.object(emergency, "DELIVERY_RETRY_SEC", 0.01),
                    mock.patch.object(emergency, "EVENT_RETRY_SEC", 0.01))
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.stderr = io.StringIO()
        redirect = contextlib.redirect_stderr(self.stderr)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        self.em = emergency.Emergency()
        self.em.start()
        self.addCleanup(self.em.stop)

    def enter_and_wait(self):
        self.em.enter(BAD_FILES)
        wait_until(lambda: self.net.event("E40"))


class OrderTest(Fixture):
    def test_enter_order(self):
        """Вход в режим: traffic.block и state.clear в ПС-1, emergency.enter в ПС-3 и ПС-4, E40, M08 (FR-48)."""
        self.enter_and_wait()
        sent = self.net.sent()
        self.assertEqual(sent[:2], [("filter", "traffic.block"), ("filter", "state.clear")])
        self.assertCountEqual(sent[2:], [("cli", "emergency.enter"), ("web", "emergency.enter")])
        e40 = self.net.event("E40")
        self.assertEqual(len(e40), 1)
        self.assertEqual(e40[0]["result"], 1)
        self.assertEqual(e40[0]["details"], BAD_FILES)
        wait_until(lambda: codes.message_text("M08") in self.stderr.getvalue())

    def test_leave_order(self):
        """Выход из режима: traffic.unblock в ПС-1, emergency.exit в ПС-3 и ПС-4, E41."""
        self.enter_and_wait()
        self.em.leave()
        wait_until(lambda: self.net.event("E41"))
        sent = self.net.sent()[4:]
        self.assertEqual(sent[0], ("filter", "traffic.unblock"))
        self.assertCountEqual(sent[1:], [("cli", "emergency.exit"), ("web", "emergency.exit")])
        self.assertEqual(self.net.event("E41")[0]["result"], 1)

    def test_event_after_clients(self):
        """E40 регистрируется после того, как оба получателя обработали emergency.enter."""
        release = threading.Event()
        self.net.hang["web"] = release
        self.em.enter(BAD_FILES)
        wait_until(lambda: ("cli", "emergency.enter") in self.net.sent())
        self.assertEqual(self.net.event("E40"), [])
        release.set()
        wait_until(lambda: self.net.event("E40"))

    def test_both_clients_always(self):
        """emergency.enter и emergency.exit всегда уходят обеим подсистемам (с. 36)."""
        self.assertEqual(emergency.CLIENTS, ("cli", "web"))

    def test_mode_changes_at_once(self):
        """Режим меняется сразу, даже если ПС-1 ещё не ответила: integrity.status не отстаёт."""
        release = threading.Event()
        self.net.hang["filter"] = release
        self.addCleanup(release.set)
        self.em.enter(BAD_FILES)
        self.assertTrue(self.em.is_active())

    def test_m08_in_enter(self):
        """emergency.enter несёт M08: у ПС-6 нет своего вывода для администратора (FR-48)."""
        self.enter_and_wait()
        self.assertEqual(self.net.payloads[("web", "emergency.enter")],
                         {"error_code": "M08", "error_message": codes.message_text("M08")})

    def test_on_check(self):
        """Нарушение включает режим и попадает в E40 только нарушенными файлами."""
        self.em.on_check(BAD_RESULT)
        wait_until(lambda: self.net.event("E40"))
        self.assertTrue(self.em.is_active())
        self.assertEqual(self.net.event("E40")[0]["details"], BAD_FILES)

    def test_ok_check_does_not_leave(self):
        """Успешная проверка из режима не выводит: выход только после восстановления (с. 21)."""
        self.enter_and_wait()
        self.em.on_check(OK_RESULT)
        self.em.on_check(OK_RESULT)
        self.assertTrue(self.em.is_active())
        self.assertNotIn(("filter", "traffic.unblock"), self.net.sent())


class UnavailableTest(Fixture):
    def test_hung_client_does_not_delay_other(self):
        """Завис один получатель: второй получает emergency.enter сразу (с. 36)."""
        for hung, other in (("cli", "web"), ("web", "cli")):
            with self.subTest(hung=hung):
                self.net.log.clear()
                release = threading.Event()
                self.addCleanup(release.set)
                self.net.hang = {hung: release}
                em = emergency.Emergency()
                em.start()
                em.enter(BAD_FILES)
                wait_until(lambda: (other, "emergency.enter") in self.net.sent())
                self.assertNotIn((hung, "emergency.enter"), self.net.sent())
                release.set()
                em.stop()

    def test_down_client_failure_logged(self):
        """Получатель не ответил после повторов: неуспех с причиной в журнале (FR-28), второй подтвердил."""
        self.net.down.add("web")
        self.enter_and_wait()
        e40 = self.net.event("E40")[0]
        self.assertEqual(e40["result"], 0)
        self.assertEqual(e40["error_code"], "M16")
        self.assertEqual(list(e40["details"]["failed"]), ["web"])
        self.assertIn("web", e40["details"]["failed"]["web"])
        self.assertEqual(e40["details"]["files"], BAD_FILES["files"])
        self.assertEqual(self.net.sent("cli"), [("cli", "emergency.enter")])

    def test_retry_until_confirmed(self):
        """Отправка повторяется, пока недоступный получатель не подтвердит режим, затем прекращается (с. 36)."""
        self.net.down.add("web")
        self.enter_and_wait()
        wait_until(lambda: len(self.net.sent("web")) >= 3)
        self.net.down.discard("web")
        wait_until(lambda: ("web", "emergency.enter") in self.net.acks)
        settled = len(self.net.sent("web"))
        time.sleep(0.05)
        self.assertEqual(len(self.net.sent("web")), settled)
        self.assertEqual(len(self.net.sent("cli")), 1)

    def test_failure_logged_once(self):
        """Постоянная недоступность даёт одну запись E40, а не запись на каждый повтор."""
        self.net.down.add("cli")
        self.enter_and_wait()
        wait_until(lambda: len(self.net.sent("cli")) >= 5)
        self.assertEqual(len(self.net.event("E40")), 1)

    def test_error_status_not_confirmed(self):
        """Ответ status=error не подтверждает режим: отправка повторяется."""
        self.net.errors.add("web")
        self.enter_and_wait()
        self.assertEqual(self.net.event("E40")[0]["result"], 0)
        wait_until(lambda: len(self.net.sent("web")) >= 3)

    def test_both_down(self):
        """Оба получателя недоступны: в журнале оба, режим включён."""
        self.net.down.update(("cli", "web"))
        self.enter_and_wait()
        self.assertCountEqual(self.net.event("E40")[0]["details"]["failed"], ["cli", "web"])
        self.assertTrue(self.em.is_active())

    def test_filter_down(self):
        """ПС-1 недоступна: ПС-3 и ПС-4 всё равно получают emergency.enter, блокировка повторяется."""
        self.net.down.add("filter")
        self.enter_and_wait()
        self.assertIn(("cli", "emergency.enter"), self.net.sent())
        self.assertIn(("web", "emergency.enter"), self.net.sent())
        self.assertIn("filter", self.net.event("E40")[0]["details"]["failed"])
        wait_until(lambda: len(self.net.sent("filter")) >= 3)
        self.net.down.discard("filter")
        wait_until(lambda: ("filter", "state.clear") in self.net.sent())

    def test_other_exception_retried(self):
        """protocol.request бросает не ConnectionError (ProtocolError в common/ ветки cli/stand):
        доставка не прекращается, неуспех в журнале, ПС-1 после запуска получает traffic.unblock (с. 22)."""
        self.net.down_error = type("ProtocolError", (Exception,), {})
        self.net.down.add("filter")
        self.em.on_check(OK_RESULT)
        wait_until(lambda: len(self.net.sent("filter")) >= 3)
        self.net.down.discard("filter")
        wait_until(lambda: ("filter", "traffic.unblock") in self.net.acks)
        self.net.down.add("web")
        self.enter_and_wait()
        self.assertIn("web", self.net.event("E40")[0]["details"]["failed"])
        self.assertIn(("cli", "emergency.enter"), self.net.acks)

    def test_exit_replaces_undelivered_enter(self):
        """Режим сменился до подтверждения: получатель в итоге видит последний режим, старый enter не приходит."""
        self.net.down.add("web")
        self.enter_and_wait()
        self.em.leave()
        wait_until(lambda: self.net.event("E41"))
        wait_until(lambda: ("web", "emergency.exit") in self.net.sent())
        self.net.down.discard("web")
        wait_until(lambda: ("web", "emergency.exit") in self.net.acks)
        settled = len(self.net.sent("web"))
        time.sleep(0.05)
        self.assertEqual(len(self.net.sent("web")), settled)
        self.assertEqual([ack for ack in self.net.acks if ack[0] == "web"], [("web", "emergency.exit")])

    def test_leave_waits_for_enter(self):
        """Выход не обгоняет незавершённый вход: сначала блокировка, потом снятие."""
        release = threading.Event()
        self.net.hang["filter"] = release
        self.em.enter(BAD_FILES)
        self.em.leave()
        release.set()
        wait_until(lambda: self.net.event("E41"))
        self.assertEqual([c for _, c in self.net.sent("filter")],
                         ["traffic.block", "state.clear", "traffic.unblock"])


class ResendTest(Fixture):
    def test_repeated_enter(self):
        """Повторный вход (периодическая проверка) не дублирует команды и E40: команды идемпотентны."""
        self.enter_and_wait()
        sent = len(self.net.sent())
        self.em.enter(BAD_FILES)
        self.em.on_check(BAD_RESULT)
        time.sleep(0.05)
        self.assertEqual(len(self.net.sent()), sent)
        self.assertEqual(len(self.net.event("E40")), 1)

    def test_repeated_leave(self):
        """Выход в штатном режиме ничего не отправляет и E41 не регистрирует."""
        self.em.leave()
        time.sleep(0.05)
        self.assertEqual(self.net.sent(), [])
        self.assertEqual(self.net.event("E41"), [])

    def test_second_violation_after_restore(self):
        """После выхода новое нарушение снова включает режим."""
        self.enter_and_wait()
        self.em.leave()
        wait_until(lambda: self.net.event("E41"))
        self.em.enter(BAD_FILES)
        wait_until(lambda: len(self.net.event("E40")) == 2)
        self.assertTrue(self.em.is_active())


class StartupTest(Fixture):
    def test_unblock_after_success(self):
        """Успешная проверка: traffic.unblock в ПС-1 (FR-04), emergency.exit и E41 не нужны."""
        self.em.on_check(OK_RESULT)
        wait_until(lambda: self.net.sent("filter"))
        self.assertEqual(self.net.sent(), [("filter", "traffic.unblock")])
        self.assertEqual(self.net.event("E41"), [])

    def test_unblock_waits_for_filter(self):
        """ПС-1 стартует позже ПС-6: traffic.unblock повторяется, пока ПС-1 не ответит (с. 22)."""
        self.net.down.add("filter")
        self.em.on_check(OK_RESULT)
        wait_until(lambda: len(self.net.sent("filter")) >= 3)
        self.net.down.discard("filter")
        wait_until(lambda: ("filter", "traffic.unblock") in self.net.acks)
        settled = len(self.net.sent("filter"))
        time.sleep(0.05)
        self.assertEqual(len(self.net.sent("filter")), settled)
        self.assertEqual(self.net.events, [])

    def test_no_unblock_on_violation(self):
        """Проверка не пройдена: обработка трафика не включается (FR-04, FR-48)."""
        self.em.on_check(BAD_RESULT)
        wait_until(lambda: self.net.event("E40"))
        self.assertNotIn(("filter", "traffic.unblock"), self.net.sent())

    def test_unblock_after_filter_restart(self):
        """Каждая успешная проверка повторяет traffic.unblock: перезапущенная ПС-1 снова в режиме drop-all."""
        self.em.on_check(OK_RESULT)
        wait_until(lambda: len(self.net.sent("filter")) == 1)
        self.em.on_check(OK_RESULT)
        wait_until(lambda: len(self.net.sent("filter")) == 2)

    def test_allow_traffic_after_enter(self):
        """Устаревшее разрешение не снимает блокировку: режим уже аварийный."""
        self.em.enter(BAD_FILES)
        self.em.allow_traffic()
        wait_until(lambda: self.net.event("E40"))
        time.sleep(0.05)
        self.assertNotIn(("filter", "traffic.unblock"), self.net.sent())


class EventQueueTest(Fixture):
    def test_payload(self):
        """Поля log.write.event совпадают с таблицей events; result — 1 или 0, как в ПС-2 (с. 41)."""
        self.em.log_event("E42", False, {"files": []}, command="integrity.check")
        wait_until(lambda: self.net.event("E42"))
        self.assertEqual(self.net.event("E42")[0], {
            "event_code": "E42", "result": 0, "actor_type": 1, "actor_id": "integrityd", "actor_ip": None,
            "command": "integrity.check", "details": {"files": []}, "error_code": None})

    def test_queue_while_logd_down(self):
        """ПС-2 недоступна: события копятся и уходят по порядку, когда она появится (с. 32)."""
        self.net.down.add("logd")
        for code in ("E40", "E41", "E42"):
            self.em.log_event(code, True)
        time.sleep(0.03)
        self.assertEqual(self.net.events, [])
        self.net.down.discard("logd")
        wait_until(lambda: len(self.net.events) == 3)
        self.assertEqual([e["event_code"] for e in self.net.events], ["E40", "E41", "E42"])

    def test_queue_limit(self):
        """В очереди не более EVENT_QUEUE_MAX событий."""
        self.net.down.add("logd")
        for _ in range(emergency.EVENT_QUEUE_MAX + 10):
            self.em.log_event("E42", True)
        self.assertLessEqual(len(self.em._events), emergency.EVENT_QUEUE_MAX)


@unittest.skipIf(os.name == "nt", "AF_UNIX недоступен в Windows-Python")
class SocketTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patchers = (mock.patch.object(emergency, "RUN_DIR", self.tmp.name),
                    mock.patch.object(emergency, "DELIVERY_RETRY_SEC", 0.01),
                    mock.patch.object(emergency, "EVENT_RETRY_SEC", 0.01))
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.stderr = contextlib.redirect_stderr(io.StringIO())
        self.stderr.__enter__()
        self.addCleanup(self.stderr.__exit__, None, None, None)
        self.lock = threading.Lock()
        self.received = {}  # dst -> сообщения
        for dst in ("filter", "cli", "web"):
            self.serve(dst)
        self.logd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.logd.close)
        self.logd.bind(emergency.sock_path("logd"))
        self.logd.listen()
        self.logged = []
        threading.Thread(target=self.read_events, daemon=True).start()

    def read_events(self):
        while True:
            try:
                conn, _ = self.logd.accept()
            except OSError:
                return
            with conn, conn.makefile("r", encoding="utf-8") as lines:
                self.logged.extend(json.loads(line) for line in lines)

    def serve(self, dst):
        def handler(msg):
            with self.lock:
                self.received.setdefault(dst, []).append(msg)
            return "ok", {}, None, None

        server = protocol.serve(emergency.sock_path(dst), dst, handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def start(self):
        em = emergency.Emergency()
        em.start()
        self.addCleanup(em.stop)
        return em

    def test_request_type(self):
        """Команды режима уходят как запросы с ответом (type=request), событие E40 — как type=event."""
        self.start().enter(BAD_FILES)
        wait_until(lambda: self.logged)
        for dst in ("cli", "web"):
            msg = self.received[dst][0]
            self.assertEqual((msg["type"], msg["src"], msg["dst"], msg["cmd"]),
                             ("request", "integrityd", dst, "emergency.enter"))
        self.assertEqual((self.logged[0]["type"], self.logged[0]["cmd"]), ("event", "log.write.event"))
        self.assertEqual(self.logged[0]["payload"]["event_code"], "E40")

    def test_same_msg_id_on_retry(self):
        """Нет ответа: до двух повторов с тем же msg_id, затем неуспех в журнале и новая отправка (с. 36)."""
        os.unlink(emergency.sock_path("web"))
        seen = []
        web = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(web.close)
        web.bind(emergency.sock_path("web"))
        web.listen()

        def swallow():
            while True:
                try:
                    conn, _ = web.accept()
                except OSError:
                    return
                with conn, conn.makefile("r", encoding="utf-8") as lines:
                    seen.append(json.loads(lines.readline()))

        threading.Thread(target=swallow, daemon=True).start()
        self.start().enter(BAD_FILES)
        wait_until(lambda: len(seen) >= 4)
        wait_until(lambda: self.logged)
        first = seen[0]["msg_id"]
        self.assertEqual([m["msg_id"] for m in seen[:3]], [first] * 3)
        self.assertNotEqual(seen[3]["msg_id"], first)
        self.assertEqual({m["cmd"] for m in seen}, {"emergency.enter"})
        self.assertEqual(self.logged[0]["payload"]["result"], 0)
        self.assertEqual(self.received["cli"][0]["cmd"], "emergency.enter")

    def test_late_recipient(self):
        """Сокета получателя ещё нет: подсистема появилась и подтвердила режим."""
        os.unlink(emergency.sock_path("web"))
        self.received.pop("web", None)
        self.start().enter(BAD_FILES)
        wait_until(lambda: self.logged)
        self.serve("web")
        wait_until(lambda: self.received.get("web"))
        self.assertEqual(self.received["web"][0]["cmd"], "emergency.enter")


if __name__ == "__main__":
    unittest.main()
