"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  общее (common/fwcommon)
Модуль:      test_protocol
Назначение:  модульные тесты кодека протокола: конверт и валидация, ISO-метка
             времени, msg_id, кодирование строк, StreamDecoder (границы сообщений
             в потоке), поведение request (ошибки M-кодов, M16, дедупликация при
             повторах) и serve (события и старые ответы пропускаются, исключение
             handler не завершает процесс).
Запуск:      make test  (из корня репозитория) или
             python3 tests/unit/test_protocol.py
"""
import json
import os
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "common"))
from fwcommon import protocol  # noqa: E402


def _ok_msg(**kw):
    base = dict(type_="request", src="cli", dst="authd", cmd="auth.ping", payload={})
    base.update(kw)
    return protocol.make_msg(**base)


class NowIsoTest(unittest.TestCase):
    def test_format(self):
        ts = protocol.now_iso()
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


class NewIdTest(unittest.TestCase):
    def test_unique_and_monotonic(self):
        ids = [protocol.new_id() for _ in range(100)]
        self.assertEqual(len(set(ids)), 100)
        self.assertEqual(ids, sorted(ids))


class MakeMsgTest(unittest.TestCase):
    def test_defaults(self):
        msg = _ok_msg()
        self.assertIsInstance(msg["msg_id"], int)
        self.assertEqual(msg["type"], "request")
        self.assertEqual(msg["payload"], {})
        self.assertIsNone(msg["reply_to"])
        self.assertRegex(msg["ts"], r"\.\d{3}Z$")


class ValidateEnvelopeTest(unittest.TestCase):
    def test_valid_request(self):
        msg = _ok_msg()
        self.assertIs(protocol.validate_envelope(msg), msg)

    def test_valid_event_without_payload_keys(self):
        msg = protocol.make_msg("event", "filter", "logd", "log.write.event",
                                payload={"code": "E01"})
        self.assertIs(protocol.validate_envelope(msg), msg)

    def test_bad_type(self):
        with self.assertRaises(ValueError):
            protocol.validate_envelope(_ok_msg(type_="reply"))

    def test_bad_src(self):
        with self.assertRaises(ValueError):
            protocol.validate_envelope(_ok_msg(src="admin"))

    def test_bad_dst(self):
        with self.assertRaises(ValueError):
            protocol.validate_envelope(_ok_msg(dst="core"))

    def test_cmd_required_for_request(self):
        msg = _ok_msg()
        msg["cmd"] = None
        with self.assertRaises(ValueError):
            protocol.validate_envelope(msg)

    def test_cmd_format(self):
        for bad in ("authlogin", "Auth.login", "auth", "auth."):
            with self.assertRaises(ValueError):
                protocol.validate_envelope(_ok_msg(cmd=bad))

    def test_cmd_too_long(self):
        with self.assertRaises(ValueError):
            protocol.validate_envelope(_ok_msg(cmd="a." + "b" * 255))

    def test_bad_ts(self):
        msg = _ok_msg()
        msg["ts"] = "2026-03-14 10:21:33"
        with self.assertRaises(ValueError):
            protocol.validate_envelope(msg)

    def test_payload_must_be_dict(self):
        with self.assertRaises(ValueError):
            protocol.validate_envelope(_ok_msg(payload=[1, 2]))

    def test_response_requires_reply_to(self):
        resp = protocol.make_msg("response", "authd", "cli", reply_to=None,
                                 status="ok", payload={})
        with self.assertRaises(ValueError):
            protocol.validate_envelope(resp)

    def test_response_bad_status(self):
        resp = protocol.make_msg("response", "authd", "cli", cmd="auth.ping",
                                 reply_to=1, status="maybe", payload={})
        with self.assertRaises(ValueError):
            protocol.validate_envelope(resp)

    def test_error_response_requires_error_code(self):
        resp = protocol.make_msg("response", "authd", "cli", cmd="auth.ping",
                                 reply_to=1, status="error", payload={})
        with self.assertRaises(ValueError):
            protocol.validate_envelope(resp)


class EncodeLineTest(unittest.TestCase):
    def test_line_format_and_utf8(self):
        raw = protocol.encode_line(_ok_msg(payload={"note": "правило"}))
        self.assertTrue(raw.endswith(b"\n"))
        self.assertIn("правило".encode("utf-8"), raw)  # ensure_ascii=False
        self.assertEqual(json.loads(raw.decode("utf-8"))["cmd"], "auth.ping")


class StreamDecoderTest(unittest.TestCase):
    def test_single_message(self):
        dec = protocol.StreamDecoder()
        msgs = dec.feed(protocol.encode_line(_ok_msg()))
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["cmd"], "auth.ping")

    def test_two_messages_one_feed(self):
        dec = protocol.StreamDecoder()
        data = protocol.encode_line(_ok_msg()) + protocol.encode_line(_ok_msg(cmd="auth.check"))
        msgs = dec.feed(data)
        self.assertEqual([m["cmd"] for m in msgs], ["auth.ping", "auth.check"])

    def test_split_across_feeds(self):
        dec = protocol.StreamDecoder()
        raw = protocol.encode_line(_ok_msg(payload={"note": "разрыв потока"}))
        self.assertEqual(dec.feed(raw[:5]), [])
        msgs = dec.feed(raw[5:])
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["payload"]["note"], "разрыв потока")

    def test_empty_lines_skipped(self):
        dec = protocol.StreamDecoder()
        data = b"\n" + protocol.encode_line(_ok_msg()) + b"\n\n"
        self.assertEqual(len(dec.feed(data)), 1)

    def test_garbage_raises(self):
        dec = protocol.StreamDecoder()
        with self.assertRaises(ValueError):
            dec.feed(b"{not json}\n")

    def test_oversize_raises(self):
        dec = protocol.StreamDecoder(max_line=64)
        with self.assertRaises(ValueError):
            dec.feed(b"x" * 100)  # нет \n, превышен предел


class _EventFirstHandler(socketserver.StreamRequestHandler):
    """Тестовый сервер: сначала событие и чужой ответ, затем нужный ответ."""

    def handle(self):
        line = self.rfile.readline()
        req = json.loads(line.decode("utf-8"))
        event = protocol.make_msg("event", "authd", "cli", cmd="log.write.event",
                                  payload={"note": "до ответа"})
        stale = protocol.make_msg("response", "authd", "cli", cmd=req["cmd"],
                                  reply_to=req["msg_id"] + 999999,
                                  status="ok", payload={"stale": True})
        proper = protocol.make_msg("response", "authd", "cli", cmd=req["cmd"],
                                   reply_to=req["msg_id"],
                                   status="ok", payload={"after_noise": True})
        self.wfile.write(protocol.encode_line(event)
                         + protocol.encode_line(stale)
                         + protocol.encode_line(proper))


class ExchangeNoiseTest(unittest.TestCase):
    """_exchange пропускает события и чужие ответы, возвращает ответ по reply_to."""

    def test_noise_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "noise.sock")
            srv = socketserver.ThreadingUnixStreamServer(path, _EventFirstHandler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                resp = protocol._exchange(path, _ok_msg(), 2)
                self.assertTrue(resp["payload"]["after_noise"])
            finally:
                srv.shutdown()
                srv.server_close()


class RequestErrorTest(unittest.TestCase):
    """Ответ status=error -> ProtocolError с кодом из messages.json."""

    def test_error_status_raises(self):
        def handler(msg):
            return ("error", {}, "M02", "Ошибка: неверный идентификатор или пароль")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "err.sock")
            srv = protocol.serve(path, "authd", handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                with self.assertRaises(protocol.ProtocolError) as cm:
                    protocol.request(path, "cli", "authd", "auth.login",
                                     {"user": "admin", "password": "x"})
                self.assertEqual(cm.exception.code, "M02")
            finally:
                srv.shutdown()
                srv.server_close()

    def test_no_subsystem_m16(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "missing.sock")
            with self.assertRaises(protocol.ProtocolError) as cm:
                protocol.request(path, "cli", "authd", "auth.ping", timeout=0.2, retries=1)
            self.assertEqual(cm.exception.code, "M16")

    def test_slow_server_retries_same_id_and_dedup(self):
        """Повторы идут с тем же msg_id; сервер выполняет команду один раз."""
        calls = []
        lock = threading.Lock()

        def slow_handler(msg):
            with lock:
                calls.append(msg["msg_id"])
            time.sleep(0.8)
            return ("ok", {"echo": msg["cmd"]}, None, None)

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "slow.sock")
            srv = protocol.serve(path, "authd", slow_handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                with self.assertRaises(protocol.ProtocolError) as cm:
                    protocol.request(path, "cli", "authd", "auth.ping",
                                     timeout=0.2, retries=2)
                self.assertEqual(cm.exception.code, "M16")
                self.assertEqual(len(calls), 1)  # повтор не выполняет команду заново
                self.assertEqual(len(set(calls)), len(calls))  # msg_id один и тот же
            finally:
                srv.shutdown()
                srv.server_close()


class ServeRobustnessTest(unittest.TestCase):
    def test_handler_exception_does_not_kill_server(self):
        def bad_handler(msg):
            raise RuntimeError("внутренняя ошибка")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.sock")
            srv = protocol.serve(path, "authd", bad_handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                with self.assertRaises(protocol.ProtocolError) as cm:
                    protocol.request(path, "cli", "authd", "auth.ping")
                self.assertEqual(cm.exception.code, "M14")
                # сервер продолжает работать
                with self.assertRaises(protocol.ProtocolError) as cm2:
                    protocol.request(path, "cli", "authd", "auth.check")
                self.assertEqual(cm2.exception.code, "M14")
            finally:
                srv.shutdown()
                srv.server_close()

    def test_socket_permissions_0600(self):
        def handler(msg):
            return ("ok", {}, None, None)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "perm.sock")
            srv = protocol.serve(path, "authd", handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                mode = os.stat(path).st_mode & 0o777
                self.assertEqual(mode, 0o600)  # PROTOCOL.md
            finally:
                srv.shutdown()
                srv.server_close()

    def test_garbage_line_does_not_kill_server(self):
        def handler(msg):
            return ("ok", {"echo": msg["cmd"]}, None, None)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "g.sock")
            srv = protocol.serve(path, "authd", handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect(path)
                    s.sendall("+++ мусор без json +++\n".encode("utf-8"))
                resp = protocol.request(path, "cli", "authd", "auth.ping")
                self.assertEqual(resp["status"], "ok")
            finally:
                srv.shutdown()
                srv.server_close()


class ServeDedupKeyTest(unittest.TestCase):
    """Одинаковый msg_id от разных клиентов не должен давать чужой кэшированный ответ."""

    def _serve(self, d, handler):
        path = os.path.join(d, "k.sock")
        srv = protocol.serve(path, "authd", handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return path, srv

    def test_same_msg_id_different_src_not_mixed(self):
        def handler(msg):
            return ("ok", {"for": msg["src"]}, None, None)
        with tempfile.TemporaryDirectory() as d:
            path, srv = self._serve(d, handler)
            try:
                a = protocol._exchange(path, protocol.make_msg(
                    "request", "cli", "authd", "auth.ping", msg_id=7), 2)
                b = protocol._exchange(path, protocol.make_msg(
                    "request", "web", "authd", "auth.ping", msg_id=7), 2)
                self.assertEqual(a["payload"]["for"], "cli")
                self.assertEqual(b["payload"]["for"], "web")
                self.assertEqual(b["reply_to"], 7)
            finally:
                srv.shutdown()
                srv.server_close()

    def test_new_id_start_not_fixed(self):
        # два процесса не должны начинать нумерацию с одного и того же значения
        import subprocess
        code = ("import sys; sys.path.insert(0, %r); "
                "from fwcommon import protocol; print(protocol.new_id())"
                % os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))
        ids = {subprocess.check_output([sys.executable, "-c", code]).strip() for _ in range(3)}
        self.assertGreater(len(ids), 1)


class ServeEventTest(unittest.TestCase):
    def test_event_reaches_handler_without_response(self):
        got = []
        done = threading.Event()

        def handler(msg):
            got.append(msg)
            done.set()
            return ("ok", {}, None, None)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ev.sock")
            srv = protocol.serve(path, "logd", handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                protocol.send_event(path, "cli", "logd", "log.write.event",
                                    {"code": "E50", "cmd": "rule add"})
                self.assertTrue(done.wait(2))
                self.assertEqual(got[0]["type"], "event")
                self.assertEqual(got[0]["payload"]["code"], "E50")
                # на событие сервер не отвечает: соединение закрывается без данных
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect(path)
                    s.sendall(protocol.encode_line(protocol.make_msg(
                        "event", "cli", "logd", "log.write.event", {"code": "E02"})))
                    with self.assertRaises(socket.timeout):
                        s.recv(1)
            finally:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()
