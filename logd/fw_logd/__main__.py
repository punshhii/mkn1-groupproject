"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-2 Регистрация
Модуль:      main
Назначение:  точка входа fw-logd: конфигурация, сервер на /run/fw/logd.sock, диспетчер команд log.*
Методы:
  - load_config — прочитать параметры журналов из конфигурации
  - make_handler — создать обработчик команд log.* с привязкой к БД и журналу пакетов
  - _packet_socket_worker — принимать подключения на сокете бинарных пакетов
  - _handle_packet_client — читать поток записей по 55 байт и передавать в PacketLog
  - dump_events — прочитать события из SQLite и вывести их в консоль
  - main — инициализировать хранилища, запустить приёмник пакетов и сервер protocol.serve
"""
import os
import sys
import json
import socket
import sqlite3
import argparse
import threading

# Импорт логики выборки данных и распаковщика, созданных ранее
from fwcommon import protocol
from fw_logd import event_log, rotation
from fw_logd.packet_log import PacketLog, RECORD_SIZE
from fw_logd.query import query_events, query_packets
from datetime import datetime, timezone

# Глобальные пути по умолчанию (будут переопределены в main на основе FW_RUN_DIR)
SOCK_PATH = "/run/fw/logd.sock"
PKT_SOCK_PATH = "/run/fw/logd-packets.sock"

COMMANDS = (
    "log.write.event",
    "log.write.packet",
    "log.query.events",
    "log.query.packets",
    "log.packets.clear",
    "log.flush"
)

def load_config(path: str = "/etc/fw/config.json") -> dict:
    """Прочитать пределы журналов из stand_config.json."""
    # Задаем дефолты в точном соответствии с ключами из stand_config.json
    config = {
        "events_db_path": "/tmp/fw/events.db",
        "events_max_bytes": 52428800,        # 50 МБ в байтах
        "packets_dump_path": "/tmp/fw/packets.bin",
        "packets_max_bytes": 104857600,     # 100 МБ в байтах
        "packets_block_records": 4096,
        "packets_flush_interval_ms": 1000,
        "default_page_size": 20
    }

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                file_config = json.load(f)
                # Если файл содержит секцию "logd", берем настройки оттуда
                if isinstance(file_config, dict):
                    if "logd" in file_config and isinstance(file_config["logd"], dict):
                        config.update(file_config["logd"])
                    else:
                        config.update(file_config)
        except Exception as e:
            print(f"fw-logd: предупреждение при чтении конфига {path}: {e}", file=sys.stderr)

    return config

def make_handler(conn: sqlite3.Connection, plog: PacketLog, config: dict):
    """Создать обработчик команд log.* с привязкой к БД и журналу пакетов."""

    def _build_emitter(actor: dict = None):
        """Сформировать функцию emit_event(code) с учетом актора для события E34."""
        def emit_event(code: str) -> None:
            actor_id = "logd"
            if code == "E34" and isinstance(actor, dict):
                actor_id = (
                    actor.get("user")
                    or actor.get("login")
                    or actor.get("actor_id")
                    or actor.get("id")
                    or "logd"
                )
            event_log.write_event(
                conn,
                {
                    "event_code": code,
                    "result": 1,
                    "actor_type": 1,
                    "actor_id": str(actor_id),
                }
            )
        return emit_event

    default_emit_event = _build_emitter()

    def handle(msg: dict):
        if not isinstance(msg, dict):
            return "error", None, "M06", "Неверный формат запроса"

        cmd = msg.get("cmd")
        payload = msg.get("payload") or {}

        if not cmd or cmd not in COMMANDS:
            return "error", None, "M11", f"Неизвестная команда: {cmd}"

        try:
            if cmd == "log.write.event":
                event_id = event_log.write_event(conn, payload)
                rotation.enforce_event_limit(
                    conn,
                    config["events_max_bytes"],
                    default_emit_event
                )
                return "ok", {"id": event_id}, None, None

            elif cmd == "log.query.events":
                page = payload.get("page", 1)
                page_size = payload.get("page_size", config.get("page_size", 20))
                filters = payload.get("filters", payload)
                result = query_events(conn, filters, page, page_size)
                return "ok", result, None, None

            elif cmd == "log.write.packet":
                raw = payload.get("raw")
                if isinstance(raw, str):
                    raw = bytes.fromhex(raw)
                if not isinstance(raw, bytes) or len(raw) != RECORD_SIZE:
                    return "error", None, "M06", "Ожидается 55 байт пакета"
                plog.append(raw)
                rotation.enforce_packet_limit(plog, default_emit_event)
                return "ok", None, None, None

            elif cmd == "log.query.packets":
                page = payload.get("page", 1)
                page_size = payload.get("page_size", config.get("page_size", 20))
                filters = payload.get("filters", payload)
                result = query_packets(plog, filters, page, page_size)
                return "ok", result, None, None

            elif cmd == "log.flush":
                plog.flush()
                rotation.enforce_packet_limit(plog, default_emit_event)
                return "ok", None, None, None


            elif cmd == "log.packets.clear":
                actor = payload.get("actor") or msg.get("actor") or {}
                rotation.clear_packets(plog, actor, _build_emitter(actor))
                return "ok", None, None, None

        except ValueError as val_err:
            err_str = str(val_err)
            return "error", None, "M06", err_str
        except Exception as exc:
            return "error", None, "M500", f"Внутренняя ошибка: {exc}"

    return handle


def _packet_socket_worker(pkt_sock_path: str, plog: PacketLog) -> None:
    """Принимать подключения на сокете бинарных пакетов."""
    if os.path.exists(pkt_sock_path):
        try:
            os.unlink(pkt_sock_path)
        except OSError:
            pass

    srv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv_sock.bind(pkt_sock_path)
    srv_sock.listen(16)

    while True:
        try:
            client_conn, _ = srv_sock.accept()
            threading.Thread(
                target=_handle_packet_client,
                args=(client_conn, plog),
                daemon=True
            ).start()
        except Exception as e:
            print(f"fw-logd: ошибка accept на сокете пакетов: {e}", file=sys.stderr)


def _handle_packet_client(client_conn: socket.socket, plog: PacketLog) -> None:
    """Чтение потока записей по 55 байт и передача в PacketLog."""
    buf = bytearray()
    try:
        with client_conn:
            while True:
                data = client_conn.recv(4096)
                if not data:
                    break
                buf.extend(data)
                while len(buf) >= RECORD_SIZE:
                    record = bytes(buf[:RECORD_SIZE])
                    del buf[:RECORD_SIZE]
                    plog.append(record)
    except Exception as e:
        print(f"fw-logd: ошибка чтения потока пакетов: {e}", file=sys.stderr)

def dump_events(db_path: str) -> int:
    """Прочитать события из SQLite и вывести их в консоль."""
    if not os.path.exists(db_path):
        print(f"База событий не найдена: {db_path}")
        return 1

    conn = event_log.init_db(db_path)
    try:
        res = query_events(conn, {}, page=1, page_size=10000)
        items = res.get("items", [])
        if not items:
            print("Журнал событий пуст.")
            return 0

        for ev in items:
            ts_us = ev.get("ts_us")
            if isinstance(ts_us, (int, float)):
                dt_str = datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            else:
                dt_str = str(ts_us)
            print(f"[{dt_str}] code={ev.get('event_code')} data={ev}")
        print(f"\nВсего событий: {res.get('total', len(items))}")
        return 0
    finally:
        conn.close()


def main() -> int:
    global SOCK_PATH, PKT_SOCK_PATH

    parser = argparse.ArgumentParser(description="Служба регистрации ПО МЭ (fw-logd)")
    parser.add_argument(
        "--config",
        default=os.environ.get("FW_CONFIG", "/etc/fw/config.json"),
        help="Путь к файлу конфигурации"
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["dump-events"],
        help="Разовая консольная команда (dump-events)"
    )
    args = parser.parse_args()

    config = load_config(args.config)

    # Обработка консольной команды python -m fw_logd dump-events
    if args.command == "dump-events":
        return dump_events(config["events_db_path"])

    run_dir = os.environ.get("FW_RUN_DIR", "/run/fw")
    os.makedirs(run_dir, exist_ok=True)

    SOCK_PATH = os.path.join(run_dir, "logd.sock")
    PKT_SOCK_PATH = os.path.join(run_dir, "logd-packets.sock")

    # Гарантируем существование папок для БД и дампа пакетов
    os.makedirs(os.path.dirname(os.path.abspath(config["events_db_path"])), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(config["packets_dump_path"])), exist_ok=True)

    # Инициализация хранилищ
    conn = event_log.init_db(config["events_db_path"])
    plog = PacketLog(
        config["packets_dump_path"],
        limit_bytes=config["packets_max_bytes"]
    )
    flush_period = config.get("packets_flush_interval_ms", 1000) / 1000.0
    plog.start_flusher(period_sec=flush_period)


    # Запуск фонового потока приёма 55-байтных пакетов
    pkt_thread = threading.Thread(
        target=_packet_socket_worker,
        args=(PKT_SOCK_PATH, plog),
        daemon=True
    )
    pkt_thread.start()

    # Создание обработчика и запуск основного сервера protocol.serve
    handler = make_handler(conn, plog, config)
    srv = protocol.serve(SOCK_PATH, "logd", handler)

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        plog.stop_flusher()
        plog.flush()
        conn.close()

    return 0

if __name__ == "__main__":
    sys.exit(main())
