"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-2 Регистрация
Модуль:      main
Назначение:  точка входа fw-logd: конфигурация, сервер на /run/fw/logd.sock, диспетчер команд log.*
Методы:
  - load_config — прочитать параметры журналов из /etc/fw/config.json
  - handle — обработать запрос (log.write.event, log.write.packet, log.query.*, log.packets.clear, log.flush)
  - main — запуск подсистемы
"""
import sys

SOCK_PATH = "/run/fw/logd.sock"
PKT_SOCK_PATH = "/run/fw/logd-packets.sock"  # решено: отдельный сокет, поток 55-байтных записей подряд, без JSON

COMMANDS = ("log.write.event", "log.write.packet", "log.query.events",
            "log.query.packets", "log.packets.clear", "log.flush")


def load_config(path: str = "/etc/fw/config.json") -> dict:
    """Прочитать пределы журналов (50 МБ / 100 МБ по умолчанию) и размер страницы."""
    raise NotImplementedError("main.load_config")


def handle(msg: dict):
    """Вернуть (status, payload, error_code, error_message) для fwcommon.protocol.serve."""
    raise NotImplementedError("main.handle")


def main():
    # TODO: load_config -> init_db -> PacketLog.start_flusher -> protocol.serve(SOCK_PATH, "logd", handle)
    print("fw-logd: skeleton, not implemented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
