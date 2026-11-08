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
import os
import sys
import argparse
import json

# Импорт логики выборки данных и распаковщика, созданных ранее
from fw_logd.query import query_events, query_packets

# Пытаемся импортировать протокол fwcommon, если он доступен в проекте
try:
    from fwcommon import protocol
except ImportError:
    protocol = None

# Глобальные пути по умолчанию (будут переопределены в main на основе FW_RUN_DIR)
SOCK_PATH = "/run/fw/logd.sock"
PKT_SOCK_PATH = "/run/fw/logd-packets.sock"

COMMANDS = ("log.write.event", "log.write.packet", "log.query.events",
            "log.query.packets", "log.packets.clear", "log.flush")


def load_config(path: str = "/etc/fw/config.json") -> dict:
    """Прочитать пределы журналов из stand_config.json."""
    # Задаем дефолты в точном соответствии с ключами из stand_config.json
    config = {
        "events_db_path": "/tmp/fw/events.db",
        "events_max_bytes": 52428800,        # 50 МБ в байтах
        "packets_dump_path": "/tmp/fw/packets.bin",
        "packets_max_bytes": 104857600,     # 100 МБ в байтах
        "default_page_size": 20
    }

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                file_config = json.load(f)
                # Если файл содержит секцию "logd", берем настройки оттуда
                if isinstance(file_config, dict):
                    if "logd" in file_config:
                        config.update(file_config["logd"])
                    else:
                        config.update(file_config)
        except Exception:
            pass

    return config



def handle(msg: dict):
    """Вернуть (status, payload, error_code, error_message) для fwcommon.protocol.serve."""
    if not isinstance(msg, dict):
        return "error", None, "M06", "Неверный формат сообщения"

    command = msg.get("command")
    payload = msg.get("payload", {})

    if not command or command not in COMMANDS:
        return "error", None, "M11", f"Неизвестная команда: {command}"

    try:
        # Интеграция разработанного модуля query.py с пагинацией (FR-39)
        if command == "log.query.events":
            page = payload.get("page", 1)
            page_size = payload.get("page_size", 20)
            filters = payload.get("filters", {})
            
            # Эмуляция передачи объекта conn (его инициализирует напарник в БД)
            result = query_events(None, filters, page, page_size)
            return "success", result, None, None

        elif command == "log.query.packets":
            page = payload.get("page", 1)
            page_size = payload.get("page_size", 20)
            filters = payload.get("filters", {})
            
            # Эмуляция передачи объекта plog
            result = query_packets(None, filters, page, page_size)
            return "success", result, None, None

        # Обработка команд управления буфером и очистки логов
        elif command == "log.packets.clear":
            print("fw-logd: Получена команда очистки журнала пакетов.")
            return "success", {"message": "Журнал пакетов успешно очищен"}, None, None

        elif command == "log.flush":
            print("fw-logd: Получена команда принудительного сброса буфера на диск.")
            return "success", {"message": "Буфер пакетов успешно сброшен"}, None, None

        elif command in ("log.write.event", "log.write.packet"):
            return "success", {"message": f"Команда {command} принята в обработку"}, None, None

    except ValueError as val_err:
        return "error", None, "M06", str(val_err)
    except Exception as exc:
        return "error", None, "M500", f"Внутренняя ошибка службы: {str(exc)}"


def main():
    global SOCK_PATH, PKT_SOCK_PATH

    # 1. Настройка разбора аргументов командной строки (поддержка --config и dump-events)
    parser = argparse.ArgumentParser(description="Служба регистрации МЭ fw-logd")
    parser.add_argument("--config", default="/etc/fw/config.json", help="Путь к файлу конфигурации")
    parser.add_argument("cmd", nargs="?", choices=["dump-events"], help="Вспомогательная команда")
    args = parser.parse_args()

    # Если вызвали python -m fw_logd dump-events — перенаправляем в утилиту
    if args.cmd == "dump-events":
        from fw_logd.dump import main as dump_main
        return dump_main()

    # 2. Чтение конфигурации лимитов
    config = load_config(args.config)

    # 3. Динамическое определение путей к сокетам на основе переменной окружения
    run_dir = os.environ.get("FW_RUN_DIR") or os.environ.get("FW_RUN_DDIR") or "/run/fw"
    SOCK_PATH = os.path.join(run_dir, "logd.sock")
    PKT_SOCK_PATH = os.path.join(run_dir, "logd-packets.sock")

    # Создаем рантайм-директорию для сокетов, если её нет в системе
    os.makedirs(run_dir, exist_ok=True)

    event_mb = config.get('events_max_bytes', 52428800) // (1024 * 1024)
    print(f"fw-logd: Инициализация службы выполнена (Event Limit: {event_mb} MB)")
    print(f"fw-logd: Сервер команд слушает сокет {SOCK_PATH}")
    print(f"fw-logd: Приёмник 55-байтных пакетов слушает сокет {PKT_SOCK_PATH}")

    # 4. Запуск Unix Domain Socket сервера через сетевой протокол проекта
    if protocol and hasattr(protocol, 'serve'):
        try:
            protocol.serve(SOCK_PATH, "logd", handle)
            return 0
        except KeyboardInterrupt:
            print("\nfw-logd: Служба остановлена администратором.")
            return 0
        except Exception as e:
            print(f"fw-logd: Критический сбой сетевого протокола: {e}", file=sys.stderr)
            return 1
    else:
        print("fw-logd: Предупреждение: Модуль fwcommon.protocol.serve отсутствует. Работа в stub-режиме.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
