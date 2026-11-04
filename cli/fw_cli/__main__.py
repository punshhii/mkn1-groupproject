"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      main
Назначение:  точка входа fw-cli: локальная консоль или SSH (ForceCommand, FR-02)
Методы:
  - unix_sockets_available — есть ли в ОС Unix-сокеты (их нет в Python для Windows)
  - main — разбор аргументов, приёмник входящих команд (cli.sock), ядро управления, цикл CLI
Запуск:      PYTHONPATH=common:cli python3 -m fw_cli [--run-dir /run/fw] [--config /etc/fw/config.json]
"""
import argparse
import os
import signal
import socket
import sys

from . import core, listener, repl, session

NO_UNIX_SOCKETS = ("fw-cli: Unix-сокеты недоступны в этой ОС. CLI работает в Linux "
                   "(Debian 12 на стенде или WSL в Windows).")


def unix_sockets_available():
    return hasattr(socket, "AF_UNIX")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fw-cli", description="командный интерфейс ПО МЭ")
    ap.add_argument("--run-dir", default="/run/fw", help="каталог сокетов подсистем")
    ap.add_argument("--config", default=None, help="config.json (по умолчанию /etc/fw/config.json)")
    ap.add_argument("--ifaces", default=None,
                    help="интерфейсы через запятую вместо config.json (для стенда)")
    args = ap.parse_args(argv)
    if not unix_sockets_available():
        print(NO_UNIX_SOCKETS, file=sys.stderr)
        return 1
    ifaces = args.ifaces.split(",") if args.ifaces else None
    # Входящие emergency.* / session.terminate: приёмник будит цикл CLI сигналом SIGUSR1
    signal.signal(signal.SIGUSR1, repl.on_wake_signal)
    pid = os.getpid()
    inbox = listener.start(os.path.join(args.run_dir, "cli.sock"),
                           on_change=lambda: os.kill(pid, signal.SIGUSR1))
    c = core.Core(run_dir=args.run_dir, ifaces=ifaces, config_path=args.config, inbox=inbox)
    try:
        return repl.run(c, ip=session.client_ip())
    except KeyboardInterrupt:
        return 130
    finally:
        inbox.close()


if __name__ == "__main__":
    sys.exit(main())
