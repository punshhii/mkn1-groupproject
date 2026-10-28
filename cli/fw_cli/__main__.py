"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      main
Назначение:  точка входа fw-cli: локальная консоль или SSH (ForceCommand, FR-02)
Методы:
  - main — разбор аргументов, создание ядра управления, цикл CLI
Запуск:      PYTHONPATH=common:cli python3 -m fw_cli [--run-dir /run/fw] [--config /etc/fw/config.json]
"""
import argparse
import sys

from . import core, repl, session


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fw-cli", description="командный интерфейс ПО МЭ")
    ap.add_argument("--run-dir", default="/run/fw", help="каталог сокетов подсистем")
    ap.add_argument("--config", default=None, help="config.json (по умолчанию /etc/fw/config.json)")
    ap.add_argument("--ifaces", default=None,
                    help="интерфейсы через запятую вместо config.json (для стенда)")
    args = ap.parse_args(argv)
    ifaces = args.ifaces.split(",") if args.ifaces else None
    c = core.Core(run_dir=args.run_dir, ifaces=ifaces, config_path=args.config)
    try:
        return repl.run(c, ip=session.client_ip())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
