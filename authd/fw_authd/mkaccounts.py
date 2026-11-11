"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-5 Авторизация
Модуль:      mkaccounts
Назначение:  создание начального accounts.json при сборке ПО МЭ
"""
import argparse
import getpass
import sys
from typing import List, Optional

from . import accounts

# Публичное имя оставлено в модуле утилиты для программного использования.
mkaccounts = accounts.mkaccounts


def _read_password(password_file: Optional[str]) -> str:
    if password_file:
        with open(password_file, "r", encoding="utf-8") as f:
            return f.read().rstrip("\r\n")

    password = getpass.getpass("Пароль admin: ")
    confirmation = getpass.getpass("Повторите пароль admin: ")
    if password != confirmation:
        raise ValueError("введённые пароли не совпадают")
    return password


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mkaccounts",
        description="Создать начальный accounts.json с учётной записью admin/rw.",
    )
    parser.add_argument(
        "--output",
        default=accounts.DEFAULT_ACCOUNTS_PATH,
        help="путь к создаваемому accounts.json (по умолчанию %(default)s)",
    )
    parser.add_argument(
        "--password-file",
        help="прочитать пароль из файла вместо безопасного интерактивного ввода",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=accounts.DEFAULT_HASH_ITERATIONS,
        help="число итераций PBKDF2 (по умолчанию %(default)s)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="разрешить замену существующего файла",
    )
    args = parser.parse_args(argv)

    try:
        password = _read_password(args.password_file)
        mkaccounts(
            password,
            path=args.output,
            iterations=args.iterations,
            overwrite=args.force,
        )
    except (OSError, ValueError) as exc:
        print("mkaccounts: %s" % exc, file=sys.stderr)
        return 1

    print("Создан файл учётных записей: %s" % args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
