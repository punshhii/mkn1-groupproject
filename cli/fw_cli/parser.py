"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      parser
Назначение:  разбор команд «группа действие [аргументы]»: слова команды,
             позиционные аргументы, именованные имя=значение; значения с
             пробелами — в двойных кавычках. Проверка числа аргументов и
             допустимых имён по таблице команд; значения полей проверяет
             модуль validation.
Методы:
  - ParseError — ошибка разбора с кодом сообщения (M06 или M14)
  - Command — результат разбора
  - tokenize — разбить строку на слова с учётом кавычек
  - parse — разобрать строку в Command по таблице команд
"""
from dataclasses import dataclass, field

from fwcommon import codes

from . import commands

MAX_LINE = 4096  # защитный предел длины введённой строки


class ParseError(Exception):
    """Ошибка разбора: code — M06 (аргументы) или M14 (неизвестная команда)."""

    def __init__(self, code, **kw):
        self.code = code
        self.field = kw.get("field")
        self.message = codes.message_text(code, **kw) if kw else codes.message_text(code)
        super().__init__(self.message)


@dataclass
class Command:
    spec: commands.CommandSpec
    args: dict = field(default_factory=dict)    # позиционные: имя из spec.args -> значение
    named: dict = field(default_factory=dict)   # именованные имя=значение
    flags: set = field(default_factory=set)     # ключевые слова, например {"password"}

    @property
    def name(self):
        return self.spec.name


def _bad(field_, allowed):
    return ParseError("M06", field=field_, allowed=allowed)


def tokenize(line):
    """Разбить строку на слова. Кавычки группируют пробелы: comment="a b" -> comment=a b.

    Внутри кавычек \\" — кавычка, \\\\ — обратная косая черта.
    Незакрытая кавычка — M06.
    """
    if len(line) > MAX_LINE:
        raise _bad("строка", "не длиннее %d символов" % MAX_LINE)
    tokens, cur, in_q, have = [], [], False, False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_q:
            if ch == "\\" and i + 1 < len(line) and line[i + 1] in "\"\\":
                cur.append(line[i + 1])
                i += 1
            elif ch == '"':
                in_q = False
            else:
                cur.append(ch)
        elif ch == '"':
            in_q, have = True, True
        elif ch.isspace():
            if cur or have:
                tokens.append("".join(cur))
            cur, have = [], False
        else:
            cur.append(ch)
        i += 1
    if in_q:
        raise _bad("кавычки", "значение в парных двойных кавычках")
    if cur or have:
        tokens.append("".join(cur))
    return tokens


def _split_named(token):
    """name=value -> (name, value); иначе None. Имя — строчные латинские буквы, цифры, «-», «_»."""
    name, sep, value = token.partition("=")
    if not sep or not name:
        return None
    if not all(c.islower() or c.isdigit() or c in "-_" for c in name) or not name[0].isalpha():
        return None
    return name, value


def parse(line):
    """Разобрать строку в Command. Пустая строка — None.

    Неизвестная команда (в т.ч. в верхнем регистре: имена команд строчные) — M14.
    Лишний, недостающий, повторный или недопустимый аргумент — M06.
    """
    tokens = tokenize(line)
    if not tokens:
        return None
    spec, n = commands.find(tokens)
    if spec is None:
        raise ParseError("M14")
    cmd = Command(spec=spec)
    positional = []
    for tok in tokens[n:]:
        kv = _split_named(tok)
        if kv is None:
            positional.append(tok)
            continue
        name, value = kv
        if name not in spec.named:
            allowed = ", ".join(spec.named) if spec.named else "нет именованных аргументов"
            raise _bad(name, allowed)
        if name in cmd.named:
            raise _bad(name, "указывается один раз")
        cmd.named[name] = value
    _bind_positional(cmd, positional)
    return cmd


def _bind_positional(cmd, values):
    """Сопоставить позиционные значения с описанием spec.args."""
    values = list(values)
    for arg in cmd.spec.args:
        if arg.startswith("'"):
            word = arg.strip("'")
            if values and values[0] == word:
                cmd.flags.add(word)
                values.pop(0)
            continue
        optional = arg.endswith("?")
        name = arg.rstrip("?")
        if not values:
            if optional:
                continue
            raise _bad(name, "обязательный аргумент: %s" % cmd.spec.help)
        cmd.args[name] = values.pop(0)
    if values:
        raise _bad(values[0], "лишний аргумент: %s" % cmd.spec.help)
