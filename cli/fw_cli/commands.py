"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      commands
Назначение:  таблица команд управления (таблица 7 ТЗ) в виде данных: права,
             события, доступность в режиме аварийной поддержки, подтверждение,
             позиционные и именованные аргументы. Общая для CLI и web.
Методы:
  - CommandSpec — описание одной команды
  - find — найти команду по началу списка слов (самое длинное совпадение)
  - groups — группы команд в порядке таблицы 7 (для help)
  - by_group — команды группы (для help группа)
  - help_text — текст help и help группа
"""
from dataclasses import dataclass

# Поля правила (таблица 2), именованные аргументы rule add / rule edit
RULE_FIELDS = ("in", "smac", "dmac", "src", "dst", "proto", "eth-proto", "sport", "dport",
               "icmp-type", "icmp-code", "action", "out", "to", "state", "active", "log",
               "comment")

# Критерии выборки журналов (FR-39) и номер страницы
EVENT_FILTERS = ("code", "from", "to", "page")
PACKET_FILTERS = ("action", "in", "out", "rule", "smac", "dmac", "src", "dst",
                  "sport", "dport", "from", "to", "page")

# Параметры конфигурации (таблица 3), именованные аргументы config set
CONFIG_PARAMS = ("tcp_syn_timeout_sec", "tcp_est_timeout_sec", "tcp_fin_timeout_sec",
                 "udp_timeout_no_reply", "udp_timeout_reply", "icmp_timeout_sec",
                 "state_table_size", "conntrack_enabled", "arp_forwarding", "ssh_port",
                 "https_port", "integrity_period_sec", "packets_log_max_mb",
                 "events_log_max_mb")


@dataclass(frozen=True)
class CommandSpec:
    """Команда таблицы 7.

    args — позиционные аргументы по порядку; имя с «?» — необязательный,
    имя в кавычках-апострофах ('password') — необязательное ключевое слово.
    named — допустимые именованные аргументы имя=значение.
    rw — нужна роль «чтение/запись» (иначе M03, E50).
    emergency — доступна в режиме аварийной поддержки (иначе M10).
    confirm — запрашивает «Подтвердите (y/n):».
    events — события при выполнении (E50 и E43 общие для всех изменяющих).
    """
    name: str
    group: str
    help: str
    rw: bool = False
    emergency: bool = True
    confirm: bool = False
    events: tuple = ()
    args: tuple = ()
    named: tuple = ()

    @property
    def words(self):
        return tuple(self.name.split())


def _c(name, group, help_, **kw):
    return CommandSpec(name=name, group=group, help=help_, **kw)


_RW = dict(rw=True, emergency=False)

_TABLE = (
    # Правила фильтрации (ТЗ 8.3)
    _c("rule list", "rule", "список правил со счётчиками срабатываний"),
    _c("rule show", "rule", "все поля правила N", args=("N",)),
    _c("rule add", "rule", "добавить правило: rule add N имя=значение ...",
       events=("E20",), args=("N",), named=RULE_FIELDS, **_RW),
    _c("rule edit", "rule", "изменить поля правила: rule edit N имя=значение ...",
       events=("E21",), args=("N",), named=RULE_FIELDS, **_RW),
    _c("rule enable", "rule", "включить правило N", events=("E21",), args=("N",), **_RW),
    _c("rule disable", "rule", "отключить правило N", events=("E21",), args=("N",), **_RW),
    _c("rule del", "rule", "удалить правило N (M11, если на него есть переход)",
       events=("E22",), args=("N",), **_RW),
    # Журналы (ТЗ 5.4–5.6)
    _c("log events show", "log", "журнал событий: [code=] [from=] [to=] [page=N]",
       named=EVENT_FILTERS),
    _c("log packets show", "log",
       "журнал пакетов: [action=pass|drop] [in=] [out=] [rule=N] [smac=] [dmac=] [src=] "
       "[dst=] [sport=] [dport=] [from=] [to=] [page=N]", named=PACKET_FILTERS),
    _c("log packets clear", "log", "очистить журнал пакетов", confirm=True,
       events=("E34",), **_RW),
    # Контроль состояний (ТЗ 9.7)
    _c("state status", "state", "настройки механизма контроля состояний"),
    _c("state table", "state", "таблица состояний"),
    _c("state enable", "state", "включить механизм", events=("E14",), **_RW),
    _c("state disable", "state", "отключить механизм", events=("E15",), **_RW),
    _c("state delete all", "state", "удалить все записи", confirm=True, events=("E35",), **_RW),
    _c("state delete", "state", "удалить запись ID", events=("E35",), args=("ID",), **_RW),
    # Конфигурации (ТЗ 5.8)
    _c("config show current", "config", "текущая конфигурация"),
    _c("config show saved", "config", "сохранённая конфигурация"),
    _c("config save", "config", "сохранить текущую конфигурацию и политику доступа",
       events=("E31",), **_RW),
    _c("config apply saved", "config", "применить сохранённую конфигурацию", confirm=True,
       events=("E31",), **_RW),
    _c("config apply default", "config", "применить конфигурацию по умолчанию", confirm=True,
       events=("E31",), **_RW),
    _c("config set", "config", "изменить параметр: config set имя=значение",
       events=("E30",), named=CONFIG_PARAMS, **_RW),
    # Учётные записи и сеансы (ТЗ 5.9)
    _c("user list", "user", "учётные записи без паролей"),
    _c("user add", "user", "добавить: user add ID role=rw|ro (пароль запрашивается)",
       events=("E32",), args=("ID",), named=("role",), **_RW),
    _c("user edit", "user", "изменить: user edit ID [role=rw|ro] [password]",
       events=("E32",), args=("ID", "'password'"), named=("role",), **_RW),
    _c("user del", "user", "удалить учётную запись ID", confirm=True,
       events=("E32", "E07"), args=("ID",), **_RW),
    _c("session list", "session", "активные сеансы"),
    _c("session kill", "session", "сбросить сеанс ID", events=("E05",), args=("ID",), **_RW),
    # Интерфейсы Ethernet (ТЗ 5.10)
    _c("if list", "if", "состояние интерфейсов"),
    _c("if show", "if", "состояние интерфейса ИМЯ", args=("NAME",)),
    _c("if up", "if", "включить интерфейс ИМЯ", events=("E33",), args=("NAME",), **_RW),
    _c("if down", "if", "выключить интерфейс ИМЯ", events=("E33",), args=("NAME",), **_RW),
    _c("if ip", "if", "IP-адрес интерфейса: if ip ИМЯ адрес/маска", events=("E33",),
       args=("NAME", "ADDR"), **_RW),
    # Система (ТЗ 5.11)
    _c("sys info", "sys", "процессор, память, интерфейсы, режим, состояние подсистем"),
    _c("time show", "time", "дата и время"),
    _c("time set", "time", "установить: time set \"ГГГГ-ММ-ДД чч:мм:сс\"", events=("E33",),
       args=("DATETIME",), **_RW),
    _c("route list", "route", "системные маршруты"),
    _c("route add", "route", "добавить: route add сеть/маска шлюз", events=("E33",),
       args=("NET", "GW"), **_RW),
    _c("route del", "route", "удалить: route del сеть/маска", events=("E33",),
       args=("NET",), **_RW),
    _c("subsystem list", "subsystem", "состояние подсистем"),
    _c("subsystem restart", "subsystem", "перезагрузить подсистему ИМЯ", confirm=True,
       events=("E13", "E12"), args=("NAME",), **_RW),
    _c("sys reboot", "sys", "перезагрузить устройство", confirm=True,
       events=("E11", "E10"), **_RW),
    _c("sys shutdown", "sys", "выключить устройство", confirm=True, events=("E11",), **_RW),
    # Контроль целостности (ТЗ 6) — check и restore доступны в аварийном режиме
    _c("integrity status", "integrity", "результат последней проверки и режим"),
    _c("integrity check", "integrity", "проверка целостности по запросу", rw=True,
       events=("E42",)),
    _c("integrity restore", "integrity", "восстановить: integrity restore ФАЙЛ|all", rw=True,
       events=("E41",), args=("FILE",)),
    # Служебные
    _c("help", "help", "список групп; help группа — синтаксис команд группы",
       args=("GROUP?",)),
    _c("whoami", "help", "идентификатор, роль, интерфейс и IP-адрес сеанса"),
    _c("logout", "help", "завершить сеанс", events=("E02",)),
    _c("exit", "help", "завершить сеанс", events=("E02",)),
)

COMMANDS = {c.name: c for c in _TABLE}

GROUP_TITLES = {
    "rule": "Правила фильтрации", "log": "Журналы", "state": "Контроль состояний",
    "config": "Конфигурации", "user": "Учётные записи", "session": "Сеансы",
    "if": "Интерфейсы Ethernet", "sys": "Система", "time": "Дата и время",
    "route": "Маршруты", "subsystem": "Подсистемы", "integrity": "Контроль целостности",
    "help": "Служебные",
}


def find(words):
    """Команда по началу списка слов; (spec, число слов имени) или (None, 0).

    Берётся самое длинное совпадение: «state delete all» раньше «state delete».
    """
    best = None
    for spec in _TABLE:
        w = spec.words
        if tuple(words[:len(w)]) == w and (best is None or len(w) > len(best.words)):
            best = spec
    return (best, len(best.words)) if best else (None, 0)


def groups():
    """Группы команд в порядке таблицы 7."""
    seen = []
    for spec in _TABLE:
        if spec.group not in seen:
            seen.append(spec.group)
    return seen


def by_group(group):
    """Команды группы в порядке таблицы 7."""
    return [s for s in _TABLE if s.group == group]


def help_text(group=None):
    """Без группы — список групп; с группой — синтаксис её команд; неизвестная группа — None."""
    if group is None:
        return "\n".join("%-10s %s" % (g, GROUP_TITLES[g]) for g in groups())
    specs = by_group(group)
    if not specs:
        return None
    return "\n".join("%-22s %s" % (s.name, s.help) for s in specs)
