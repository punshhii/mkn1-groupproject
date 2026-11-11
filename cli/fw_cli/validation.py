"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      validation
Назначение:  проверка данных администратора строго по common/validation.json
             (таблицы 2 и 3, FR-13, FR-36, FR-39): поля правила, параметры
             конфигурации, учётные записи, критерии выборки журналов, аргументы
             системных команд. Ошибка — ValidationError с кодом M06 и текстом из
             common/messages.json. Преобразование правила в формат policy.json
             ПС-1 и обратно.
Методы:
  - ValidationError — ошибка проверки (code, field, allowed, message)
  - load_spec — описание правил проверки из common/validation.json
  - parse_ipv4 — IPv4-адрес -> int (None, если адрес неверный)
  - check_int, check_mac, check_ipv4_expr, check_port_expr, check_datetime,
    check_cidr, check_ipv4_addr — проверка отдельных значений
  - validate_rule — поля правила -> нормализованное правило с умолчаниями
  - rule_to_filter — правило -> запись policy.json ПС-1
  - rule_from_filter — запись policy.json ПС-1 -> правило
  - validate_config — значение параметра конфигурации
  - validate_account — идентификатор, пароль и роль учётной записи
  - validate_event_filter, validate_packet_filter — критерии выборки -> payload ПС-2
  - check_command — проверить все аргументы разобранной команды до выполнения
"""
import json
import os
import re
from datetime import datetime

from fwcommon import codes

_SPEC_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(codes.__file__))),
                          "validation.json")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_DEC_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_DT_FMT = "%Y-%m-%d %H:%M:%S"
_DT_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
PROTO_NUM = {"icmp": 1, "tcp": 6, "udp": 17}

_spec = None


class ValidationError(Exception):
    """Некорректное значение: M06 «неверное значение поля «field». Допустимые значения: allowed»."""

    def __init__(self, field, allowed, code="M06"):
        self.code = code
        self.field = field
        self.allowed = allowed
        self.message = codes.message_text(code, field=field, allowed=allowed)
        super().__init__(self.message)


def load_spec(path=None):
    """Описание правил проверки (кэшируется для пути по умолчанию)."""
    global _spec
    if path is not None:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    if _spec is None:
        with open(_SPEC_PATH, encoding="utf-8") as fh:
            _spec = json.load(fh)
    return _spec


# --------------------------------------------------------------------------
# Отдельные значения
# --------------------------------------------------------------------------

def check_int(value, field, lo, hi):
    """Десятичное целое lo..hi без знака и ведущих нулей."""
    if isinstance(value, int) and not isinstance(value, bool):
        n = value
    elif isinstance(value, str) and _DEC_RE.match(value):
        n = int(value)
    else:
        raise ValidationError(field, "целое число %d–%d" % (lo, hi))
    if not lo <= n <= hi:
        raise ValidationError(field, "целое число %d–%d" % (lo, hi))
    return n


def parse_ipv4(s):
    """«a.b.c.d» -> int; None, если строка не адрес (без ведущих нулей, 0–255)."""
    if not isinstance(s, str):
        return None
    parts = s.split(".")
    if len(parts) != 4 or not all(_DEC_RE.match(p) and int(p) <= 255 for p in parts):
        return None
    n = 0
    for p in parts:
        n = (n << 8) | int(p)
    return n


def check_ipv4_addr(value, field):
    if parse_ipv4(value) is None:
        raise ValidationError(field, "IPv4-адрес, например 192.168.1.10")
    return value


def check_cidr(value, field):
    """«a.b.c.d/len», len 0–32."""
    addr, sep, length = (value or "").partition("/")
    if not sep or parse_ipv4(addr) is None or not _DEC_RE.match(length) or int(length) > 32:
        raise ValidationError(field, "адрес с маской, например 192.168.1.0/24")
    return value


def check_mac(value, field, allow_any=True):
    if allow_any and value == "any":
        return "any"
    if not isinstance(value, str) or not _MAC_RE.match(value):
        raise ValidationError(field, "XX:XX:XX:XX:XX:XX" + (" или any" if allow_any else ""))
    return value.upper()


def check_ipv4_expr(value, field, allow_any=True):
    """Адрес, адрес с маской (0–32) или диапазон «a-b» с a <= b; any."""
    allowed = "адрес, адрес/маска (0–32), диапазон адрес-адрес" + (" или any" if allow_any else "")
    if allow_any and value == "any":
        return "any"
    if not isinstance(value, str):
        raise ValidationError(field, allowed)
    if "/" in value:
        try:
            return check_cidr(value, field)
        except ValidationError:
            raise ValidationError(field, allowed)
    if "-" in value:
        a, _, b = value.partition("-")
        ia, ib = parse_ipv4(a), parse_ipv4(b)
        if ia is None or ib is None or ia > ib:
            raise ValidationError(field, allowed)
        return value
    if parse_ipv4(value) is None:
        raise ValidationError(field, allowed)
    return value


def check_port_expr(value, field, lo=1, hi=65535, allow_any=True):
    """Порт lo..hi или диапазон «a-b» с a <= b; any."""
    allowed = "порт %d–%d или диапазон, например 1024-2000" % (lo, hi)
    if allow_any and value == "any":
        return "any"
    if not isinstance(value, str):
        raise ValidationError(field, allowed)
    a, sep, b = value.partition("-")
    try:
        pa = check_int(a, field, lo, hi)
        pb = check_int(b, field, lo, hi) if sep else pa
    except ValidationError:
        raise ValidationError(field, allowed)
    if pa > pb:
        raise ValidationError(field, allowed)
    return value


def check_datetime(value, field):
    """«ГГГГ-ММ-ДД чч:мм:сс» с существующей датой."""
    if not isinstance(value, str) or not _DT_RE.match(value):
        raise ValidationError(field, "ГГГГ-ММ-ДД чч:мм:сс")
    try:
        datetime.strptime(value, _DT_FMT)
    except ValueError:
        raise ValidationError(field, "ГГГГ-ММ-ДД чч:мм:сс")
    return value


# --------------------------------------------------------------------------
# Правило фильтрации (таблица 2, FR-13)
# --------------------------------------------------------------------------

def _proto_name(proto):
    """Протокол по имени или номеру -> tcp | udp | icmp | any | номер."""
    if isinstance(proto, int):
        return {v: k for k, v in PROTO_NUM.items()}.get(proto, proto)
    return proto


def _check_field(name, value, fs, ifaces):
    """Проверить одно поле правила по его описанию fs из validation.json."""
    t = fs["type"]
    if t == "int":
        if value == "any" and fs.get("default") == "any":
            return "any"
        return check_int(value, name, fs["min"], fs["max"])
    if t == "enum":
        if value not in fs["values"]:
            raise ValidationError(name, ", ".join(fs["values"]))
        return value
    if t == "enum_or_int":
        if value in fs["values"]:
            return value
        try:
            return _proto_name(check_int(value, name, fs["int_min"], fs["int_max"]))
        except ValidationError:
            raise ValidationError(name, "%s или номер %d–%d" % (
                ", ".join(fs["values"]), fs["int_min"], fs["int_max"]))
    if t == "iface_or_any":
        if value != "any" and value not in ifaces:
            raise ValidationError(name, ", ".join(list(ifaces) + ["any"]))
        return value
    if t == "mac_or_any":
        return check_mac(value, name)
    if t == "ipv4_expr":
        return check_ipv4_expr(value, name)
    if t == "port_expr":
        return check_port_expr(value, name, fs["min"], fs["max"])
    if t == "iface_list":
        items = value.split(",") if isinstance(value, str) else []
        if not items or any(i not in ifaces for i in items) or len(set(items)) != len(items):
            raise ValidationError(name, "интерфейсы через запятую без пробелов: " + ", ".join(ifaces))
        return items
    if t == "rule_ref":
        return check_int(value, name, 1, 65535)
    if t == "string":
        if not isinstance(value, str) or len(value) > fs["max_len"]:
            raise ValidationError(name, "строка до %d символов" % fs["max_len"])
        return value
    raise ValueError("validation.json: неизвестный тип %s" % t)  # ошибка описания, не ввода


def _defaults(spec):
    return {k: fs["default"] for k, fs in spec.items() if "default" in fs and k != "id"}


def validate_rule(rule_id, fields, ifaces, existing_ids=(), base=None):
    """Проверить правило (rule add / rule edit) и вернуть его с умолчаниями.

    rule_id — номер N (строка или int); fields — именованные аргументы
    (имя -> строка); ifaces — имена интерфейсов из конфигурации; existing_ids —
    номера правил политики (для перехода to); base — текущее правило при
    rule edit (поля fields накладываются на него). Ошибка — ValidationError (M06).
    Уникальность и существование номера (M07) проверяет вызывающий.
    """
    spec = load_spec()["rule"]
    rid = check_int(rule_id, "N", spec["id"]["min"], spec["id"]["max"])
    rule = dict(base) if base else _defaults(spec)
    for name, raw in fields.items():
        if name not in spec or name == "id":
            raise ValidationError(name, ", ".join(k for k in spec if k != "id"))
        rule[name] = _check_field(name, raw, spec[name], ifaces)
    rule["id"] = rid
    if "action" not in rule:
        raise ValidationError("action", ", ".join(spec["action"]["values"]))

    proto = rule.get("proto", "any")
    for name in ("sport", "dport", "icmp-type", "icmp-code", "state"):
        only = spec[name].get("only_if")
        if not only or rule.get(name, spec[name].get("default")) == spec[name].get("default"):
            continue
        key, allowed = next(iter(only.items()))
        actual = proto if key == "proto" else rule.get(key)
        if actual in allowed:
            continue
        if name in fields:
            raise ValidationError(name, "только при %s=%s" % (key, " или ".join(allowed)))
        rule[name] = spec[name]["default"]  # унаследовано при rule edit — сбросить

    # out и to имеют смысл только при своём действии: заданные явно — ошибка,
    # унаследованные при rule edit от прежнего действия — сбрасываются
    action = rule["action"]
    if action == "accept":
        if not rule.get("out"):
            raise ValidationError("out", "список интерфейсов, обязателен при action=accept")
        if rule.get("in", "any") in rule["out"]:
            raise ValidationError("out", "не включает входной интерфейс")
    elif "out" in fields:
        raise ValidationError("out", "только при action=accept")
    else:
        rule.pop("out", None)
    if action == "goto":
        to = rule.get("to")
        if to is None or to <= rid or to not in set(existing_ids):
            raise ValidationError("to", "номер существующего правила, больший номера текущего")
    elif "to" in fields:
        raise ValidationError("to", "только при action=goto")
    else:
        rule.pop("to", None)
    return rule


def _port_to_filter(v):
    a, sep, b = v.partition("-")
    return "%s-%s" % (a, b) if sep else int(a)


def rule_to_filter(rule, ifaces):
    """Правило CLI -> запись policy.json ПС-1 (поля json_parse_rule); any опускается."""
    idx = {name: i for i, name in enumerate(ifaces)}
    out = {"id": rule["id"], "active": rule.get("active", "yes") == "yes",
           "log": rule.get("log", "no") == "yes", "action": rule["action"],
           "conntrack": rule.get("state", "off") == "on"}
    if rule.get("in", "any") != "any":
        out["in_iface"] = idx[rule["in"]]
    for k in ("smac", "dmac", "src", "dst"):
        if rule.get(k, "any") != "any":
            out[k] = rule[k]
    if rule.get("proto", "any") != "any":
        out["proto"] = rule["proto"]
    if rule.get("eth-proto", "any") != "any":
        out["eth_proto"] = rule["eth-proto"]
    for k in ("sport", "dport"):
        if rule.get(k, "any") != "any":
            out[k] = _port_to_filter(rule[k])
    for k, fk in (("icmp-type", "icmp_type"), ("icmp-code", "icmp_code")):
        if rule.get(k, "any") != "any":
            out[fk] = rule[k]
    if rule.get("out"):
        out["out_ifaces"] = [idx[i] for i in rule["out"]]
    if rule.get("to") is not None:
        out["to_rule"] = rule["to"]
    if rule.get("comment"):
        out["comment"] = rule["comment"]
    return out


def rule_from_filter(rec, ifaces):
    """Запись policy.json / rule.get ПС-1 -> правило CLI (с умолчаниями таблицы 2)."""
    spec = load_spec()["rule"]
    rule = _defaults(spec)
    rule["id"] = rec["id"]
    rule["action"] = rec.get("action", "drop")
    rule["active"] = "yes" if rec.get("active", True) else "no"
    rule["log"] = "yes" if rec.get("log", False) else "no"
    rule["state"] = "on" if rec.get("conntrack", False) else "off"
    ii = rec.get("in_iface", -1)
    rule["in"] = ifaces[ii] if isinstance(ii, int) and 0 <= ii < len(ifaces) else "any"
    for k in ("smac", "dmac", "src", "dst"):
        if rec.get(k) not in (None, "", "any"):
            rule[k] = rec[k]
    if rec.get("proto") not in (None, 0, "any"):
        rule["proto"] = _proto_name(rec["proto"])
    if rec.get("eth_proto") not in (None, "any"):
        rule["eth-proto"] = rec["eth_proto"]
    for k in ("sport", "dport"):
        if rec.get(k) not in (None, 0, "any"):
            rule[k] = str(rec[k])
    for k, fk in (("icmp-type", "icmp_type"), ("icmp-code", "icmp_code")):
        if rec.get(fk) not in (None, 255):
            rule[k] = rec[fk]
    if rec.get("out_ifaces"):
        rule["out"] = [ifaces[i] for i in rec["out_ifaces"] if 0 <= i < len(ifaces)]
    if rec.get("to_rule"):
        rule["to"] = rec["to_rule"]
    if rec.get("comment"):
        rule["comment"] = rec["comment"]
    if "hits" in rec:
        rule["hits"] = rec["hits"]
    return rule


# --------------------------------------------------------------------------
# Конфигурация, учётные записи
# --------------------------------------------------------------------------

_BOOL = {"on": True, "yes": True, "off": False, "no": False}


def validate_config(name, value):
    """Значение параметра конфигурации (таблица 3) -> int или bool."""
    spec = load_spec()["config"]
    if name not in spec:
        raise ValidationError(name, ", ".join(spec))
    fs = spec[name]
    if fs["type"] == "bool":
        if value not in _BOOL:
            raise ValidationError(name, "on, off")
        return _BOOL[value]
    return check_int(value, name, fs["min"], fs["max"])


def validate_account(user_id=None, password=None, role=None):
    """Проверить заданные поля учётной записи (FR-36); уникальность проверяет ПС-5."""
    spec = load_spec()["account"]
    if user_id is not None:
        s = spec["id"]
        if (not isinstance(user_id, str) or not s["min_len"] <= len(user_id) <= s["max_len"]
                or not re.match(s["pattern"], user_id)):
            raise ValidationError("id", "от %d до %d символов: латиница, цифры, «_»"
                                  % (s["min_len"], s["max_len"]))
    if password is not None:
        s = spec["password"]
        if not isinstance(password, str) or not s["min_len"] <= len(password) <= s["max_len"]:
            raise ValidationError("password", "от %d до %d символов" % (s["min_len"], s["max_len"]))
    if role is not None and role not in spec["role"]["values"]:
        raise ValidationError("role", ", ".join(spec["role"]["values"]))


# --------------------------------------------------------------------------
# Критерии выборки журналов (FR-39) -> payload ПС-2
# --------------------------------------------------------------------------

def _page(named):
    return check_int(named.get("page", "1"), "page", 1, 10 ** 9)


def _interval(named, out):
    for k in ("from", "to"):
        if k in named:
            out[k + "_ts"] = check_datetime(named[k], k)
    if "from_ts" in out and "to_ts" in out and out["from_ts"] > out["to_ts"]:
        raise ValidationError("from", "начало интервала не позже конца")


def validate_event_filter(named, page_size=20):
    """code, from, to, page -> payload log.query.events."""
    out = {"page": _page(named), "page_size": page_size}
    if "code" in named:
        code = named["code"]
        if code not in codes.EVENTS:
            raise ValidationError("code", "код события E01–E50")
        out["event_code"] = code
    _interval(named, out)
    return out


def validate_packet_filter(named, ifaces, page_size=20):
    """Критерии журнала пакетов -> payload log.query.packets (pass -> accept)."""
    out = {"page": _page(named), "page_size": page_size}
    if "action" in named:
        a = named["action"]
        if a not in ("pass", "drop"):
            raise ValidationError("action", "pass, drop")
        out["action"] = "accept" if a == "pass" else "drop"
    for k, fk in (("in", "in_iface"), ("out", "out_iface")):
        if k in named:
            if named[k] not in ifaces:
                raise ValidationError(k, ", ".join(ifaces))
            out[fk] = named[k]
    if "rule" in named:
        out["rule_id"] = check_int(named["rule"], "rule", 0, 65535)  # 0 — ни одно не подошло
    for k in ("smac", "dmac"):
        if k in named:
            out[k] = check_mac(named[k], k, allow_any=False)
    for k, fk in (("src", "src_ip"), ("dst", "dst_ip")):
        if k in named:
            out[fk] = check_ipv4_expr(named[k], k, allow_any=False)
    for k in ("sport", "dport"):
        if k in named:
            v = check_port_expr(named[k], k, allow_any=False)
            out[k] = int(v) if "-" not in v else v
    _interval(named, out)
    return out


# --------------------------------------------------------------------------
# Аргументы команды целиком
# --------------------------------------------------------------------------

def _check_id(value, field, lo=1, hi=2 ** 32 - 1):
    return check_int(value, field, lo, hi)


def check_command(cmd, ifaces, rule_ids=()):
    """Проверить аргументы разобранной команды (parser.Command) до выполнения.

    Возвращает проверенные значения для ядра управления (правило, payload
    выборки, параметры конфигурации и т.п.); ошибка — ValidationError (M06).
    Существование и уникальность номера правила (M07) проверяет ядро.
    """
    n, a, named = cmd.name, cmd.args, cmd.named
    if n in ("rule show", "rule enable", "rule disable", "rule del"):
        return {"id": check_int(a["N"], "N", 1, 65535)}
    if n == "rule add":
        return validate_rule(a["N"], named, ifaces, rule_ids)
    if n == "rule edit":
        check_int(a["N"], "N", 1, 65535)
        spec = load_spec()["rule"]
        for name, raw in named.items():  # значения полей; правило целиком — с текущим в ядре
            if name not in spec or name == "id":
                raise ValidationError(name, ", ".join(k for k in spec if k != "id"))
            _check_field(name, raw, spec[name], ifaces)
        return dict(named)
    if n == "log events show":
        return validate_event_filter(named)
    if n == "log packets show":
        return validate_packet_filter(named, ifaces)
    if n == "state delete":
        return {"conn_id": _check_id(a["ID"], "ID")}
    if n == "config set":
        if not named:
            raise ValidationError("имя", ", ".join(load_spec()["config"]))
        return {k: validate_config(k, val) for k, val in named.items()}
    if n == "user add":
        if "role" not in named:
            raise ValidationError("role", ", ".join(load_spec()["account"]["role"]["values"]))
        validate_account(a["ID"], role=named["role"])
        return {"id": a["ID"], "role": named["role"]}
    if n == "user edit":
        validate_account(a["ID"], role=named.get("role"))
        if "role" not in named and "password" not in cmd.flags:
            raise ValidationError("role", "role=rw|ro и/или password")
        return {"id": a["ID"], "role": named.get("role"), "password": "password" in cmd.flags}
    if n == "user del":
        validate_account(a["ID"])
        return {"id": a["ID"]}
    if n in ("if show", "if up", "if down", "if ip"):
        if a["NAME"] not in ifaces:
            raise ValidationError("ИМЯ", ", ".join(ifaces))
        if n == "if ip":
            check_cidr(a["ADDR"], "адрес/маска")
        return dict(a)
    if n == "time set":
        return {"datetime": check_datetime(a["DATETIME"], "ДАТА ВРЕМЯ")}
    if n == "route add":
        check_cidr(a["NET"], "сеть/маска")
        check_ipv4_addr(a["GW"], "шлюз")
        return dict(a)
    if n == "route del":
        check_cidr(a["NET"], "сеть/маска")
        return dict(a)
    if n == "session kill":
        if not re.match(r"^[0-9a-f]{1,64}$", a["ID"]):
            raise ValidationError("ID", "идентификатор сеанса из session list")
        return dict(a)
    if n == "integrity restore":
        f = a["FILE"]
        if f != "all" and (not f.startswith("/") or len(f) > 255 or ".." in f.split("/")):
            raise ValidationError("ФАЙЛ", "абсолютный путь контролируемого файла или all")
        return {"file": f}
    if n == "subsystem restart":
        names = ("filter", "logd", "authd", "integrityd", "cli", "web")
        if a["NAME"] not in names:
            raise ValidationError("ИМЯ", ", ".join(names))
        return dict(a)
    return {}
