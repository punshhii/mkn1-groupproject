"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  тестовый стенд (tests/stand)
Модуль:      mock_core
Назначение:  заглушки подсистем, к которым обращаются ПС-3 CLI и ПС-4 web:
             ПС-5 authd, ПС-2 logd, ПС-6 integrityd, ПС-1 filter. Работают на
             том же кодеке (fwcommon.protocol.serve), что и боевые подсистемы.
             Контракты: authd — authd/README.md (ветка authd/stubs); filter —
             filter/src/control.c (ветка filtration), rule.replace — по ТЗ
             (путь к подготовленному policy.json); logd — logd/fw_logd/query.py;
             integrityd — integrityd/README.md. События, которые порождают
             заглушки и которые присылают клиенты (log.write.event), попадают
             в общий журнал заглушки и доступны через log.query.events.
             Заглушка для стенда: не для продуктивной эксплуатации.
Методы:
- reset_state — исходное состояние всех заглушек (для тестов)
- advance_clock — сдвинуть часы заглушки (проверка таймаутов и блокировок)
- set_broken — пометить контролируемый файл повреждённым (аварийный режим)
- events — события, накопленные заглушкой
- build_handlers — таблица обработчиков подсистемы: cmd -> handler
- with_delay — обработчик подсистемы с искусственной задержкой ответа
- start — поднять серверы подсистем в каталоге сокетов
- main — разбор аргументов командной строки
Запуск:  python3 tests/stand/mock_core.py /tmp/fw [--only authd,logd] [--delay СЕК]
         (сокеты /tmp/fw/authd.sock, logd.sock, integrityd.sock, filter.sock)
"""
import argparse
import copy
import json
import os
import re
import secrets
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))

from fwcommon import codes, protocol  # noqa: E402

SUBSYSTEMS = ("authd", "logd", "integrityd", "filter")

SESSION_TIMEOUT_SEC = 900   # FR-35: 15 минут бездействия
LOGIN_MAX_ATTEMPTS = 5      # FR-31
LOGIN_BLOCK_SEC = 60        # FR-31
BUILTIN_ADMIN = "admin"     # FR-33

# Пароли заглушки удовлетворяют FR-36 (не менее 8 символов)
_USERS = {"admin": ("admin123", "rw"), "viewer": ("viewer123", "ro")}

# Команды, не изменяющие состояние (для auth.check); остальные требуют роль rw
READ_ONLY_CMDS = {
    "rule.get", "rule.list", "rule.show", "state.status", "state.list", "stats.get",
    "log.query.events", "log.query.packets", "user.list", "session.list",
    "integrity.status", "config.show", "if.list", "if.show", "route.list",
    "time.show", "sys.info", "subsystem.list",
}

_ID_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

_lock = threading.RLock()
_state = {}


def _initial_state():
    return {
        "clock_offset": 0.0,
        "users": {u: {"password": p, "role": r} for u, (p, r) in _USERS.items()},
        "sessions": {},          # session_id -> {username, role, source, last, downgraded}
        "fails": {},             # id -> {"count": N, "locked_until": t}
        "events": [
            {"ts": "2026-10-20 09:00:00", "code": "E01", "actor": "admin", "src": "authd"},
            {"ts": "2026-10-20 09:05:12", "code": "E20", "actor": "admin", "src": "cli"},
            {"ts": "2026-10-20 09:07:40", "code": "E03", "actor": "viewer", "src": "authd"},
        ],
        "packets": [
            {"ts": "2026-10-20 10:00:00", "action": "accept", "in_iface": "eth0",
             "out_ifaces": ["eth1"], "rule_id": 1, "conn_id": 1, "protos": "Ethernet/IPv4/TCP",
             "smac": "AA:BB:CC:DD:EE:01", "dmac": "AA:BB:CC:DD:EE:02",
             "src_ip": "192.168.1.10", "dst_ip": "192.168.2.10", "sport": 40000, "dport": 80},
            {"ts": "2026-10-20 10:00:05", "action": "drop", "in_iface": "eth1",
             "out_ifaces": [], "rule_id": 0, "conn_id": 0, "protos": "Ethernet/IPv4/ICMP",
             "smac": "AA:BB:CC:DD:EE:02", "dmac": "AA:BB:CC:DD:EE:01",
             "src_ip": "192.168.2.10", "dst_ip": "192.168.1.10", "icmp_type": 8, "icmp_code": 0},
        ],
        "rules": [               # как rule.get ПС-1, с полем hits
            {"id": 1, "active": True, "action": "accept", "in_iface": 0, "out_ifaces": [1],
             "proto": "tcp", "dport": 80, "conntrack": True, "log": True, "hits": 7},
            {"id": 2, "active": True, "action": "accept", "in_iface": 0, "out_ifaces": [1],
             "proto": "udp", "dport": 53, "conntrack": True, "log": False, "hits": 3},
        ],
        "last_policy_path": None,
        "ct_enabled": True,
        "ct_entries": [
            {"conn_id": 1, "proto": "tcp", "src_ip": "192.168.1.10", "dst_ip": "192.168.2.10",
             "sport": 40000, "dport": 80, "state": "ESTABLISHED", "in_iface": 0,
             "out_ifaces": [1], "rule_id": 1, "expires_in_sec": 3540},
            {"conn_id": 2, "proto": "udp", "src_ip": "192.168.1.11", "dst_ip": "8.8.8.8",
             "sport": 53000, "dport": 53, "state": "UDP_REPLIED", "in_iface": 0,
             "out_ifaces": [1], "rule_id": 2, "expires_in_sec": 42},
        ],
        "integrity": {
            "mode": "normal",
            "last_check_ts": "2026-10-20 09:00:00",
            "files": {"/etc/fw/config.json": "ok", "/etc/fw/policy.json": "ok",
                      "/etc/fw/accounts.json": "ok", "/usr/lib/fw/bin/fw-filter": "ok"},
        },
    }


def reset_state():
    """Исходное состояние всех заглушек."""
    with _lock:
        _state.clear()
        _state.update(_initial_state())


def advance_clock(sec):
    """Сдвинуть часы заглушки вперёд на sec секунд."""
    with _lock:
        _state["clock_offset"] += sec


def set_broken(path):
    """Пометить контролируемый файл повреждённым: ПС-6 переходит в аварийный режим (E40)."""
    with _lock:
        _state["integrity"]["files"][path] = "mismatch"
        _state["integrity"]["mode"] = "emergency"
        _emit("integrityd", "E40", file=path)


def events(code=None):
    """События, накопленные заглушкой (по желанию — только с кодом code)."""
    with _lock:
        return [e for e in _state["events"] if code is None or e["code"] == code]


def _now():
    return time.monotonic() + _state["clock_offset"]


def _wall():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _emit(src, code, **details):
    """Записать событие в журнал заглушки (как log.write.event в ПС-2)."""
    rec = {"ts": _wall(), "code": code, "src": src}
    rec.update(details)
    _state["events"].append(rec)


def _m(code, **kw):
    return codes.message_text(code, **kw) if kw else codes.message_text(code)


def _err(code, payload=None, **kw):
    return ("error", payload or {}, code, _m(code, **kw))


def _ok(payload=None):
    return ("ok", payload or {}, None, None)


def _bad(field, allowed):
    return _err("M06", field=field, allowed=allowed)


# --------------------------------------------------------------------------
# ПС-5 authd
# --------------------------------------------------------------------------

def _session(p):
    """Сеанс по session_id; (session, None) или (None, ответ M15)."""
    sid = p.get("session_id")
    s = _state["sessions"].get(sid) if isinstance(sid, str) else None
    if s is None:
        return None, _err("M15", reason="сеанс не найден")
    if _now() - s["last"] > SESSION_TIMEOUT_SEC:
        del _state["sessions"][sid]
        _emit("authd", "E07", actor=s["username"], reason="бездействие")
        return None, _err("M15", reason="бездействие более 15 минут")
    return s, None


def _need(msg, rw):
    """Проверить сеанс и, если rw, роль «чтение/запись»; иначе M15 / M03 (E50)."""
    s, e = _session(msg["payload"])
    if e:
        return None, e
    if rw and s["role"] != "rw":
        _emit("authd", "E50", actor=s["username"], cmd=msg["cmd"])
        return None, _err("M03")
    return s, None


def _h_auth_login(msg):
    p = msg["payload"]
    uid, pwd = p.get("id"), p.get("password")
    if not isinstance(uid, str) or not isinstance(pwd, str):
        return _err("M02")
    with _lock:
        f = _state["fails"].setdefault(uid, {"count": 0, "locked_until": 0.0})
        if f["locked_until"] > _now():
            return _err("M12")
        user = _state["users"].get(uid)
        if user is None or user["password"] != pwd:
            f["count"] += 1
            _emit("authd", "E03", actor=uid)
            if f["count"] >= LOGIN_MAX_ATTEMPTS:
                f["count"] = 0
                f["locked_until"] = _now() + LOGIN_BLOCK_SEC
                _emit("authd", "E06", actor=uid)
                return _err("M12")
            return _err("M02")
        f["count"] = 0
        role, downgraded = user["role"], False
        if role == "rw" and any(s["role"] == "rw" for s in _state["sessions"].values()):
            role, downgraded = "ro", True  # FR-34
            _emit("authd", "E04", actor=uid)
        sid = secrets.token_hex(16)
        _state["sessions"][sid] = {"username": uid, "role": role, "last": _now(),
                                   "source": p.get("source", msg["src"]),
                                   "downgraded": downgraded}
        _emit("authd", "E01", actor=uid, source=p.get("source", msg["src"]))
    out = {"session_id": sid, "username": uid, "role": role, "downgraded": downgraded}
    if downgraded:
        out.update(warning="M04", warning_message=_m("M04"))
    return _ok(out)


def _h_auth_logout(msg):
    with _lock:
        s, e = _session(msg["payload"])
        if e:
            return e
        del _state["sessions"][msg["payload"]["session_id"]]
        _emit("authd", "E02", actor=s["username"])
    return _ok({"status": "logged_out"})


def _h_auth_ping(msg):
    with _lock:
        s, e = _session(msg["payload"])
        if e:
            return e
        s["last"] = _now()
    return _ok({"status": "pong"})


def _h_auth_check(msg):
    with _lock:
        s, e = _session(msg["payload"])
        if e:
            return e
        cmd = msg["payload"].get("cmd")
        if s["role"] != "rw" and cmd not in READ_ONLY_CMDS:
            _emit("authd", "E50", actor=s["username"], cmd=cmd)
            return _err("M03", {"allowed": False})
    return _ok({"allowed": True})


def _h_user_list(msg):
    with _lock:
        _, e = _need(msg, rw=False)
        if e:
            return e
        users = [{"id": u, "role": v["role"]} for u, v in sorted(_state["users"].items())]
    return _ok({"users": users})


def _check_password(pwd):
    if not isinstance(pwd, str) or not 8 <= len(pwd) <= 128:
        return _bad("password", "не менее 8 символов")
    return None


def _h_user_add(msg):
    p = msg["payload"]
    with _lock:
        s, e = _need(msg, rw=True)
        if e:
            return e
        uid = p.get("id")
        if not isinstance(uid, str) or not _ID_RE.match(uid):
            return _bad("id", "от 3 до 32 символов: латиница, цифры, «_»")
        if uid in _state["users"]:
            return _bad("id", "уникальный идентификатор")
        e = _check_password(p.get("password"))
        if e:
            return e
        if p.get("role") not in ("rw", "ro"):
            return _bad("role", "rw, ro")
        _state["users"][uid] = {"password": p["password"], "role": p["role"]}
        _emit("authd", "E32", actor=s["username"], target=uid, op="add")
    return _ok()


def _h_user_edit(msg):
    p = msg["payload"]
    with _lock:
        s, e = _need(msg, rw=True)
        if e:
            return e
        uid = p.get("id")
        user = _state["users"].get(uid)
        if user is None:
            return _bad("id", "существующий идентификатор")
        role, pwd = p.get("role"), p.get("password")
        if role is not None:
            if role not in ("rw", "ro"):
                return _bad("role", "rw, ro")
            if uid == BUILTIN_ADMIN and role != "rw":
                return _err("M05")
        if pwd is not None:
            e = _check_password(pwd)
            if e:
                return e
        if role is not None:
            user["role"] = role
        if pwd is not None:
            user["password"] = pwd
        _emit("authd", "E32", actor=s["username"], target=uid, op="edit")
    return _ok()


def _h_user_delete(msg):
    with _lock:
        s, e = _need(msg, rw=True)
        if e:
            return e
        uid = msg["payload"].get("id")
        if uid == BUILTIN_ADMIN:
            return _err("M05")
        if uid not in _state["users"]:
            return _bad("id", "существующий идентификатор")
        del _state["users"][uid]
        for sid in [k for k, v in _state["sessions"].items() if v["username"] == uid]:
            del _state["sessions"][sid]
            _emit("authd", "E07", actor=uid, reason="учётная запись удалена")
        _emit("authd", "E32", actor=s["username"], target=uid, op="delete")
    return _ok()


def _h_session_list(msg):
    with _lock:
        s, e = _need(msg, rw=False)
        if e:
            return e
        now = _now()
        # Полный session_id видит только rw (нужен для session.kill); для ro он
        # маскируется, иначе ro мог бы подставить чужой rw-сеанс (как в authd)
        show = (lambda sid: sid) if s["role"] == "rw" else (lambda sid: sid[:8] + "…")
        items = [{"session_id": show(sid), "username": v["username"], "role": v["role"],
                  "source": v["source"], "idle_sec": int(now - v["last"]),
                  "downgraded": v["downgraded"]}
                 for sid, v in _state["sessions"].items()]
    return _ok({"sessions": items})


def _h_session_kill(msg):
    with _lock:
        s, e = _need(msg, rw=True)
        if e:
            return e
        target = msg["payload"].get("target_session_id")
        victim = _state["sessions"].pop(target, None) if isinstance(target, str) else None
        if victim is None:
            return _err("M13")
        _emit("authd", "E05", actor=s["username"], target=victim["username"])
    return _ok({"killed": target})


# --------------------------------------------------------------------------
# ПС-2 logd
# --------------------------------------------------------------------------

def _h_log_write_event(msg):
    p = msg["payload"]
    with _lock:
        rec = {"ts": _wall(), "src": msg["src"]}
        rec.update({k: v for k, v in p.items() if k != "ts"})
        rec.setdefault("code", None)
        _state["events"].append(rec)
    return _ok()


def _page(p):
    page, size = p.get("page", 1), p.get("page_size", 20)
    if not isinstance(page, int) or isinstance(page, bool) or page < 1:
        return None, _bad("page", "целое число не меньше 1")
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 1000:
        return None, _bad("page_size", "от 1 до 1000")
    return (page, size), None


def _interval(p):
    """Проверка from_ts / to_ts в формате «ГГГГ-ММ-ДД чч:мм:сс»; начало не позже конца."""
    for k in ("from_ts", "to_ts"):
        v = p.get(k)
        if v is not None and (not isinstance(v, str) or not _TS_RE.match(v)):
            return _bad(k, "ГГГГ-ММ-ДД чч:мм:сс")
    if p.get("from_ts") and p.get("to_ts") and p["from_ts"] > p["to_ts"]:
        return _bad("from_ts", "начало интервала не позже конца")
    return None


def _in_interval(ts, p):
    return (not p.get("from_ts") or ts >= p["from_ts"]) and (not p.get("to_ts") or ts <= p["to_ts"])


def _paged(items, page, size):
    """От новых к старым; пустая выборка — items=[] (клиент выводит M13)."""
    # при равном времени более позднее по порядку записи — новее
    items = [r for _, r in sorted(enumerate(items), key=lambda x: (x[1]["ts"], x[0]),
                                  reverse=True)]
    return _ok({"items": items[(page - 1) * size: page * size], "total": len(items)})


def _h_log_query_events(msg):
    p = msg["payload"]
    pg, e = _page(p)
    if e:
        return e
    e = _interval(p)
    if e:
        return e
    with _lock:
        items = [dict(r) for r in _state["events"]
                 if (not p.get("event_code") or r.get("code") == p["event_code"])
                 and _in_interval(r["ts"], p)]
    return _paged(items, *pg)


_PACKET_KEYS = ("action", "in_iface", "rule_id", "smac", "dmac",
                "src_ip", "dst_ip", "sport", "dport")


def _h_log_query_packets(msg):
    p = msg["payload"]
    pg, e = _page(p)
    if e:
        return e
    e = _interval(p)
    if e:
        return e
    if p.get("action") not in (None, "accept", "drop"):
        return _bad("action", "accept, drop")
    with _lock:
        items = [dict(r) for r in _state["packets"]
                 if all(p.get(k) is None or r.get(k) == p[k] for k in _PACKET_KEYS)
                 and (p.get("out_iface") is None or p["out_iface"] in r["out_ifaces"])
                 and _in_interval(r["ts"], p)]
    return _paged(items, *pg)


def _h_log_packets_clear(msg):
    with _lock:
        n = len(_state["packets"])
        _state["packets"].clear()
    return _ok({"deleted": n})


def _h_log_flush(msg):
    return _ok({"flushed": True})


# --------------------------------------------------------------------------
# ПС-6 integrityd
# --------------------------------------------------------------------------

def _integrity_view():
    st = _state["integrity"]
    return {"mode": st["mode"], "last_check_ts": st["last_check_ts"],
            "files": [{"path": k, "status": v} for k, v in sorted(st["files"].items())]}


def _h_integrity_status(msg):
    with _lock:
        return _ok(_integrity_view())


def _h_integrity_check(msg):
    with _lock:
        st = _state["integrity"]
        st["last_check_ts"] = _wall()
        broken = [k for k, v in st["files"].items() if v != "ok"]
        _emit("integrityd", "E42", result="нарушена" if broken else "успешно")
        return _ok(_integrity_view())


def _h_integrity_restore(msg):
    f = msg["payload"].get("file")
    with _lock:
        files = _state["integrity"]["files"]
        if f != "all" and f not in files:
            return _bad("file", "контролируемый файл или all")
        for k in (files if f == "all" else [f]):
            files[k] = "ok"
        if all(v == "ok" for v in files.values()) and _state["integrity"]["mode"] != "normal":
            _state["integrity"]["mode"] = "normal"
            _emit("integrityd", "E41")
        return _ok(_integrity_view())


def _h_integrity_update_baseline(msg):
    return _ok({"updated": True})


# --------------------------------------------------------------------------
# ПС-1 filter
# --------------------------------------------------------------------------

def _rule_error(r, ids):
    """Проверка правила из policy.json (FR-13); None — правило корректно."""
    rid = r.get("id") if isinstance(r, dict) else None
    if not isinstance(rid, int) or isinstance(rid, bool) or not 1 <= rid <= 65535:
        return _bad("id", "целое число 1–65535")
    if r.get("action") not in ("accept", "goto", "drop"):
        return _bad("action", "accept, goto, drop")
    if r["action"] == "accept":
        out = r.get("out_ifaces")
        if not isinstance(out, list) or not out:
            return _bad("out", "список интерфейсов, обязателен при action=accept")
        if r.get("in_iface", -1) in out:
            return _bad("out", "не включает входной интерфейс")
    if r["action"] == "goto":
        to = r.get("to_rule")
        if not isinstance(to, int) or to <= rid or to not in ids:
            return _bad("to", "номер существующего правила, больший номера текущего")
    return None


def _h_rule_replace(msg):
    path = msg["payload"].get("path")
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 255:
        return _bad("path", "абсолютный путь к подготовленному policy.json")
    try:
        with open(path, encoding="utf-8") as fh:
            rules = json.load(fh)["rules"]
        if not isinstance(rules, list):
            raise ValueError("rules")
    except (OSError, ValueError, KeyError, TypeError):
        return _bad("path", "читаемый JSON-файл политики с массивом rules")
    ids = [r.get("id") for r in rules if isinstance(r, dict)]
    for r in rules:
        e = _rule_error(r, ids)
        if e:
            return e
    seen = set()
    for rid in ids:
        if rid in seen:
            return _err("M07", n=rid)
        seen.add(rid)
    with _lock:
        old = {r["id"]: r for r in _state["rules"]}
        new_rules, changed = [], set(old) - set(ids)
        for r in sorted(rules, key=lambda x: x["id"]):
            r = copy.deepcopy(r)
            r.pop("hits", None)
            prev = old.get(r["id"])
            same = prev is not None and {k: v for k, v in prev.items() if k != "hits"} == r
            if prev is not None and (not same or not r.get("active", True)):
                changed.add(r["id"])  # изменённое или отключённое правило (новые не считаются)
            r["hits"] = prev["hits"] if same else 0  # счётчики неизменённых правил сохраняются
            new_rules.append(r)
        _state["rules"] = new_rules  # атомарная подмена таблицы (FR-10)
        _state["last_policy_path"] = path
        before = len(_state["ct_entries"])
        _state["ct_entries"] = [c for c in _state["ct_entries"] if c["rule_id"] not in changed]
        purged = before - len(_state["ct_entries"])  # FR-23
    return _ok({"rule_count": len(new_rules), "purged_sessions": purged})


def _h_rule_get(msg):
    with _lock:
        return _ok({"rules": copy.deepcopy(_state["rules"])})


def _h_state_enable(msg):
    with _lock:
        _state["ct_enabled"] = True
        _emit("filter", "E14")
    return _ok({"enabled": True})


def _h_state_disable(msg):
    with _lock:
        _state["ct_enabled"] = False
        _state["ct_entries"].clear()  # FR-20
        _emit("filter", "E15")
    return _ok({"enabled": False})


def _h_state_status(msg):
    with _lock:
        return _ok({"enabled": _state["ct_enabled"], "active_sessions": len(_state["ct_entries"]),
                    "max_sessions": 65536, "arp_forwarding": False,
                    "emergency_mode": _state["integrity"]["mode"] == "emergency",
                    "tcp_syn_timeout_sec": 5, "tcp_est_timeout_sec": 3600,
                    "tcp_fin_timeout_sec": 30, "udp_timeout_no_reply": 15,
                    "udp_timeout_reply": 60, "icmp_timeout_sec": 5})


def _h_state_list(msg):
    with _lock:
        return _ok({"entries": copy.deepcopy(_state["ct_entries"])})


def _h_state_delete(msg):
    cid = msg["payload"].get("conn_id")
    with _lock:
        left = [c for c in _state["ct_entries"] if c["conn_id"] != cid]
        if len(left) == len(_state["ct_entries"]):
            return _err("M13")
        _state["ct_entries"] = left
    return _ok({"deleted": True, "conn_id": cid})


def _h_state_delete_all(msg):
    with _lock:
        n = len(_state["ct_entries"])
        _state["ct_entries"].clear()
    return _ok({"deleted": n})


def _h_stats_get(msg):
    with _lock:
        return _ok({"rx_packets": 1000, "tx_packets": 900, "drop_packets": 100,
                    "active_rules": len(_state["rules"]),
                    "active_sessions": len(_state["ct_entries"]), "pktlog_dropped": 0})


_HANDLERS = {
    "authd": {
        "auth.login": _h_auth_login, "auth.logout": _h_auth_logout,
        "auth.ping": _h_auth_ping, "auth.check": _h_auth_check,
        "user.list": _h_user_list, "user.add": _h_user_add,
        "user.edit": _h_user_edit, "user.delete": _h_user_delete,
        "session.list": _h_session_list, "session.kill": _h_session_kill,
    },
    "logd": {
        "log.write.event": _h_log_write_event, "log.query.events": _h_log_query_events,
        "log.query.packets": _h_log_query_packets, "log.packets.clear": _h_log_packets_clear,
        "log.flush": _h_log_flush,
    },
    "integrityd": {
        "integrity.status": _h_integrity_status, "integrity.check": _h_integrity_check,
        "integrity.restore": _h_integrity_restore,
        "integrity.update_baseline": _h_integrity_update_baseline,
    },
    "filter": {
        "rule.replace": _h_rule_replace, "rule.get": _h_rule_get,
        "state.enable": _h_state_enable, "state.disable": _h_state_disable,
        "state.status": _h_state_status, "state.list": _h_state_list,
        "state.delete": _h_state_delete, "state.delete_all": _h_state_delete_all,
        "stats.get": _h_stats_get,
    },
}


def build_handlers(name):
    """Таблица обработчиков подсистемы name: cmd -> handler(msg) -> 4-кортеж."""
    return dict(_HANDLERS[name])


def with_delay(handlers, delay=0.0):
    """Один обработчик для serve(): задержка ответа (проверка M16), M14 на неизвестную команду."""
    def handler(msg):
        if delay > 0:
            time.sleep(delay)
        h = handlers.get(msg.get("cmd"))
        if h is None:
            return _err("M14")
        return h(msg)
    return handler


def start(run_dir, names=SUBSYSTEMS, delay=0.0):
    """Поднять серверы подсистем names в каталоге run_dir; вернуть {name: srv}."""
    servers = {}
    for name in names:
        srv = protocol.serve(os.path.join(run_dir, name + ".sock"), name,
                             with_delay(build_handlers(name), delay))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers[name] = srv
    return servers


def main():
    ap = argparse.ArgumentParser(description="заглушки подсистем ПО МЭ для стенда ПС-3/ПС-4")
    ap.add_argument("run_dir", help="каталог сокетов, например /tmp/fw (на стенде /run/fw)")
    ap.add_argument("--only", default=",".join(SUBSYSTEMS),
                    help="подсистемы через запятую (без filter — чтобы запустить настоящий fw-filter)")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="задержка ответа, секунд (проверка тайм-аута и M16)")
    args = ap.parse_args()
    names = [n for n in args.only.split(",") if n]
    unknown = set(names) - set(SUBSYSTEMS)
    if unknown:
        ap.error("неизвестные подсистемы: %s" % ", ".join(sorted(unknown)))
    reset_state()

    def _stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _stop)  # kill — тоже штатная остановка с удалением сокетов
    servers = start(args.run_dir, names, args.delay)
    sys.stderr.write("mock_core: %s в %s, Ctrl+C — выход\n" % (", ".join(names), args.run_dir))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for name, srv in servers.items():
            srv.shutdown()
            srv.server_close()
            path = os.path.join(args.run_dir, name + ".sock")
            if os.path.exists(path):
                os.unlink(path)


reset_state()

if __name__ == "__main__":
    main()
