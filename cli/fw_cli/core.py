"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      core
Назначение:  ядро управления, общее для CLI и web: проверка прав и режима по
             таблице команд, проверка ввода, подтверждение, выполнение команд
             через ПС-1, ПС-2, ПС-5, ПС-6, регистрация E50 / E43 и событий
             команд. Политика доступа: рабочая таблица ПС-1 (rule.get);
             rule add/edit/enable/disable/del строят новую таблицу, пишут её во
             временный policy.json и отправляют rule.replace с путём к нему.
             Реализованы группы rule, user, session, log events, state, а также
             whoami, help, logout/exit.
Методы:
  - access_error — код отказа по роли и режиму: None, M03 или M10
  - Result — результат команды: код сообщения и/или данные для вывода
  - CommandError — отказ ядра с кодом сообщения (M07, M11, M13, ...)
  - EventQueue — отправка событий в ПС-2 с очередью до 1000 и повтором раз в 5 с
  - load_ifaces — имена интерфейсов из config.json
  - Core — ядро: login, logout, emergency, execute
"""
import collections
import json
import os
import threading
from dataclasses import dataclass, field

from fwcommon import codes, protocol

from . import commands, formatter, session, validation

EVENT_QUEUE_MAX = 1000     # PROTOCOL.md: очередь событий при недоступной ПС-2
EVENT_RETRY_SEC = 5        # PROTOCOL.md: повтор отправки каждые 5 с
CONFIG_PATHS = ("/etc/fw/config.json",)


def access_error(spec, role, emergency):
    """Отказ по таблице 7: M10 — недоступна в аварийном режиме, M03 — нужна роль rw.

    Режим проверяется первым: в аварийном режиме изменяющая команда отклоняется
    с M10 для любой роли. При M03 вызывающий регистрирует E50 (FR-37b).
    """
    if emergency and not spec.emergency:
        return "M10"
    if spec.rw and role != "rw":
        return "M03"
    return None


@dataclass
class Result:
    code: str = None                          # M09, M13, ... или None
    columns: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    text: str = None
    footer: str = None
    error: bool = False
    end_session: bool = False                 # logout / exit / M15

    def render(self):
        """Текст для вывода администратору."""
        if self.columns:
            out = formatter.table(self.columns, self.rows)
            return out + ("\n" + self.footer if self.footer and self.rows else "")
        if self.text is not None:
            return self.text
        return formatter.message(self.code) if self.code else ""


class CommandError(Exception):
    """Отказ ядра управления с кодом сообщения из common/messages.json."""

    def __init__(self, code, **kw):
        self.code = code
        self.message = codes.message_text(code, **kw) if kw else codes.message_text(code)
        super().__init__(self.message)


def _error(code, message, end=False):
    return Result(code=code, text=message, error=True, end_session=end)


class EventQueue:
    """События в ПС-2 (log.write.event). При недоступной ПС-2 — очередь до 1000
    событий (самые старые вытесняются) и повтор отправки каждые 5 с."""

    def __init__(self, path, src, retry=True):
        self.path, self.src = path, src
        self._q = collections.deque(maxlen=EVENT_QUEUE_MAX)
        self._lock = threading.Lock()
        self._timer = None
        self._retry = retry

    def __len__(self):
        return len(self._q)

    def send(self, payload):
        with self._lock:
            self._q.append(payload)
        self.flush()

    def flush(self):
        """Отправить накопленные события по порядку; при ошибке — повтор позже."""
        with self._lock:
            while self._q:
                try:
                    protocol.send_event(self.path, self.src, "logd", "log.write.event", self._q[0])
                except (OSError, ValueError):
                    self._schedule()
                    return
                self._q.popleft()

    def _schedule(self):
        if self._retry and (self._timer is None or not self._timer.is_alive()):
            self._timer = threading.Timer(EVENT_RETRY_SEC, self.flush)
            self._timer.daemon = True
            self._timer.start()


def load_ifaces(config_path=None):
    """Имена интерфейсов из config.json (порядок задаёт индексы для ПС-1)."""
    for path in ([config_path] if config_path else CONFIG_PATHS):
        try:
            with open(path, encoding="utf-8") as fh:
                return [i["name"] for i in json.load(fh).get("ifaces", []) if i.get("name")]
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return []


_RULE_COLUMNS = [("id", "N"), ("active", "Акт."), ("in", "Вход"), ("src", "Источник"),
                 ("dst", "Получатель"), ("proto", "Протокол"), ("sport", "Порт ист."),
                 ("dport", "Порт пол."), ("action", "Действие"), ("target", "Куда"),
                 ("state", "Сост."), ("log", "Журнал"), ("hits", "Сраб.")]

_STATE_LABELS = [("enabled", "Контроль состояний"), ("active_sessions", "Записей в таблице"),
                 ("max_sessions", "Размер таблицы"), ("arp_forwarding", "Пересылка ARP"),
                 ("emergency_mode", "Аварийный режим"),
                 ("tcp_syn_timeout_sec", "Таймаут TCP SYN, с"),
                 ("tcp_est_timeout_sec", "Таймаут TCP ESTABLISHED, с"),
                 ("tcp_fin_timeout_sec", "Таймаут TCP FIN, с"),
                 ("udp_timeout_no_reply", "Таймаут UDP без ответа, с"),
                 ("udp_timeout_reply", "Таймаут UDP с ответом, с"),
                 ("icmp_timeout_sec", "Таймаут ICMP, с")]


class Core:
    """Ядро управления от имени интерфейса src (cli | web)."""

    def __init__(self, run_dir="/run/fw", ifaces=None, config_path=None, src="cli",
                 page_size=20, policy_dir=None, ping_interval=session.PING_INTERVAL_SEC,
                 event_retry=True):
        self.run_dir = run_dir
        self.src = src
        self.ifaces = list(ifaces) if ifaces is not None else load_ifaces(config_path)
        self.page_size = page_size
        self.policy_dir = policy_dir or run_dir
        self.ping_interval = ping_interval
        self.events = EventQueue(self.path("logd"), src, retry=event_retry)
        self._handlers = {
            "rule list": self._rule_list, "rule show": self._rule_show,
            "rule add": self._rule_add, "rule edit": self._rule_edit,
            "rule enable": self._rule_active, "rule disable": self._rule_active,
            "rule del": self._rule_del,
            "user list": self._user_list, "user add": self._user_add,
            "user edit": self._user_edit, "user del": self._user_del,
            "session list": self._session_list, "session kill": self._session_kill,
            "log events show": self._log_events,
            "state status": self._state_status, "state table": self._state_table,
            "state enable": self._state_switch, "state disable": self._state_switch,
            "state delete": self._state_delete, "state delete all": self._state_delete_all,
            "whoami": self._whoami, "help": self._help,
            "logout": self._logout, "exit": self._logout,
        }

    # -- связь с подсистемами ------------------------------------------------

    def path(self, name):
        return os.path.join(self.run_dir, name + ".sock")

    def call(self, dst, cmd, payload=None):
        """Запрос подсистеме; ProtocolError при ошибке или отсутствии ответа (M16)."""
        return protocol.request(self.path(dst), self.src, dst, cmd, payload)["payload"]

    def event(self, code, sess, cmd_name, result="ok", **details):
        """Событие FR-25: код, администратор, IP, результат, имя команды."""
        rec = {"code": code, "actor": sess.username, "source": self.src, "ip": sess.ip,
               "result": result, "cmd": cmd_name}
        rec.update(details)
        self.events.send(rec)

    def login(self, user_id, password, ip=None):
        return session.login(self.path("authd"), user_id, password, self.src, ip)

    def emergency(self):
        """Режим аварийной поддержки по ПС-6. Нет ответа ПС-6 — считается аварийным:
        доступны только просмотр и восстановление, изменения отклоняются (M10)."""
        try:
            return self.call("integrityd", "integrity.status").get("mode") != "normal"
        except protocol.ProtocolError:
            return True

    # -- выполнение ----------------------------------------------------------

    def execute(self, cmd, sess, confirm=None, ask_password=None):
        """Выполнить разобранную команду (parser.Command) от имени сеанса sess.

        confirm() -> bool — ответ на «Подтвердите (y/n):»; ask_password(prompt)
        -> str — скрытый ввод пароля. Изменяющая команда, отклонённая по роли, —
        M03 и E50; завершённая неуспешно по иной причине — E43 (FR-32).
        """
        spec = cmd.spec
        if spec.name not in ("logout", "exit"):
            try:
                session.ping_if_due(self.path("authd"), sess, self.ping_interval)
            except protocol.ProtocolError as e:
                return _error(e.code, e.message, end=(e.code == "M15"))

        emergency = (not spec.emergency) and self.emergency()
        denied = access_error(spec, sess.role, emergency)
        if denied == "M03":
            self.event("E50", sess, spec.name, "fail", reason="M03")
            return _error("M03", codes.message_text("M03"))
        if denied:
            return _error(denied, codes.message_text(denied))

        handler = self._handlers.get(spec.name)
        if handler is None:
            return _error("M14", "Ошибка: команда «%s» пока не реализована" % spec.name)
        try:
            rules = self._load_rules() if spec.group == "rule" else None
            ids = {r["id"] for r in rules} if rules is not None else ()
            values = validation.check_command(cmd, self.ifaces, ids)
            if spec.confirm and not (confirm and confirm()):
                return Result(text="Операция отменена")
            return handler(cmd, sess, values, rules, ask_password)
        except (validation.ValidationError, CommandError, protocol.ProtocolError) as e:
            if spec.rw:
                self.event("E43", sess, spec.name, "fail", reason="%s: %s" % (e.code, e.message))
            return _error(e.code, e.message, end=(e.code == "M15"))

    # -- правила (ПС-1) --------------------------------------------------------

    def _load_rules(self):
        recs = self.call("filter", "rule.get").get("rules", [])
        return sorted((validation.rule_from_filter(r, self.ifaces) for r in recs),
                      key=lambda r: r["id"])

    def _replace(self, rules):
        """Новая таблица -> временный policy.json -> rule.replace с путём к нему."""
        data = {"rules": [validation.rule_to_filter(r, self.ifaces) for r in rules]}
        path = os.path.join(self.policy_dir, "policy.%s.%d.json" % (self.src, os.getpid()))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
            return self.call("filter", "rule.replace", {"path": os.path.abspath(path)})
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    @staticmethod
    def _find(rules, rid):
        for r in rules:
            if r["id"] == rid:
                return r
        raise CommandError("M07", n=rid)

    @staticmethod
    def _without_hits(r):
        return {k: v for k, v in r.items() if k != "hits"}

    def _rule_list(self, cmd, sess, values, rules, ask):
        rows = []
        for r in rules:
            row = dict(r)
            row["target"] = r.get("out") or ("правило %s" % r["to"] if r.get("to") else None)
            rows.append(row)
        return Result(columns=_RULE_COLUMNS, rows=rows)

    def _rule_show(self, cmd, sess, values, rules, ask):
        r = self._find(rules, values["id"])
        keys = ("id",) + commands.RULE_FIELDS + ("hits",)
        return Result(columns=[("field", "Поле"), ("value", "Значение")],
                      rows=[{"field": k, "value": r.get(k)} for k in keys if k in r])

    def _rule_add(self, cmd, sess, values, rules, ask):
        if any(r["id"] == values["id"] for r in rules):
            raise CommandError("M07", n=values["id"])
        self._replace([self._without_hits(r) for r in rules] + [values])
        self.event("E20", sess, cmd.name, rule=values["id"])
        return Result(code="M09")

    def _rule_edit(self, cmd, sess, values, rules, ask):
        rid = int(cmd.args["N"])
        base = self._without_hits(self._find(rules, rid))
        new = validation.validate_rule(rid, cmd.named, self.ifaces,
                                       {r["id"] for r in rules}, base=base)
        self._replace([new if r["id"] == rid else self._without_hits(r) for r in rules])
        self.event("E21", sess, cmd.name, rule=rid)
        return Result(code="M09")

    def _rule_active(self, cmd, sess, values, rules, ask):
        rid = values["id"]
        self._find(rules, rid)
        flag = "yes" if cmd.name == "rule enable" else "no"
        self._replace([dict(self._without_hits(r), active=flag) if r["id"] == rid
                       else self._without_hits(r) for r in rules])
        self.event("E21", sess, cmd.name, rule=rid)
        return Result(code="M09")

    def _rule_del(self, cmd, sess, values, rules, ask):
        rid = values["id"]
        self._find(rules, rid)
        refs = [r["id"] for r in rules if r.get("to") == rid]
        if refs:
            raise CommandError("M11", n=refs[0])  # FR-13: на правило есть переход
        self._replace([self._without_hits(r) for r in rules if r["id"] != rid])
        self.event("E22", sess, cmd.name, rule=rid)
        return Result(code="M09")

    # -- учётные записи и сеансы (ПС-5) --------------------------------------

    def _auth(self, sess, cmd, **payload):
        return self.call("authd", cmd, dict(payload, session_id=sess.session_id))

    def _new_password(self, ask):
        """Пароль скрытым вводом дважды; проверка FR-36. Пароль нигде не выводится."""
        if ask is None:
            raise validation.ValidationError("password", "ввод пароля недоступен")
        pwd = ask("Новый пароль: ")
        validation.validate_account(password=pwd)
        if ask("Повторите пароль: ") != pwd:
            raise validation.ValidationError("password", "одинаковый пароль при повторном вводе")
        return pwd

    def _user_list(self, cmd, sess, values, rules, ask):
        users = self._auth(sess, "user.list").get("users", [])
        return Result(columns=[("id", "Идентификатор"), ("role", "Роль")], rows=users)

    def _user_add(self, cmd, sess, values, rules, ask):
        pwd = self._new_password(ask)
        self._auth(sess, "user.add", id=values["id"], password=pwd, role=values["role"])
        return Result(code="M09")  # E32 регистрирует ПС-5

    def _user_edit(self, cmd, sess, values, rules, ask):
        payload = {"id": values["id"]}
        if values.get("role"):
            payload["role"] = values["role"]
        if values.get("password"):
            payload["password"] = self._new_password(ask)
        self._auth(sess, "user.edit", **payload)
        return Result(code="M09")

    def _user_del(self, cmd, sess, values, rules, ask):
        self._auth(sess, "user.delete", id=values["id"])
        return Result(code="M09")  # E32, E07 регистрирует ПС-5

    def _session_list(self, cmd, sess, values, rules, ask):
        items = self._auth(sess, "session.list").get("sessions", [])
        return Result(columns=[("session_id", "ID сеанса"), ("username", "Администратор"),
                               ("role", "Роль"), ("source", "Интерфейс"),
                               ("idle_sec", "Бездействие, с"), ("downgraded", "Понижен")],
                      rows=items)

    def _session_kill(self, cmd, sess, values, rules, ask):
        self._auth(sess, "session.kill", target_session_id=values["ID"])
        return Result(code="M09")  # E05 регистрирует ПС-5

    # -- журнал событий (ПС-2) -------------------------------------------------

    def _log_events(self, cmd, sess, values, rules, ask):
        values["page_size"] = self.page_size
        p = self.call("logd", "log.query.events", values)
        rows = []
        for it in p.get("items", []):
            code = it.get("code")
            rows.append(dict(it, text=codes.EVENTS.get(code, "")))
        return Result(columns=[("ts", "Время"), ("code", "Код"), ("text", "Событие"),
                               ("actor", "Инициатор"), ("ip", "IP-адрес"),
                               ("result", "Результат"), ("cmd", "Команда")],
                      rows=rows, footer=formatter.page_footer(values["page"], self.page_size,
                                                               p.get("total", len(rows))))

    # -- контроль состояний (ПС-1) ---------------------------------------------

    def _iface(self, i):
        return self.ifaces[i] if isinstance(i, int) and 0 <= i < len(self.ifaces) else i

    def _state_status(self, cmd, sess, values, rules, ask):
        p = self.call("filter", "state.status")
        return Result(columns=[("name", "Параметр"), ("value", "Значение")],
                      rows=[{"name": label, "value": p.get(k)} for k, label in _STATE_LABELS
                            if k in p])

    def _state_table(self, cmd, sess, values, rules, ask):
        rows = []
        for e in self.call("filter", "state.list").get("entries", []):
            rows.append({"conn_id": e.get("conn_id"), "proto": e.get("proto"),
                         "src": "%s:%s" % (e.get("src_ip"), e.get("sport")),
                         "dst": "%s:%s" % (e.get("dst_ip"), e.get("dport")),
                         "state": e.get("state"), "ttl": e.get("expires_in_sec"),
                         "in": self._iface(e.get("in_iface")),
                         "out": [self._iface(i) for i in e.get("out_ifaces", [])],
                         "rule": e.get("rule_id")})
        # FR-44: поля вывода таблицы состояний
        return Result(columns=[("conn_id", "ID"), ("proto", "Протокол"), ("src", "Отправитель"),
                               ("dst", "Получатель"), ("state", "Состояние"),
                               ("ttl", "Осталось, с"), ("in", "Вход"), ("out", "Выход"),
                               ("rule", "Правило")], rows=rows)

    def _state_switch(self, cmd, sess, values, rules, ask):
        self.call("filter", cmd.name.replace(" ", "."))
        return Result(code="M09")  # E14 / E15 регистрирует ПС-1

    def _state_delete(self, cmd, sess, values, rules, ask):
        self.call("filter", "state.delete", {"conn_id": values["conn_id"]})
        self.event("E35", sess, cmd.name, conn_id=values["conn_id"])
        return Result(code="M09")

    def _state_delete_all(self, cmd, sess, values, rules, ask):
        p = self.call("filter", "state.delete_all")
        self.event("E35", sess, cmd.name, deleted=p.get("deleted"))
        return Result(code="M09")

    # -- служебные -------------------------------------------------------------

    def _whoami(self, cmd, sess, values, rules, ask):
        return Result(text="Идентификатор: %s\nРоль: %s\nИнтерфейс: %s\nIP-адрес: %s" % (
            sess.username, sess.role, sess.source, sess.ip or "локальная консоль"))

    def _help(self, cmd, sess, values, rules, ask):
        group = cmd.args.get("GROUP")
        text = commands.help_text(group)
        if text is None:
            raise validation.ValidationError("группа", ", ".join(commands.groups()))
        return Result(text=text)

    def _logout(self, cmd, sess, values, rules, ask):
        try:
            session.logout(self.path("authd"), sess)
        except protocol.ProtocolError:
            pass  # сеанс уже завершён или ПС-5 не отвечает — локально всё равно выходим
        return Result(code="M09", end_session=True)  # M15 — только для принудительного завершения
