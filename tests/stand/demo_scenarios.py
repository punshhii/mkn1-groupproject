#!/usr/bin/env python3
"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  тестовый стенд (tests/stand)
Модуль:      demo_scenarios.py
Назначение:  сценарии взаимодействия подсистем для промежуточного показа:
             CLI (ПС-3) и web (ПС-4) против настоящих authd (ПС-5), logd (ПС-2),
             integrityd (ПС-6) и filter (ПС-1). Стенд поднимает demo_stand.sh.
             Каждый сценарий печатает диалог CLI и итог ПРОЙДЕН / НЕ ПРОЙДЕН.
Запуск:      sudo tests/stand/demo_stand.sh            # терминал 1
             python3 tests/stand/demo_scenarios.py     # терминал 2
             python3 tests/stand/demo_scenarios.py --pause      # пауза (Enter) перед каждым сценарием
             python3 tests/stand/demo_scenarios.py --only 1,4   # выбранные сценарии
             Сценарий 8 (целостность) переводит МЭ в аварийный режим: после него стенд перезапустить.
"""
import argparse
import http.cookiejar
import json
import os
import pty
import re
import select
import sys
import time
import urllib.parse
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUN_DIR = "/tmp/fw"
CONFIG = os.path.join(RUN_DIR, "config.json")
WEB = "http://127.0.0.1:8080/"
ADMIN_PW = "Admin_12345"
OPER_PW = "Oper_12345"
PROMPT = re.compile(r"@fw\[(rw|ro|EMERGENCY)\]> $")

C_OK, C_FAIL, C_HEAD, C_DIM, C_END = "\033[32m", "\033[31m", "\033[1;36m", "\033[2m", "\033[0m"


class Cli:
    """Сеанс fw_cli в псевдотерминале: вход, команды, ответ до следующего приглашения."""

    def __init__(self, user, password, echo=True):
        self.echo = echo
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(REPO)
            os.environ["PYTHONPATH"] = "common:cli"
            os.execvp(sys.executable, [sys.executable, "-m", "fw_cli", "--run-dir", RUN_DIR,
                                       "--config", CONFIG, "--net", "stand"])
        self.read_until(["идентификатор"])
        self.send(user)
        self.read_until(["пароль"])
        self.send(password, show=False)
        self.login_output = self.read_until([PROMPT, "идентификатор"])

    def send(self, line, show=True):
        time.sleep(0.2)
        os.write(self.fd, (line + "\n").encode())

    def read_until(self, pats, timeout=10.0):
        buf, end = "", time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.2)
            if not r:
                continue
            try:
                chunk = os.read(self.fd, 4096).decode("utf-8", "replace")
            except OSError:
                break
            buf += chunk
            if self.echo:
                sys.stdout.write(chunk.replace("\r", ""))
                sys.stdout.flush()
            for p in pats:
                if (p.search(buf) if hasattr(p, "search") else p in buf):
                    return buf
        return buf

    def cmd(self, line, answers=()):
        """Выполнить команду; answers — ответы на запросы пароля и (y/n) по порядку."""
        self.send(line)
        out = self.read_until([PROMPT, "пароль", "(y/n)"])
        for a in answers:
            if PROMPT.search(out):  # запроса нет — ответ не нужен
                break
            self.send(a, show=False)
            out += self.read_until([PROMPT, "пароль", "(y/n)"])
        return out

    def wait_for(self, text, timeout):
        """Дождаться асинхронного вывода (например, уведомления ПС-6) без ввода команды."""
        return self.read_until([text], timeout)

    @property
    def prompt_ok(self):
        return bool(PROMPT.search(self.login_output))

    def close(self):
        try:
            self.cmd("logout")
        except OSError:
            pass
        try:
            os.close(self.fd)
            os.waitpid(self.pid, 0)
        except OSError:
            pass


class Web:
    """Клиент web ПС-4: вход с CSRF-токеном и чтение разделов."""

    def __init__(self):
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def get(self, page):
        with self.op.open(WEB + "?page=" + page, timeout=10) as r:
            return r.read().decode("utf-8")

    def login(self, user, password):
        token = re.search(r'name="csrf" value="([^"]*)"', self.get("login")).group(1)
        data = urllib.parse.urlencode({"csrf": token, "id": user, "password": password}).encode()
        with self.op.open(WEB + "?page=login", data=data, timeout=10) as r:
            return r.read().decode("utf-8")

    @staticmethod
    def text(html):
        main = re.sub(r"(?s)<style.*?</style>", "", html)
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)).strip()


RESULTS = []


def check(name, cond):
    RESULTS.append((name, bool(cond)))
    mark = C_OK + "  ✔ " if cond else C_FAIL + "  ✘ "
    print("\n" + mark + name + C_END)


def head(n, title, what):
    print("\n" + C_HEAD + "═" * 78 + "\n Сценарий %d. %s\n" % (n, title) + C_END + C_DIM + " " + what + C_END)
    print(C_HEAD + "═" * 78 + C_END)


# ---------------------------------------------------------------- сценарии

def s1_login():
    head(1, "Вход администратора", "CLI → authd: проверка пароля PBKDF2, сеанс, роль; событие E01 → logd")
    a = Cli("admin", ADMIN_PW)
    check("admin вошёл, приглашение admin@fw[rw]", "admin@fw[rw]" in a.login_output)
    out = a.cmd("whoami")
    check("whoami: роль rw, интерфейс cli", "rw" in out and "cli" in out)
    a.close()


def s2_users():
    head(2, "Учётные записи", "CLI → authd: user add / list; запись в accounts.json; событие E32 → logd")
    a = Cli("admin", ADMIN_PW)
    a.cmd("user del operator", answers=("y",))  # повторный прогон: убрать прежнюю запись
    out = a.cmd("user add operator role=ro", answers=(OPER_PW, OPER_PW))
    check("user add operator role=ro — «Операция выполнена»", "выполнена" in out)
    out = a.cmd("user list")
    check("operator в списке с ролью ro", re.search(r"operator\s+ro", out))
    a.close()


def s3_roles():
    head(3, "Разграничение прав", "CLI → authd (auth.check перед каждой командой) → отказ M03 и событие E50 → logd")
    o = Cli("operator", OPER_PW)
    check("operator вошёл с ролью ro", "operator@fw[ro]" in o.login_output)
    out = o.cmd("rule list")
    check("просмотр разрешён: rule list без ошибки", "недостаточно прав" not in out)
    out = o.cmd("rule add 9 in=eth1 proto=icmp action=drop")
    check("изменение запрещено: «недостаточно прав»", "недостаточно прав" in out)
    out = o.cmd("user add hacker role=rw")
    check("создание учётной записи запрещено", "недостаточно прав" in out)
    o.close()
    a = Cli("admin", ADMIN_PW)
    out = a.cmd("log events show code=E50")
    check("в журнале logd событие E50 от operator", "E50" in out and "operator" in out)
    a.close()


def s4_rules():
    head(4, "Политика доступа", "CLI → filter (rule.replace с путём к policy.json) → filter применяет; E20/E21 → logd")
    a = Cli("admin", ADMIN_PW)
    out = a.cmd("rule list")
    for n in sorted({int(x) for x in re.findall(r"^(\d+)\s", out, re.M)}, reverse=True):
        a.cmd("rule del %d" % n, answers=("y",))
    out = a.cmd("rule add 1 in=eth1 proto=icmp action=drop")
    check("rule add 1 (ICMP drop) принят фильтром", "выполнена" in out)
    out = a.cmd("rule add 2 in=eth1 proto=tcp dport=22 action=accept out=eth2")
    check("rule add 2 (TCP/22 accept → eth2) принят фильтром", "выполнена" in out)
    out = a.cmd("rule disable 1")
    check("rule disable 1 принят фильтром", "выполнена" in out)
    out = a.cmd("rule list")
    check("rule list из filter: правило 1 отключено, 2 активно",
          re.search(r"^1\s+no\s", out, re.M) and re.search(r"^2\s+yes\s", out, re.M))
    out = a.cmd("log events show")
    check("в журнале E20 (добавление) и E21 (изменение) с командой", "E20" in out and "E21" in out)
    a.close()


def s5_second_rw():
    head(5, "Второй администратор с правами rw", "authd: одновременно только один rw-сеанс, второй понижается до ro (FR-34)")
    a = Cli("admin", ADMIN_PW, echo=False)
    print(C_DIM + "  (первый сеанс admin открыт в фоне)" + C_END)
    b = Cli("admin", ADMIN_PW)
    check("второй сеанс получил «права понижены», приглашение [ro]",
          "понижены" in b.login_output and "admin@fw[ro]" in b.login_output)
    out = b.cmd("session list")
    check("session list показывает оба сеанса admin", out.count("admin") >= 2)
    b.close()
    a.close()


def s6_bad_password():
    head(6, "Неверный пароль", "CLI → authd: отказ M02, событие E03 → logd")
    a = Cli("admin", "wrong_password")
    check("вход отклонён: «неверный идентификатор или пароль»", "неверный" in a.login_output)
    os.close(a.fd)
    os.kill(a.pid, 9)
    os.waitpid(a.pid, 0)
    a = Cli("admin", ADMIN_PW)
    out = a.cmd("log events show code=E03")
    check("в журнале событие E03 (неуспешный вход)", "E03" in out)
    a.close()


def s7_web():
    head(7, "Web-интерфейс", "браузер → web (PHP) → authd; общие с CLI учётные записи и сеансы")
    w = Web()
    try:
        w.login("operator", OPER_PW)
    except OSError as e:
        check("web доступен на %s (%s)" % (WEB, e), False)
        return
    t = Web.text(w.get("status"))
    print(C_DIM + "  status: " + t[:160] + " ..." + C_END)
    check("operator вошёл в web, роль ro", "operator" in t and "ro" in t)
    t = Web.text(w.get("admins"))
    print(C_DIM + "  admins: " + t[t.find("Учётные"):][:200] + " ..." + C_END)
    check("в разделе «Администраторы» видны admin и operator, созданный в CLI",
          "admin" in t and "operator" in t)
    a = Cli("admin", ADMIN_PW)
    out = a.cmd("session list")
    check("CLI видит web-сеанс operator (интерфейс web)", re.search(r"operator\s+ro\s+web", out))
    a.close()


def s8_integrity():
    head(8, "Нарушение целостности", "integrityd → emergency.enter в CLI и web, блокировка изменений, E40 → logd")
    cfg = json.load(open(CONFIG, encoding="utf-8"))["integrityd"]
    target, period = cfg["files"][0], int(cfg.get("check_period_sec", 60))
    a = Cli("admin", ADMIN_PW)
    w = Web()
    w.login("admin", ADMIN_PW)
    print(C_DIM + "  >>> злоумышленник дописывает строку в %s" % target + C_END)
    with open(target, "a", encoding="utf-8") as f:
        f.write("\n#tampered\n")
    out = a.wait_for("EMERGENCY", period + 15)
    check("открытый CLI сам перешёл в [EMERGENCY] (без ввода команды)", "EMERGENCY" in out)
    out = a.cmd("rule add 5 in=eth1 proto=udp action=drop")
    check("изменения отклонены: «недопустимая операция в режиме аварийной поддержки»",
          "аварийной" in out)
    out = a.cmd("rule list")
    check("просмотр в аварийном режиме доступен", "аварийной" not in out)
    out = a.cmd("log events show code=E40")
    check("в журнале событие E40 от integrityd", "E40" in out)
    t = Web.text(w.get("status"))
    check("web показывает «Аварийная поддержка» и плашку о нарушении", "Аварийная поддержка" in t)
    a.close()
    print(C_DIM + "  Для повтора сценариев перезапустите стенд (demo_stand.sh)." + C_END)


SCENARIOS = [s1_login, s2_users, s3_roles, s4_rules, s5_second_rw, s6_bad_password, s7_web, s8_integrity]


def main():
    ap = argparse.ArgumentParser(description="Сценарии взаимодействия подсистем ПО МЭ")
    ap.add_argument("--only", help="номера сценариев через запятую, например 1,3,8")
    ap.add_argument("--pause", action="store_true", help="ждать Enter перед каждым сценарием")
    args = ap.parse_args()
    if not os.path.exists(os.path.join(RUN_DIR, "authd.sock")):
        sys.exit("Стенд не запущен: sudo tests/stand/demo_stand.sh")
    picked = [int(x) for x in args.only.split(",")] if args.only else range(1, len(SCENARIOS) + 1)
    for n in picked:
        if args.pause:
            input(C_DIM + "\n[Enter] — сценарий %d" % n + C_END)
        try:
            SCENARIOS[n - 1]()
        except Exception as e:  # сценарий не должен ронять остальные
            check("сценарий %d завершился исключением: %r" % (n, e), False)
    ok = sum(r for _, r in RESULTS)
    color = C_OK if ok == len(RESULTS) else C_FAIL
    print("\n" + color + "Итого проверок: %d из %d пройдено" % (ok, len(RESULTS)) + C_END)
    for name, r in RESULTS:
        if not r:
            print(C_FAIL + "  ✘ " + name + C_END)
    sys.exit(0 if ok == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
