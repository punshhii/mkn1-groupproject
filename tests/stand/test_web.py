"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  тестовый стенд (tests/stand)
Модуль:      test_web
Назначение:  web ПС-4 через php -S поверх заглушек mock_core: вход через ПС-5 с
             IP из REMOTE_ADDR, auth.check на каждую страницу и действие (M03 от
             ПС-5, M16 — ПС-5 не отвечает), разделы «Администраторы» (сеансы с
             IP), «Контроль состояний» («Клиент» и «Сервер»), «Сеть» (IP только у
             управляющего интерфейса), integrity.status на каждом запросе
             (баннер M08, M10 на действия), session.terminate (M15), CSRF.
             Интерпретатор — переменная PHP или php в PATH; нет — тест пропускается.
Запуск:      python3 tests/stand/test_web.py
"""
import http.cookiejar
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "common"))
sys.path.insert(0, _HERE)

import mock_core  # noqa: E402

PHP = os.environ.get("PHP") or shutil.which("php")
WEB = os.path.join(_HERE, "..", "..", "web")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


class Browser:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.page = ""

    def get(self, query=""):
        with self.opener.open(self.base + query, timeout=30) as r:
            self.page = r.read().decode("utf-8")
        return self.page

    def csrf(self):
        return re.search(r'name="csrf" value="([0-9a-f]+)"', self.page).group(1)

    def post(self, query, **fields):
        fields.setdefault("csrf", self.csrf())
        data = urllib.parse.urlencode(fields).encode()
        with self.opener.open(self.base + query, data=data, timeout=30) as r:
            self.page = r.read().decode("utf-8")
        return self.page

    def login(self, uid="admin", pwd="admin123"):
        self.get()
        return self.post("?page=login", id=uid, password=pwd)


@unittest.skipUnless(PHP, "нет интерпретатора PHP (переменная PHP или php в PATH)")
class WebTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = cls._tmp.name
        with open(os.path.join(cls.dir, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"ifaces": [{"name": "eth0", "is_mgmt": True}, {"name": "eth1"},
                                  {"name": "eth2"}]}, f)
        cls.servers = mock_core.start(cls.dir)
        env = dict(os.environ, FW_RUN_DIR=cls.dir, FW_NET="stand")
        cls.listener = subprocess.Popen([PHP, os.path.join(WEB, "src", "listener.php"), cls.dir],
                                        stderr=subprocess.DEVNULL)
        port = _free_port()
        cls.web = subprocess.Popen([PHP, "-S", "127.0.0.1:%d" % port, "-t", os.path.join(WEB, "public")],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.base = "http://127.0.0.1:%d/" % port
        def up():
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return True
            except OSError:
                return False
        assert _wait(lambda: os.path.exists(os.path.join(cls.dir, "web.sock")))
        assert _wait(up, 10), "php -S не запустился"

    @classmethod
    def tearDownClass(cls):
        for p in (cls.web, cls.listener):
            p.terminate()
            p.wait(timeout=5)
        for srv in cls.servers.values():
            srv.shutdown()
            srv.server_close()
        cls._tmp.cleanup()

    def setUp(self):
        mock_core.reset_state()
        state = os.path.join(self.dir, "web.state.json")
        if os.path.exists(state):
            os.unlink(state)
        self.b = Browser(self.base)

    def sessions(self, uid):
        return [sid for sid, v in mock_core._state["sessions"].items() if v["username"] == uid]

    def test_login_page_and_wrong_password(self):
        self.assertIn("Идентификатор", self.b.get())
        self.assertIn("неверный идентификатор или пароль", self.b.login(pwd="wrong-pass"))

    def test_login_through_authd_with_ip(self):
        page = self.b.login()
        self.assertIn("Штатный", page)                      # раздел «Состояние» после входа
        self.assertIn("IP: 127.0.0.1", page)
        s = mock_core._state["sessions"][self.sessions("admin")[0]]
        self.assertEqual((s["source"], s["ip"]), ("web", "127.0.0.1"))  # IP из REMOTE_ADDR

    def test_admins_sessions_with_ip(self):
        self.b.login()
        page = self.b.get("?page=admins")
        self.assertIn("<th>IP-адрес</th>", page)
        self.assertIn("<td>127.0.0.1</td>", page)
        self.assertIn("viewer", page)                       # учётные записи

    def test_conntrack_client_server(self):
        self.b.login()
        page = self.b.get("?page=conntrack")
        self.assertIn("Клиент (IP:порт)", page)
        self.assertIn("Сервер (IP:порт)", page)
        self.assertIn("192.168.1.10:40000", page)
        page = self.b.post("?page=conntrack", action="state_delete", conn_id="1")
        self.assertIn("Операция выполнена", page)
        self.assertNotIn("192.168.1.10:40000", page)
        self.assertTrue(_wait(lambda: [e for e in mock_core.events("E35") if e.get("source") == "web"]))

    def test_network_ip_only_management(self):
        self.b.login()
        page = self.b.get("?page=network")
        row = lambda name: re.search(r"<tr><td>%s</td>.*?</tr>" % name, self.b.page).group(0)  # noqa: E731
        self.assertIn("управляющий", row("eth0"))
        self.assertIn("192.168.1.1/24", row("eth0"))
        self.assertIn("фильтрующий", row("eth1"))
        self.assertNotIn("Задать IP", row("eth1"))
        page = self.b.post("?page=network", action="if_ip", name="eth1", addr="10.0.0.1/24")
        self.assertIn("только управляющий интерфейс: eth0", page)
        self.assertIsNone(mock_core._state["net"]["links"]["eth1"]["addr"])
        page = self.b.post("?page=network", action="if_ip", name="eth0", addr="192.168.1.7/24")
        self.assertIn("Операция выполнена", page)
        self.assertEqual(mock_core._state["net"]["links"]["eth0"]["addr"], "192.168.1.7/24")
        page = self.b.post("?page=network", action="route_add", net="10.20.0.0/16", gw="10.10.0.1")
        self.assertIn("адрес в сети управляющего интерфейса", page)

    def test_auth_check_ro_m03(self):
        self.b.login("viewer", "viewer123")
        page = self.b.get("?page=conntrack")
        self.assertNotIn("Удалить", page)                   # кнопок изменения для ro нет
        page = self.b.post("?page=conntrack", action="state_delete", conn_id="1")  # запрос напрямую
        self.assertIn("недостаточно прав", page)            # M03 от ПС-5
        self.assertEqual(len(mock_core._state["ct_entries"]), 2)
        e50 = mock_core.events("E50")[-1]
        self.assertEqual((e50["src"], e50["cmd"]), ("authd", "state delete"))

    def test_auth_check_extends_and_every_page(self):
        self.b.login()
        sid = self.sessions("admin")[0]
        mock_core.advance_clock(600)
        self.b.get("?page=network")                         # auth.check продлевает сеанс
        self.assertLess(mock_core._now() - mock_core._state["sessions"][sid]["last"], 5)
        mock_core.advance_clock(901)
        self.assertIn("Сеанс завершён", self.b.get("?page=admins"))   # M15 -> вход
        self.assertIn("Войти", self.b.page)

    def test_emergency_banner_and_m10(self):
        self.b.login()
        mock_core.set_broken("/etc/fw/config.json")
        page = self.b.get("?page=status")
        self.assertIn("Аварийная поддержка", page)
        self.assertIn("нарушена целостность файлов", page)  # баннер M08
        page = self.b.get("?page=network")
        self.assertIn("недопустимая операция в режиме аварийной поддержки", page)  # M10
        page = self.b.post("?page=conntrack", action="state_delete_all")
        self.assertIn("недопустимая операция", page)
        self.assertEqual(len(mock_core._state["ct_entries"]), 2)
        mock_core.restore_all()
        self.assertTrue(_wait(lambda: "Штатный" in self.b.get("?page=status")))

    def test_session_terminate_m15_resets_php_session(self):
        self.b.login("viewer", "viewer123")
        sid = self.sessions("viewer")[0]
        admin = Browser(self.base)
        admin.login()
        admin.get("?page=admins")
        self.assertIn("Операция выполнена", admin.post("?page=admins", action="session_kill", target=sid))
        st = os.path.join(self.dir, "web.state.json")

        def terminated():
            with open(st, encoding="utf-8") as f:
                return sid in f.read()
        self.assertTrue(_wait(terminated))
        page = self.b.get("?page=status")
        self.assertIn("Сеанс завершён: «сеанс сброшен администратором admin»", page)
        self.assertIn("Войти", self.b.get("?page=status"))  # PHP-сессия сброшена

    def test_csrf_required(self):
        self.b.login()
        self.b.get("?page=conntrack")
        page = self.b.post("?page=conntrack", action="state_delete", conn_id="1", csrf="0" * 32)
        self.assertIn("форма устарела", page)
        self.assertEqual(len(mock_core._state["ct_entries"]), 2)

    def test_authd_down_m16(self):
        self.b.login()
        srv = self.servers.pop("authd")
        srv.shutdown()
        srv.server_close()
        os.unlink(os.path.join(self.dir, "authd.sock"))
        try:
            page = self.b.get("?page=admins")
            self.assertIn("подсистема «authd» не отвечает", page)
            self.assertNotIn("<h2>Активные сеансы</h2>", page)
        finally:
            self.servers.update(mock_core.start(self.dir, ("authd",)))


if __name__ == "__main__":
    unittest.main()
