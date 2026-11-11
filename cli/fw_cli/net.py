"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      net
Назначение:  интерфейсы и маршруты ОС для групп if и route (ТЗ 5.10, 5.11).
             На МЭ: чтение — ip -j, изменение — sudo -n и фиксированный список
             команд ip (README ПС-3: «ОС (sudo, фиксированный список)»). На
             стенде вместо ОС — заглушка «os» (tests/stand/mock_core.py) по
             протоколу подсистем, чтобы не менять сеть машины стенда.
Методы:
  - NetError — команда ОС не выполнена
  - SystemNet — ОС: links, routes, set_link, set_addr, add_route, del_route
  - SocketNet — заглушка ОС стенда с теми же методами (сокет os.sock)
  - in_subnet — адрес принадлежит сети адрес/маска
"""
import ipaddress
import json
import subprocess

from fwcommon import protocol

IP = "/usr/sbin/ip"
SUDO = ("sudo", "-n")      # без запроса пароля: разрешения — в sudoers, фиксированный список
TIMEOUT_SEC = 5


class NetError(Exception):
    """Команда ОС не выполнена (текст stderr ip или sudo)."""


def in_subnet(addr, cidr):
    """True, если addr (a.b.c.d) лежит в сети интерфейса cidr (a.b.c.d/nn)."""
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_interface(cidr).network
    except ValueError:
        return False


class SystemNet:
    """Интерфейсы и маршруты ОС через ip(8)."""

    def _run(self, args, sudo=False):
        cmd = (list(SUDO) if sudo else []) + [IP] + list(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_SEC)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise NetError(str(e))
        if r.returncode != 0:
            raise NetError((r.stderr or r.stdout).strip() or "код %d" % r.returncode)
        return r.stdout

    def links(self):
        """[{name, state, addr, mac, rx_bytes, tx_bytes}] — addr: a.b.c.d/nn или None."""
        out = []
        for i in json.loads(self._run(["-j", "-s", "addr", "show"]) or "[]"):
            v4 = [a for a in i.get("addr_info", []) if a.get("family") == "inet"]
            st = i.get("stats64") or i.get("stats") or {}
            out.append({"name": i.get("ifname"),
                        "state": "up" if "UP" in i.get("flags", []) else "down",
                        "addr": "%s/%s" % (v4[0]["local"], v4[0]["prefixlen"]) if v4 else None,
                        "mac": i.get("address"),
                        "rx_bytes": (st.get("rx") or {}).get("bytes"),
                        "tx_bytes": (st.get("tx") or {}).get("bytes")})
        return out

    def routes(self):
        """[{dst, gw, dev}] — dst: сеть/маска или default."""
        return [{"dst": r.get("dst"), "gw": r.get("gateway"), "dev": r.get("dev")}
                for r in json.loads(self._run(["-j", "route", "show"]) or "[]")]

    def set_link(self, name, up):
        self._run(["link", "set", "dev", name, "up" if up else "down"], sudo=True)

    def set_addr(self, name, cidr):
        self._run(["addr", "flush", "dev", name], sudo=True)
        self._run(["addr", "add", cidr, "dev", name], sudo=True)

    def add_route(self, net, gw, dev):
        self._run(["route", "add", net, "via", gw, "dev", dev], sudo=True)

    def del_route(self, net):
        self._run(["route", "del", net], sudo=True)


class SocketNet:
    """Заглушка ОС стенда: те же методы через запросы к os.sock."""

    def __init__(self, path, src="cli"):
        self.path, self.src = path, src

    def _call(self, cmd, payload=None):
        try:
            return protocol.request(self.path, self.src, "os", cmd, payload)["payload"]
        except protocol.ProtocolError as e:
            raise NetError(e.message)

    def links(self):
        return self._call("if.list").get("ifaces", [])

    def routes(self):
        return self._call("route.list").get("routes", [])

    def set_link(self, name, up):
        self._call("if.up" if up else "if.down", {"name": name})

    def set_addr(self, name, cidr):
        self._call("if.ip", {"name": name, "addr": cidr})

    def add_route(self, net, gw, dev):
        self._call("route.add", {"dst": net, "gw": gw, "dev": dev})

    def del_route(self, net):
        self._call("route.del", {"dst": net})
