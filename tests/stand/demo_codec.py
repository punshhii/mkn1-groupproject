"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  тестовый стенд (tests/stand)
Модуль:      demo_codec
Назначение:  демонстрация клиентского сценария ПС-3/ПС-4 поверх кодека: серия
             запросов к запущенным заглушкам (mock_core) с выводом ответов и
             ошибок M-кодов. Показывает типовой код клиента:
             request() -> ответ / ProtocolError.
Методы:
- show — выполнить запрос и напечатать ответ или ошибку
- main — сценарий демонстрации
Запуск:      терминал 1: python3 tests/stand/mock_core.py /tmp/fw
             терминал 2: python3 tests/stand/demo_codec.py /tmp/fw
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "common"))

from fwcommon import protocol  # noqa: E402

RUN_DIR = sys.argv[1] if len(sys.argv) > 1 else "/tmp/fw"


def show(dst, cmd, payload=None):
    """Выполнить один запрос и напечатать запрос и ответ в читаемом виде."""
    print("\n-> %s %s %s" % (dst, cmd, json.dumps(payload or {}, ensure_ascii=False)))
    try:
        resp = protocol.request(os.path.join(RUN_DIR, dst + ".sock"), "cli", dst, cmd, payload)
    except protocol.ProtocolError as e:
        print("   <- %s: %s" % (e.code, e.message))
        return None
    print("   <- ok %s" % json.dumps(resp["payload"], ensure_ascii=False))
    return resp["payload"]


def main():
    print("Клиент src=cli -> заглушки в %s" % RUN_DIR)

    show("authd", "auth.login", {"id": "admin", "password": "wrong-password"})   # M02
    admin = show("authd", "auth.login", {"id": "admin", "password": "admin123"})
    viewer = show("authd", "auth.login", {"id": "viewer", "password": "viewer123"})
    if not admin or not viewer:
        return 1
    show("authd", "auth.check", {"session_id": viewer["session_id"], "cmd": "rule.replace"})  # M03

    rules = show("filter", "rule.get")["rules"]
    for r in rules:
        r.pop("hits", None)
    rules.append({"id": 10, "action": "drop", "proto": "icmp"})
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump({"rules": rules}, fh)
    show("filter", "rule.replace", {"path": fh.name})
    os.unlink(fh.name)
    show("filter", "state.list")

    show("logd", "log.query.events", {"page": 1, "page_size": 5})
    show("logd", "log.query.events", {"event_code": "E99"})                      # пусто -> M13
    show("integrityd", "integrity.status")
    show("authd", "rule.dropall")                                                # M14
    show("authd", "auth.logout", {"session_id": admin["session_id"]})
    return 0


if __name__ == "__main__":
    sys.exit(main())
