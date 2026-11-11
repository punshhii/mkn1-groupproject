"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      test_shared
Назначение:  прогон общих сценариев tests/shared/*.json: шаги do=command —
             через разбор и проверку CLI; шаги login / notify / mode / exec —
             через ядро управления, приёмник входящих команд и заглушки
             mock_core (аварийный режим, session.terminate). ПС-4 прогоняет те
             же сценарии и должна получать те же коды и поля
"""
import glob
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "stand"))

import mock_core  # noqa: E402
from fwcommon import protocol  # noqa: E402
from fw_cli import core, listener, parser, validation  # noqa: E402

_SHARED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "shared")
SESSION_STEPS = ("login", "notify", "mode", "exec")


def scenarios():
    for path in sorted(glob.glob(os.path.join(_SHARED, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            yield os.path.basename(path), json.load(fh)


def run_line(line, ifaces, rule_ids):
    """Строка команды -> {"ok": True} или {"message": код, "field": поле}."""
    try:
        cmd = parser.parse(line)
        validation.check_command(cmd, ifaces, rule_ids)
    except (parser.ParseError, validation.ValidationError) as e:
        out = {"message": e.code}
        if e.field is not None:
            out["field"] = e.field
        return out
    return {"ok": True}


class SharedScenariosTest(unittest.TestCase):
    def test_command_steps(self):
        total = 0
        for path in sorted(glob.glob(os.path.join(_SHARED, "*.json"))):
            with open(path, encoding="utf-8") as fh:
                sc = json.load(fh)
            for step in sc["steps"]:
                if step["do"] != "command":
                    continue
                total += 1
                with self.subTest(file=os.path.basename(path), line=step["line"]):
                    got = run_line(step["line"], sc.get("ifaces", []),
                                   set(sc.get("existing_rules", [])))
                    self.assertEqual(got, step["expect"])
        self.assertGreater(total, 0)


class SharedSessionScenariosTest(unittest.TestCase):
    """Сценарии с шагами login / notify / mode / exec против заглушек."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = cls._tmp.name
        cls.servers = mock_core.start(cls.dir)

    @classmethod
    def tearDownClass(cls):
        for srv in cls.servers.values():
            srv.shutdown()
            srv.server_close()
        cls._tmp.cleanup()

    def run_scenario(self, name, sc):
        mock_core.reset_state()
        inbox = listener.Inbox()  # без сокета: входящие команды передаются напрямую
        c = core.Core(run_dir=self.dir, ifaces=["eth0", "eth1", "eth2"], event_retry=False,
                      inbox=inbox)
        sess = None
        for i, step in enumerate(sc["steps"]):
            do, exp = step["do"], step.get("expect")
            with self.subTest(file=name, step=i, do=do):
                if do == "login":
                    sess = c.login(step["id"], step["password"])
                    self.assertEqual({"role": sess.role}, exp)
                elif do == "mode":
                    self.assertEqual("emergency" if c.emergency() else "normal", exp)
                elif do == "notify":
                    payload = {k: (sess.session_id if v == "$session" else v)
                               for k, v in step.get("payload", {}).items()}
                    msg = protocol.make_msg("request", step["src"], "cli", cmd=step["cmd"],
                                            payload=payload)
                    status, p, code, _ = inbox.handler(msg)
                    got = {"status": status}
                    if "mode" in exp:
                        got["mode"] = p.get("mode")
                    if code:
                        got["error_code"] = code
                    self.assertEqual(got, exp)
                elif do == "exec":
                    r = c.execute(parser.parse(step["line"]), sess, confirm=lambda: True,
                                  ask_password=lambda _p: "password99")
                    self.assertEqual({"message": r.code} if r.error else {"ok": True}, exp)

    def test_session_steps(self):
        total = 0
        for name, sc in scenarios():
            if any(s["do"] in SESSION_STEPS and s["do"] != "login" for s in sc["steps"]):
                total += 1
                self.run_scenario(name, sc)
        self.assertGreater(total, 0)


if __name__ == "__main__":
    unittest.main()
