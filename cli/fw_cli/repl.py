"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      repl
Назначение:  цикл чтения-выполнения: вход (M01, скрытый ввод пароля),
             приглашения admin@fw[rw|ro|EMERGENCY]>, подтверждение
             «Подтвердите (y/n):», вывод результатов ядра управления.
Методы:
  - prompt — строка приглашения для сеанса и режима
  - is_confirmed — ответ на «Подтвердите (y/n):»: только «y» подтверждает
  - help_text — help и help группа по таблице команд
  - login_loop — запрос идентификатора и пароля до успешного входа
  - on_wake_signal — обработчик SIGUSR1: прервать ожидание ввода после входящей команды
  - run — вход и цикл чтения-выполнения до logout / exit / конца ввода / session.terminate
"""
import getpass

from fwcommon import codes, protocol

from . import commands, parser

CONFIRM_PROMPT = "Подтвердите (y/n): "
help_text = commands.help_text

_waiting = False  # CLI ждёт строку команды: только тогда сигнал прерывает ввод


class Wake(Exception):
    """Пока CLI ждал ввода, пришла входящая команда: вывести её и обновить приглашение."""


def on_wake_signal(signum=None, frame=None):
    """SIGUSR1 от приёмника: во время выполнения команды игнорируется, изменение
    будет показано перед следующим приглашением."""
    if _waiting:
        raise Wake()


def prompt(username, role, emergency=False):
    """admin@fw[rw]> , admin@fw[ro]> или admin@fw[EMERGENCY]> ."""
    return "%s@fw[%s]> " % (username, "EMERGENCY" if emergency else role)


def is_confirmed(answer):
    """Любой ответ, кроме y, отменяет операцию без изменений и без события."""
    return answer.strip() == "y"


def login_loop(core, read, read_secret, write, ip=None):
    """M01: идентификатор и пароль (скрытым вводом) до успешного входа; None — конец ввода."""
    ask_id, ask_pwd = (s.strip() + " " for s in codes.message_text("M01").split("/"))
    while True:
        try:
            uid = read(ask_id).strip()
            pwd = read_secret(ask_pwd)
        except EOFError:
            return None
        if not uid:
            continue
        try:
            sess = core.login(uid, pwd, ip=ip)
        except protocol.ProtocolError as e:
            write(e.message)  # M02, M12 или M16
            continue
        except Exception as e:  # необработанные исключения не завершают процесс
            write("Ошибка: вход не выполнен, внутренняя ошибка CLI (%s)" % type(e).__name__)
            continue
        if sess.warning:
            write(codes.message_text(sess.warning))  # M04: права понижены
        return sess


def run(core, read=input, read_secret=getpass.getpass, write=print, ip=None):
    """Вход и цикл чтения-выполнения. Возвращает код завершения процесса."""
    sess = login_loop(core, read, read_secret, write, ip)
    if sess is None:
        return 0

    global _waiting

    def confirm():
        try:
            return is_confirmed(read(CONFIRM_PROMPT))
        except EOFError:
            return False

    def incoming():
        """Вывести принятое приёмником; True — ПС-5 завершила сеанс (session.terminate)."""
        text = core.inbox.take_notice()
        if text:
            write(text)  # M08 из emergency.enter
        reason = core.inbox.terminated_reason(sess.session_id)
        if reason is not None:
            write(codes.message_text("M15", reason=reason))
            return True
        return False

    while True:
        if incoming():
            return 0
        core.inbox.listen()  # сокет освободился (другой вход завершён) — занять его
        _waiting = True
        try:
            line = read(prompt(sess.username, sess.role, core.emergency()))
        except EOFError:
            line = "logout"  # конец ввода (закрыт SSH) — штатный выход, E02
        except Wake:
            write("")
            continue
        except KeyboardInterrupt:
            write("")
            continue
        finally:
            _waiting = False
        if incoming():
            return 0
        try:
            cmd = parser.parse(line)
            if cmd is None:
                continue
            res = core.execute(cmd, sess, confirm=confirm, ask_password=read_secret)
        except parser.ParseError as e:
            write(e.message)
            continue
        except KeyboardInterrupt:
            write("Операция отменена")
            continue
        except Exception as e:  # необработанные исключения не завершают процесс
            write("Ошибка: внутренняя ошибка CLI (%s)" % type(e).__name__)
            continue
        out = res.render()
        if out:
            write(out)
        if res.end_session:
            return 0
