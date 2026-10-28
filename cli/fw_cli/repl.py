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
  - run — вход и цикл чтения-выполнения до logout / exit / конца ввода
"""
import getpass

from fwcommon import codes, protocol

from . import commands, parser

CONFIRM_PROMPT = "Подтвердите (y/n): "
help_text = commands.help_text


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
        if sess.warning:
            write(codes.message_text(sess.warning))  # M04: права понижены
        return sess


def run(core, read=input, read_secret=getpass.getpass, write=print, ip=None):
    """Вход и цикл чтения-выполнения. Возвращает код завершения процесса."""
    sess = login_loop(core, read, read_secret, write, ip)
    if sess is None:
        return 0

    def confirm():
        try:
            return is_confirmed(read(CONFIRM_PROMPT))
        except EOFError:
            return False

    while True:
        try:
            line = read(prompt(sess.username, sess.role, core.emergency()))
        except EOFError:
            line = "logout"  # конец ввода (закрыт SSH) — штатный выход, E02
        except KeyboardInterrupt:
            write("")
            continue
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
