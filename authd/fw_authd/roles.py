"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-5 Авторизация
Модуль:      roles
Назначение:  роли rw / ro, проверка права на команду
Методы:
  - is_modifying_cmd — проверка, является ли команда изменяющей состояние
  - is_read_only_cmd — проверка, является ли команда запросом на чтение
  - check_permission — проверка прав роли на выполнение команды
  - check_session_permission — проверка прав сеанса на выполнение команды
  - validate_role_transition — валидация смены роли (защита admin)
  - get_role_permissions — получение описания прав для заданной роли
"""
from typing import Any, Dict, Optional, Set, Tuple

ROLE_RW = "rw"
ROLE_RO = "ro"
ALLOWED_ROLES = (ROLE_RW, ROLE_RO)

# Полный список изменяющих команд ПО МЭ (FR-32, FR-37b, таблица 7 ТЗ, commands.py CLI).
# Включает как имена команд CLI (через пробел), так и протокольные имена с точками.
MODIFYING_COMMANDS: Set[str] = {
    # ПС-1 Фильтрация
    "rule add",
    "rule edit",
    "rule enable",
    "rule disable",
    "rule del",
    "rule.add",
    "rule.edit",
    "rule.enable",
    "rule.disable",
    "rule.del",
    "rule.delete",
    "rule.replace",
    # Контроль состояний
    "state enable",
    "state disable",
    "state delete",
    "state delete all",
    "state.enable",
    "state.disable",
    "state.delete",
    "state.clear",
    # ПС-2 Журналирование
    "log packets clear",
    "log.packets.clear",
    "log.flush",
    # Конфигурация
    "config save",
    "config apply saved",
    "config apply default",
    "config set",
    "config.save",
    "config.apply",
    "config.apply.saved",
    "config.apply.default",
    "config.set",
    "config.reset",
    # ПС-5 Учётные записи и сеансы
    "user add",
    "user edit",
    "user del",
    "user.add",
    "user.edit",
    "user.del",
    "user.delete",
    "session kill",
    "session.kill",
    # Сеть и система (ОС)
    "if up",
    "if down",
    "if ip",
    "if.up",
    "if.down",
    "if.ip",
    "if.set",
    "time set",
    "time.set",
    "route add",
    "route del",
    "route.add",
    "route.del",
    "route.set",
    "subsystem restart",
    "subsystem.restart",
    "sys reboot",
    "sys.reboot",
    "sys shutdown",
    "sys.shutdown",
    # ПС-6 Контроль целостности
    "integrity check",
    "integrity restore",
    "integrity.check",
    "integrity.restore",
    "integrity.update_baseline",
}

# Белый список команд, доступных роли ro (таблица 7 ТЗ, commands.py CLI, tests/stand/mock_core.py)
# + служебные команды auth.*. Любая команда, которой нет в этом списке, считается
# изменяющей и требует роль rw.
READ_ONLY_COMMANDS: Set[str] = {
    # Служебные и справочные
    "help",
    "whoami",
    "logout",
    "exit",
    # ПС-5 Авторизация
    "auth.login",
    "auth.logout",
    "auth.ping",
    "auth.check",
    "user list",
    "user.list",
    "session list",
    "session.list",
    # ПС-1 Фильтрация
    "rule list",
    "rule show",
    "rule.get",
    "rule.list",
    "rule.show",
    "state status",
    "state table",
    "state.status",
    "state.list",
    "state.table",
    "stats.get",
    # ПС-2 Журналирование
    "log events show",
    "log packets show",
    "log.query.events",
    "log.query.packets",
    "log.events.show",
    "log.packets.show",
    # Конфигурация
    "config show current",
    "config show saved",
    "config.show",
    "config.show.current",
    "config.show.saved",
    # Сеть и система (ОС)
    "if list",
    "if show",
    "if.list",
    "if.show",
    "route list",
    "route.list",
    "time show",
    "time.show",
    "sys info",
    "sys.info",
    "subsystem list",
    "subsystem.list",
    # ПС-6 Контроль целостности
    "integrity status",
    "integrity.status",
}


def is_modifying_cmd(cmd: str) -> bool:
    """
    Проверка, является ли команда изменяющей состояние (FR-32).
    Принцип «запрещено всё, что явно не разрешено»: команда, которой нет
    в белом списке READ_ONLY_COMMANDS (в том числе неизвестная), считается
    изменяющей и требует роль rw.
    """
    if not isinstance(cmd, str):
        return True
    return cmd.strip() not in READ_ONLY_COMMANDS


def is_read_only_cmd(cmd: str) -> bool:
    """Проверка, является ли команда запросом на чтение."""
    return not is_modifying_cmd(cmd)


def check_permission(role: str, cmd: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Проверка прав роли на выполнение команды (FR-32, FR-37b).
    Роль 'rw' может выполнять любые команды.
    Роль 'ro' не может выполнять изменяющие команды: возвращает (False, "M03", "E50").
    """
    if role not in ALLOWED_ROLES:
        return False, "M03", "E50"

    if role == ROLE_RW:
        return True, None, None

    # Роль ro (только чтение)
    if is_modifying_cmd(cmd):
        return False, "M03", "E50"

    return True, None, None


def check_session_permission(session: Any, cmd: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Проверка прав сеанса (словарь сеанса или идентификатор роли).
    """
    if isinstance(session, dict):
        role = session.get("effective_role") or session.get("role", ROLE_RO)
    elif isinstance(session, str):
        role = session
    else:
        return False, "M03", "E50"

    return check_permission(role, cmd)


def validate_role_transition(
    username: str,
    current_role: str,
    new_role: str,
) -> Tuple[bool, Optional[str]]:
    """
    Проверка допустимости изменения роли (FR-33).
    Предустановленному администратору 'admin' запрещено менять роль с rw (M05).
    """
    if username == "admin" and new_role != ROLE_RW:
        return False, "M05"
    if new_role not in ALLOWED_ROLES:
        return False, "M06"
    return True, None


def get_role_permissions(role: str) -> Dict[str, Any]:
    """Получение информации о правах роли."""
    can_modify = (role == ROLE_RW)
    return {
        "role": role,
        "can_modify": can_modify,
        "can_read": True,
        "allowed_categories": ["read", "write"] if can_modify else ["read"],
    }
