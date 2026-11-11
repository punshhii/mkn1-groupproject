"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-3 CLI
Модуль:      formatter
Назначение:  вывод результатов: таблица с заголовком, постраничный вывод
             журналов (от новых к старым, page=N), сообщения M-кодов.
             Пароли и хэши не выводятся (FR-37).
Методы:
  - table — таблица с заголовком и выравниванием по ширине столбцов
  - page_footer — строка «Страница N из M, записей K»
  - message — текст сообщения по коду из common/messages.json
"""
from fwcommon import codes

_HIDDEN = {"password", "password_hash", "hash", "salt"}  # FR-37: никогда не выводятся


def _cell(v):
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return ",".join(str(x) for x in v) or "-"
    return str(v).replace("\n", " ")


def table(columns, rows):
    """columns — [(ключ, заголовок)], rows — список словарей; пустой список — M13."""
    columns = [(k, h) for k, h in columns if k not in _HIDDEN]
    if not rows:
        return codes.message_text("M13")
    cells = [[_cell(r.get(k)) for k, _ in columns] for r in rows]
    widths = [max([len(h)] + [len(c[i]) for c in cells]) for i, (_, h) in enumerate(columns)]
    line = lambda vals: "  ".join(v.ljust(w) for v, w in zip(vals, widths)).rstrip()  # noqa: E731
    out = [line([h for _, h in columns]), line(["-" * w for w in widths])]
    out += [line(c) for c in cells]
    return "\n".join(out)


def page_footer(page, page_size, total):
    pages = max(1, (total + page_size - 1) // page_size)
    return "Страница %d из %d, записей %d" % (page, pages, total)


def message(code, **kw):
    return codes.message_text(code, **kw) if kw else codes.message_text(code)
