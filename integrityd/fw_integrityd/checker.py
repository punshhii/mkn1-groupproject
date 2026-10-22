"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      checker
Назначение:  проверка целостности при запуске, по таймеру и по запросу;
обновление эталона (FR-46, FR-47)
Методы:
  - compare — сравнить хэши контролируемых файлов с эталоном
  - Checker.check — проверка: HMAC файла эталонов, затем SHA-256 каждого файла
  - Checker.last_result — результат последней проверки (integrity.status)
  - Checker.update_baseline — обновить эталон после штатного изменения
  - Checker.start_periodic — запустить периодическую проверку
  - Checker.stop — остановить периодическую проверку
"""


def compare(files: list, baseline: dict) -> list:
    """Вычислить SHA-256 каждого файла и сравнить с эталоном;
    вернуть список файлов с несовпадением."""
    raise NotImplementedError("checker.compare")


class Checker:
    def __init__(self, config: dict, on_result=None):
        """config — конфигурация ПС-6 (integrityd_config_t);
        on_result(result) вызывается после каждой проверки."""
        self.config = config
        self.on_result = on_result
        self._last = None

    def check(self):
        """Проверить HMAC файла эталонов и SHA-256 каждого
        контролируемого файла; сохранить и вернуть результат.
        Нарушение — значение или HMAC не совпали (FR-46, FR-47)."""
        raise NotImplementedError("checker.Checker.check")

    def last_result(self):
        """Вернуть результат последней проверки."""
        raise NotImplementedError("checker.Checker.last_result")

    def update_baseline(self, src: str) -> None:
        """Обновить эталон и резервные копии после штатного изменения
        (FR-47, FR-50). src - источник: ПС-3/ПС-4 при config save,
        ПС-5 при user add/edit/delete."""
        raise NotImplementedError("checker.Checker.update_baseline")

    def start_periodic(self) -> None:
        """Запустить проверку с периодом check_period_sec."""
        raise NotImplementedError("checker.Checker.start_periodic")

    def stop(self) -> None:
        """Остановить периодическую проверку."""
        raise NotImplementedError("checker.Checker.stop")
