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
from datetime import datetime

from . import hasher


def compare(files: list, baseline: dict) -> list:
    """Вычислить SHA-256 каждого файла и сравнить с эталоном;
    вернуть [{"path", "status"}]: ok, mismatch (хэш не совпал или нет эталона),
    missing (файл отсутствует или не читается)."""
    result = []
    for path in files:
        try:
            digest = hasher.sha256_file(path)
        except OSError:
            status = "missing"
        else:
            status = "ok" if baseline.get(path) == digest else "mismatch"
        result.append({"path": path, "status": status})
    return result


class Checker:
    def __init__(self, config: dict, on_result=None):
        """config — конфигурация ПС-6 (integrityd_config_t);
        on_result(result) вызывается после каждой проверки."""
        self.config = config
        self.on_result = on_result
        self._last = None

    def check(self):
        """Проверить HMAC файла эталонов и SHA-256 каждого
        контролируемого файла; сохранить и вернуть результат
        {"last_check_ts", "ok", "baseline_error", "files": [{"path", "status"}]}.
        Нарушение — значение или HMAC не совпали (FR-46, FR-47);
        при ошибке файла эталонов files пуст: сравнивать не с чем."""
        result = {"last_check_ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  "baseline_error": None, "files": []}
        try:
            key = hasher.load_key(self.config["hmac_key_path"])
            baseline = hasher.load_baseline(self.config["baseline_path"], key)
        except (hasher.BaselineError, OSError) as e:
            result["baseline_error"] = str(e)
        else:
            result["files"] = compare(self.config["files"], baseline)
        result["ok"] = result["baseline_error"] is None and all(f["status"] == "ok" for f in result["files"])
        self._last = result
        if self.on_result:
            self.on_result(result)
        return result

    def last_result(self):
        """Вернуть результат последней проверки (None, если проверки не было)."""
        return self._last

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
