"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-6 Целостность
Модуль:      checker
Назначение:  проверка целостности при запуске, по таймеру и по запросу;
обновление эталона (FR-46, FR-47)
Методы:
  - compare - сравнить хэши контролируемых файлов с эталоном
  - violations - нарушения из результата проверки
  - Checker.check - проверка: HMAC файла эталонов, затем SHA-256 каждого файла
  - Checker.last_result - результат последней проверки (integrity.status)
  - Checker.update_baseline - обновить эталон после штатного изменения
  - Checker.restore_files - восстановить файлы и повторить проверку
  - Checker.start_periodic - запустить периодическую проверку
  - Checker.stop - остановить периодическую проверку
"""
import sys
import threading

from fwcommon import protocol

from . import hasher, restore

# Файлы config save (с. 30, FR-41a): до первого сохранения их нет, работают значения по умолчанию (FR-04).
# Имя config.json - допущение, в спецификации только /etc/fw/*.json
SAVED_FILES = ("/etc/fw/config.json", "/etc/fw/policy.json")
ACCOUNTS_FILE = "/etc/fw/accounts.json"

# Какие файлы штатно меняет источник integrity.update_baseline (с. 36)
UPDATED_FILES = {"cli": SAVED_FILES, "web": SAVED_FILES, "authd": (ACCOUNTS_FILE,)}

PASSED_STATUSES = ("ok", "not_saved")


def compare(files: list, baseline: dict) -> list:
    """Вычислить SHA-256 каждого файла и сравнить с эталоном;
    вернуть [{"path", "status"}]: ok, mismatch (хэш не совпал или нет эталона),
    missing (файл отсутствует или не читается), not_saved (файл config save
    ещё не сохранялся: нет ни файла, ни записи в эталоне, не нарушение, FR-04)."""
    result = []
    for path in files:
        try:
            digest = hasher.sha256_file(path)
        except FileNotFoundError:
            status = "not_saved" if path in SAVED_FILES and path not in baseline else "missing"
        except OSError:
            status = "missing"
        else:
            status = "ok" if baseline.get(path) == digest else "mismatch"
        result.append({"path": path, "status": status})
    return result


def violations(result: dict) -> dict:
    """Нарушения из результата проверки: {"baseline_error", "files": [{"path", "status"}]}."""
    return {"baseline_error": result["baseline_error"],
            "files": [f for f in result["files"] if f["status"] not in PASSED_STATUSES]}


class Checker:
    def __init__(self, config: dict, on_result=None):
        """config - конфигурация ПС-6 (integrityd_config_t);
        on_result(result) вызывается после каждой проверки под блокировкой, поэтому не должен блокировать:
        иначе проверка, начатая до восстановления, сообщила бы о нарушении уже после выхода из режима."""
        self.config = config
        self.on_result = on_result
        self._last = None
        self._lock = threading.Lock()  # проверка и обновление эталона идут из разных потоков сервера
        self._stopped = threading.Event()
        self._thread = None

    def check(self):
        """Проверить HMAC файла эталонов и SHA-256 каждого
        контролируемого файла; сохранить и вернуть результат
        {"last_check_ts", "ok", "baseline_error", "files": [{"path", "status"}]}.
        Нарушение - значение или HMAC не совпали (FR-46, FR-47);
        при ошибке файла эталонов files пуст: сравнивать не с чем."""
        with self._lock:
            return self._check()

    def _check(self):
        result = {"last_check_ts": protocol.now_iso(),  # ISO 8601 с миллисекундами, UTC (с. 32)
                  "baseline_error": None, "files": []}
        try:
            key = hasher.load_key(self.config["hmac_key_path"])
            baseline = hasher.load_baseline(self.config["baseline_path"], key)
        except (hasher.BaselineError, OSError) as e:
            result["baseline_error"] = str(e)
        else:
            result["files"] = compare(self.config["files"], baseline)
        result["ok"] = result["baseline_error"] is None \
            and all(f["status"] in PASSED_STATUSES for f in result["files"])
        self._last = result
        if self.on_result:
            self.on_result(result)
        return result

    def last_result(self):
        """Вернуть результат последней проверки (None, если проверки не было).
        Читается без блокировки: integrity.status не ждёт идущую проверку и не запускает её."""
        return self._last

    def update_baseline(self, src: str) -> None:
        """Обновить эталон и резервные копии после штатного изменения
        (FR-47, FR-50). src - источник: ПС-3/ПС-4 при config save,
        ПС-5 при user add/edit/delete. Пересчитываются только файлы источника
        (UPDATED_FILES), иначе посторонняя подмена стала бы штатной; при первом
        config save запись в эталоне создаётся.
        BaselineError - нарушен HMAC, OSError - файл недоступен: эталон не меняется."""
        with self._lock:
            key = hasher.load_key(self.config["hmac_key_path"])
            baseline = hasher.load_baseline(self.config["baseline_path"], key)
            digests = {path: hasher.sha256_file(path) for path in UPDATED_FILES[src] if path in self.config["files"]}
            for path in digests:
                restore.update_backup(self.config["backup_dir"], path)
            baseline.update(digests)
            hasher.save_baseline(self.config["baseline_path"], baseline, key)

    def restore_files(self, target: str):
        """Восстановить файл target или все нарушенные файлы ("all") и повторить проверку (FR-49).
        Вернуть (result, errors): errors - [{"path", "reason"}] по файлам, которые не восстановлены;
        копии, не совпавшие с эталоном, не используются. При нарушенном файле эталонов сверять копии не с чем."""
        errors = []
        with self._lock:
            try:
                key = hasher.load_key(self.config["hmac_key_path"])
                baseline = hasher.load_baseline(self.config["baseline_path"], key)
            except (hasher.BaselineError, OSError) as e:
                errors.append({"path": self.config["baseline_path"], "reason": str(e)})
            else:
                paths = [target]
                if target == "all":
                    paths = [f["path"] for f in compare(self.config["files"], baseline)
                             if f["status"] not in PASSED_STATUSES]
                for path in paths:
                    try:
                        restore.restore_file(self.config["backup_dir"], path, baseline)
                    except restore.RestoreError as e:
                        errors.append({"path": path, "reason": str(e)})
            return self._check(), errors

    def start_periodic(self) -> None:
        """Запустить проверку с периодом check_period_sec."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stopped.wait(self.config["check_period_sec"]):
            try:
                self.check()
            except Exception as e:  # контроль не должен прекратиться из-за одного сбоя
                print(f"fw-integrityd: проверка не выполнена: {e}", file=sys.stderr)

    def stop(self) -> None:
        """Остановить периодическую проверку."""
        self._stopped.set()
        self._thread.join()
