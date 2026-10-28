"""
Система:     ПО межсетевого экрана (ПО МЭ)
Подсистема:  ПС-2 Регистрация
Модуль:      packet_log
Назначение:  журнал пакетов: двоичный кольцевой файл (записи по 55 байт), буфер в памяти,
             запись блоками по 4096 записей или не реже раза в секунду (FR-26, FR-29)
Методы:
  - unpack_record — разобрать 55 байт в dict (формат common/packet_record.h)
  - PacketLog.append — добавить запись в буфер
  - PacketLog.flush — сбросить буфер в файл (log.flush)
  - PacketLog.read_all — записи файла + буфера (для выборок)
  - PacketLog.clear — очистить журнал (E34)
  - PacketLog.count — число записей
  - PacketLog.start_flusher — фоновый сброс буфера раз в секунду
"""
import struct

RECORD_SIZE = 55
BLOCK_RECORDS = 4096
# ts_us, action, in_iface, out_count, out_ifaces[6], rule_id, conn_id, eth_proto, ip_proto,
# smac, dmac, src_ip, dst_ip, sport, dport, icmp_type, icmp_code  (little-endian, без выравнивания)
RECORD_FMT = "<QBBB6sHIBBQQIIHHBB"
assert struct.calcsize(RECORD_FMT) == RECORD_SIZE



def unpack_record(raw: bytes) -> dict:
    """Разобрать одну запись (ровно 55 байт) в словарь; ValueError при неверной длине."""
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("raw must be bytes-like")

    if len(raw) != RECORD_SIZE:
        raise ValueError(
            f"Expected {RECORD_SIZE} bytes, got {len(raw)}"
        )

    (
        ts_us,
        action,
        in_iface,
        out_count,
        out_ifaces,
        rule_id,
        conn_id,
        eth_proto,
        ip_proto,
        smac,
        dmac,
        src_ip,
        dst_ip,
        sport,
        dport,
        icmp_type,
        icmp_code,
    ) = struct.unpack(RECORD_FMT, raw)

    return {
        "ts_us": ts_us,
        "action": action,
        "in_iface": in_iface,
        "out_count": out_count,
        "out_ifaces": out_ifaces,
        "rule_id": rule_id,
        "conn_id": conn_id,
        "eth_proto": eth_proto,
        "ip_proto": ip_proto,
        "smac": smac,
        "dmac": dmac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "sport": sport,
        "dport": dport,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
    }



class PacketLog:
    def __init__(self, path: str, limit_bytes: int):
        """Инициализировать журнал пакетов."""
        import threading

        if limit_bytes < RECORD_SIZE:
            raise ValueError(
                f"limit_bytes must be at least {RECORD_SIZE}"
            )

        self.path = path
        self.limit_bytes = limit_bytes
        self.max_records = limit_bytes // RECORD_SIZE

        self.buffer = []
        self._lock = threading.RLock()
        self._flusher_thread = None
        self._stop_flusher = threading.Event()

    def append(self, raw: bytes) -> None:
        """Добавить запись в журнал пакетов."""
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise TypeError("raw must be bytes-like")

        if len(raw) != RECORD_SIZE:
            raise ValueError(
                f"Expected {RECORD_SIZE} bytes, got {len(raw)}"
            )

        with self._lock:
            self.buffer.append(bytes(raw))

            if len(self.buffer) >= BLOCK_RECORDS:
                self.flush()

    def flush(self) -> None:
        """Записать в файл с учётом максимального размера."""
        with self._lock:
            if not self.buffer:
                return

            # Прочитать записи, уже имеющиеся в файле.
            existing_records = []

            try:
                with open(self.path, "rb") as file:
                    while True:
                        raw = file.read(RECORD_SIZE)

                        if not raw:
                            break

                        if len(raw) != RECORD_SIZE:
                            raise ValueError(
                                "The packet log contains an incomplete record"
                            )

                        existing_records.append(raw)

            except FileNotFoundError:
                pass

            # Добавить новые записи к имеющимся.
            all_records = existing_records + self.buffer

            # Оставить более новые записи.
            all_records = all_records[-self.max_records:]

            # Перезаписать файл.
            with open(self.path, "wb") as file:
                for raw in all_records:
                    file.write(raw)

            # Сбросить буфер.
            self.buffer.clear()

    def read_all(self):
        """Прочитать все записи от старых к новым."""
        with self._lock:
            records = []

            # Прочитать записи, уже записанные в файл.
            try:
                with open(self.path, "rb") as file:
                    while True:
                        raw = file.read(RECORD_SIZE)

                        if not raw:
                            break

                        if len(raw) != RECORD_SIZE:
                            raise ValueError(
                                "The packet log contains an incomplete record"
                            )

                        records.append(raw)

            except FileNotFoundError:
                pass

            # Добавить записи, ещё находящиеся в буфере.
            records.extend(self.buffer)

            # Преобразовать каждую бинарную запись в словарь.
            return [unpack_record(raw) for raw in records]

    def clear(self) -> None:
        """Очистить журнал пакетов."""
        with self._lock:
            self.buffer.clear()

            with open(self.path, "wb"):
                pass

    def count(self) -> int:
        """Вернуть количество записей в журнале."""
        with self._lock:
            file_count = 0

            try:
                with open(self.path, "rb") as file:
                    while True:
                        raw = file.read(RECORD_SIZE)

                        if not raw:
                            break

                        if len(raw) != RECORD_SIZE:
                            raise ValueError(
                                "The packet log contains an incomplete record"
                            )

                        file_count += 1

            except FileNotFoundError:
                pass

            return file_count + len(self.buffer)

    def start_flusher(self, period_sec: float = 1.0) -> None:
        """Запустить поток, периодически сбрасывающий буфер."""
        import threading

        if period_sec <= 0:
            raise ValueError("period_sec must be positive")

        with self._lock:
            if (
                    self._flusher_thread is not None
                    and self._flusher_thread.is_alive()
            ):
                return

            self._stop_flusher.clear()

            def worker():
                while not self._stop_flusher.wait(period_sec):
                    try:
                        self.flush()
                    except Exception:
                        # Избежать тихой остановки потока
                        # без возможности сигнализации.
                        import traceback
                        traceback.print_exc()

            self._flusher_thread = threading.Thread(
                target=worker,
                name="packet-log-flusher",
                daemon=True,
            )
            self._flusher_thread.start()

    def stop_flusher(self) -> None:
        """Остановить поток и записать последние записи."""
        import threading  

        with self._lock:
            thread = self._flusher_thread
            if thread is None:
                return
            self._stop_flusher.set()

        if thread is not threading.current_thread():
            thread.join()

        self.flush()

        with self._lock:
            self._flusher_thread = None