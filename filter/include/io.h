/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      io
 * Назначение:  приём и отправка кадров L2-моста через AF_PACKET (Linux) или mock (macOS/тест)
 * Методы:
 *   - io_init — открыть AF_PACKET-сокеты на интерфейсах (по конфигурации)
 *   - io_init_mock — инициализировать mock-бэкенд для тестирования (socketpair)
 *   - io_cleanup — закрыть сокеты и освободить ресурсы
 *   - io_recv_frame — принять кадр с указанного интерфейса
 *   - io_send_frame — отправить кадр на указанный интерфейс
 *   - io_get_fd — получить файловый дескриптор интерфейса (для poll/epoll)
 *   - io_get_iface_count — получить число активных интерфейсов
 *   - io_inject_frame — инжекция тестового кадра в mock-бэкенд
 *   - io_drain_frame — извлечение отправленного кадра из mock-бэкенда
 */
#ifndef FW_IO_H
#define FW_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "types.h"

#define IO_MAX_FRAME_SIZE   9216     /* Jumbo frame + запас */

/**
 * Инициализировать модуль ввода-вывода из JSON-конфигурации.
 *
 * @param config_path Путь к config.json (если NULL, используется /etc/fw/config.json)
 * @return 0 при успехе, -1 при ошибке
 */
int io_init(const char *config_path);

/**
 * Инициализировать mock-бэкенд для модульного тестирования (socketpair/loopback).
 * Не требует привилегий root. Создаёт виртуальные пары для каждого интерфейса.
 *
 * @param iface_count Число виртуальных интерфейсов (1..MAX_INTERFACES)
 * @return 0 при успехе, -1 при ошибке
 */
int io_init_mock(uint8_t iface_count);

/**
 * Закрыть все открытые сокеты и освободить ресурсы.
 */
void io_cleanup(void);

/**
 * Принять следующий кадр с интерфейса (неблокирующий приём).
 *
 * @param iface_idx Индекс интерфейса (0..io_get_iface_count()-1)
 * @param buf       Буфер для приёма кадра
 * @param max_len   Максимальный размер буфера
 * @param out_len   Выходной параметр: фактическая длина принятого кадра
 * @return 0 при успехе, -1 если нет данных или ошибка
 */
int io_recv_frame(int iface_idx, uint8_t *buf, size_t max_len, size_t *out_len);

/**
 * Отправить кадр на указанный интерфейс.
 *
 * @param iface_idx Индекс интерфейса
 * @param buf       Указатель на кадр для отправки
 * @param len       Длина кадра в байтах
 * @return 0 при успехе, -1 при ошибке
 */
int io_send_frame(int iface_idx, const uint8_t *buf, size_t len);

/**
 * Получить файловый дескриптор для приёма кадров на указанном интерфейсе.
 *
 * @param iface_idx Индекс интерфейса
 * @return файловый дескриптор или -1
 */
int io_get_fd(int iface_idx);

/**
 * Получить число активных интерфейсов.
 */
uint8_t io_get_iface_count(void);

/**
 * Проверить, является ли интерфейс с данным индексом управляющим.
 *
 * @param iface_idx Индекс интерфейса (0..MAX_INTERFACES-1)
 * @return true, если интерфейс управляющий (is_mgmt)
 */
bool io_is_mgmt_iface(int8_t iface_idx);

/**
 * Проверить, является ли интерфейс с данным именем управляющим.
 *
 * @param name Имя интерфейса (например, "eth0")
 * @return true, если интерфейс управляющий
 */
bool io_is_mgmt_iface_name(const char *name);

/**
 * Получить индекс интерфейса по его имени.
 *
 * @param name Имя интерфейса (например, "eth0", "mock0")
 * @return Индекс интерфейса (0..MAX_INTERFACES-1) или -1, если не найден
 */
int8_t io_get_iface_index_by_name(const char *name);

/**
 * Получить имя интерфейса по индексу.
 *
 * @param iface_idx Индекс интерфейса
 * @return Имя интерфейса или NULL
 */
const char *io_get_iface_name(int8_t iface_idx);

/**
 * Установить признак управляющего интерфейса (для тестов/настройки).
 *
 * @param iface_idx Индекс интерфейса
 * @param is_mgmt   true, если управляющий
 * @return 0 при успехе, -1 при неверном индексе
 */
int io_set_iface_mgmt(int8_t iface_idx, bool is_mgmt);

/**
 * Инжекция кадра в mock-бэкенд (для тестов).
 * Кадр становится доступен для io_recv_frame на соответствующем интерфейсе.
 *
 * @param iface_idx Индекс интерфейса
 * @param buf       Указатель на кадр
 * @param len       Длина кадра
 * @return 0 при успехе, -1 при ошибке
 */
int io_inject_frame(int iface_idx, const uint8_t *buf, size_t len);

/**
 * Извлечь кадр, отправленный через io_send_frame на mock-интерфейсе (для тестов).
 *
 * @param iface_idx Индекс интерфейса
 * @param buf       Буфер для кадра
 * @param max_len   Максимальный размер буфера
 * @param out_len   Выходной параметр: фактическая длина кадра
 * @return 0 при успехе (кадр извлечён), -1 если пусто
 */
int io_drain_frame(int iface_idx, uint8_t *buf, size_t max_len, size_t *out_len);

#endif /* FW_IO_H */
