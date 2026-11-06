/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      pktlog_client
 * Назначение:  передача записей пакетов в ПС-2 (двоичный формат 55 байт, неблокирующая очередь)
 * Методы:
 *   - pktlog_init — открыть неблокирующее соединение с ПС-2
 *   - pktlog_cleanup — закрыть соединение и освободить очередь
 *   - pktlog_log_packet — сформировать запись и передать в очередь/сокет
 *   - pktlog_write_record — прямая передача packet_record_t
 *   - pktlog_flush — сброс буферизованных записей в сокет
 *   - pktlog_get_stats — опрос счётчиков работы клиента
 *   - pktlog_is_connected — проверка статуса соединения с сокетом
 */
#ifndef FW_PKTLOG_CLIENT_H
#define FW_PKTLOG_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include "packet_record.h"
#include "parser.h"
#include "rules.h"

#define PKTLOG_DEFAULT_SOCKET_PATH "/run/fw/logd-packets.sock"
#define PKTLOG_DEFAULT_QUEUE_CAPACITY 4096

typedef struct {
    uint64_t records_queued;
    uint64_t records_sent;
    uint64_t records_dropped;
    uint64_t connect_errors;
} pktlog_stats_t;

/**
 * Инициализировать клиент журнала пакетов (с сокетом по умолчанию /run/fw/logd-packets.sock).
 *
 * @return 0 при успехе, -1 при ошибке
 */
int pktlog_init(void);

/**
 * Инициализировать клиент журнала пакетов с указанным путём к сокету.
 *
 * @param sock_path Путь к Unix-сокету (если NULL, используется PKTLOG_DEFAULT_SOCKET_PATH)
 * @return 0 при успехе, -1 при ошибке
 */
int pktlog_init_path(const char *sock_path);

/**
 * Закрыть соединение и освободить ресурсы очереди.
 */
void pktlog_cleanup(void);

/**
 * Сформировать запись журнала пакетов и отправить её в сокет/очередь (неблокирующе).
 *
 * @param pkt      Указатель на разобранный пакет
 * @param dec      Указатель на принятое решение по правилам
 * @param conn_id  Идентификатор записи conntrack (0, если вне соединения)
 * @return 0 при успехе, -1 при переполнении очереди
 */
int pktlog_log_packet(const parsed_packet_t *pkt, const rule_decision_t *dec, uint32_t conn_id);

/**
 * Прямая запись структуры packet_record_t (55 байт) в сокет или очередь.
 *
 * @param rec Указатель на запись журнала пакетов
 * @return 0 при успехе, -1 при переполнении очереди
 */
int pktlog_write_record(const packet_record_t *rec);

/**
 * Сбросить буферизованные записи очереди в сокет.
 *
 * @return Число успешно отправленных записей (или отрицательное значение при ошибке)
 */
int pktlog_flush(void);

/**
 * Получить текущую статистику клиента журнала пакетов.
 *
 * @param stats Выходная структура для метрик
 */
void pktlog_get_stats(pktlog_stats_t *stats);

/**
 * Проверить активность соединения с Unix-сокетом.
 *
 * @return true если сокет подключён, false если отключён
 */
bool pktlog_is_connected(void);

#endif /* FW_PKTLOG_CLIENT_H */
