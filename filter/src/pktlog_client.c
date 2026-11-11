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
#define _POSIX_C_SOURCE 200809L
#include "pktlog_client.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct {
    packet_record_t *entries;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} pktlog_queue_t;

static int g_sock_fd = -1;
static char g_sock_path[108];
static pktlog_queue_t g_queue = {NULL, 0, 0, 0, 0};
static pktlog_stats_t g_stats = {0, 0, 0, 0};
static time_t g_last_connect_attempt = 0;

static void queue_cleanup(void)
{
    free(g_queue.entries);
    g_queue.entries = NULL;
    g_queue.capacity = 0;
    g_queue.head = 0;
    g_queue.tail = 0;
    g_queue.count = 0;
}

static int queue_init(uint32_t capacity)
{
    queue_cleanup();
    g_queue.entries = calloc(capacity, sizeof(packet_record_t));
    if (!g_queue.entries) {
        return -1;
    }
    g_queue.capacity = capacity;
    return 0;
}

static int queue_push(const packet_record_t *rec)
{
    if (g_queue.count >= g_queue.capacity) {
        g_stats.records_dropped++;
        return -1;
    }
    g_queue.entries[g_queue.tail] = *rec;
    g_queue.tail = (g_queue.tail + 1) % g_queue.capacity;
    g_queue.count++;
    g_stats.records_queued++;
    return 0;
}

static int try_connect(void)
{
    if (g_sock_fd >= 0) {
        return 0;
    }

    time_t now = time(NULL);
    if (now == g_last_connect_attempt) {
        return -1; /* Ограничение попыток: не чаще раза в секунду */
    }
    g_last_connect_attempt = now;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        g_stats.connect_errors++;
        return -1;
    }

    /* Неблокирующий режим */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

#ifdef SO_NOSIGPIPE
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_sock_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            g_stats.connect_errors++;
            return -1;
        }
    }

    g_sock_fd = fd;
    return 0;
}

static void close_socket(void)
{
    if (g_sock_fd >= 0) {
        close(g_sock_fd);
        g_sock_fd = -1;
    }
}

int pktlog_init(void)
{
    char default_path[sizeof(g_sock_path)];
    const char *run_dir = getenv("FW_RUN_DIR");
    if (run_dir && *run_dir) {
        snprintf(default_path, sizeof(default_path), "%s/logd-packets.sock", run_dir);
        return pktlog_init_path(default_path);
    }
    return pktlog_init_path(PKTLOG_DEFAULT_SOCKET_PATH);
}

int pktlog_init_path(const char *sock_path)
{
    close_socket();
    if (sock_path && sock_path[0] != '\0') {
        strncpy(g_sock_path, sock_path, sizeof(g_sock_path) - 1);
        g_sock_path[sizeof(g_sock_path) - 1] = '\0';
    } else {
        strncpy(g_sock_path, PKTLOG_DEFAULT_SOCKET_PATH, sizeof(g_sock_path) - 1);
    }

    if (queue_init(PKTLOG_DEFAULT_QUEUE_CAPACITY) != 0) {
        return -1;
    }

    memset(&g_stats, 0, sizeof(g_stats));
    g_last_connect_attempt = 0;

    /* Попытка первичного подключения (неблокирующая) */
    try_connect();
    return 0;
}

void pktlog_cleanup(void)
{
    close_socket();
    queue_cleanup();
}

int pktlog_flush(void)
{
    if (g_sock_fd < 0) {
        try_connect();
    }
    if (g_sock_fd < 0 || g_queue.count == 0) {
        return 0;
    }

    int sent_count = 0;
    while (g_queue.count > 0) {
        const packet_record_t *item = &g_queue.entries[g_queue.head];
        ssize_t ret = send(g_sock_fd, item, sizeof(*item), MSG_NOSIGNAL);
        if (ret == (ssize_t)sizeof(*item)) {
            g_queue.head = (g_queue.head + 1) % g_queue.capacity;
            g_queue.count--;
            g_stats.records_sent++;
            sent_count++;
        } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* Сокет временно заполнен */
            break;
        } else {
            /* Разрыв соединения */
            close_socket();
            break;
        }
    }
    return sent_count;
}

int pktlog_write_record(const packet_record_t *rec)
{
    if (!rec) return -1;

    /* Сначала сбрасываем то, что накопилось */
    if (g_queue.count > 0) {
        pktlog_flush();
    }

    /* Если очередь пуста и сокет готов, пробуем прямую отправку */
    if (g_queue.count == 0 && g_sock_fd >= 0) {
        ssize_t ret = send(g_sock_fd, rec, sizeof(*rec), MSG_NOSIGNAL);
        if (ret == (ssize_t)sizeof(*rec)) {
            g_stats.records_sent++;
            return 0;
        }
        if (ret < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
            close_socket();
        }
    }

    /* Помещаем в кольцевой буфер очереди */
    return queue_push(rec);
}

int pktlog_log_packet(const parsed_packet_t *pkt, const rule_decision_t *dec, uint32_t conn_id)
{
    if (!pkt || !dec) return -1;

    packet_record_t rec;
    memset(&rec, 0, sizeof(rec));

    /* Метка времени в микросекундах */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    rec.ts_us = (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;

    /* Действие: 0 = accept, 1 = drop */
    rec.action = (dec->verdict == RULE_MATCH_ACCEPT || dec->verdict == RULE_MATCH_ARP_FORWARD) ? 0 : 1;

    /* Входной интерфейс */
    rec.in_iface = (pkt->in_iface >= 0) ? (uint8_t)pkt->in_iface : 0xFF;

    /* Выходные интерфейсы (заполнение 0xFF для неиспользуемых позиций) */
    rec.out_count = dec->out_count;
    memset(rec.out_ifaces, 0xFF, sizeof(rec.out_ifaces));
    for (uint8_t i = 0; i < dec->out_count && i < 6; i++) {
        if (dec->out_ifaces[i] >= 0) {
            rec.out_ifaces[i] = (uint8_t)dec->out_ifaces[i];
        }
    }

    rec.rule_id = dec->rule_id;
    rec.conn_id = conn_id;

    /* eth_proto: 0 = IPv4, 1 = ARP, 2 = other */
    if (pkt->eth_proto == ETH_PROTO_ARP) {
        rec.eth_proto = 1;
    } else if (pkt->eth_proto == ETH_PROTO_OTHER) {
        rec.eth_proto = 2;
    } else {
        rec.eth_proto = 0;
    }

    rec.ip_proto = pkt->ip_proto;
    rec.smac = pkt->smac;
    rec.dmac = pkt->dmac;
    rec.src_ip = pkt->src_ip;
    rec.dst_ip = pkt->dst_ip;
    rec.sport = pkt->sport;
    rec.dport = pkt->dport;
    rec.icmp_type = pkt->icmp_type;
    rec.icmp_code = pkt->icmp_code;

    return pktlog_write_record(&rec);
}

void pktlog_get_stats(pktlog_stats_t *stats)
{
    if (stats) {
        *stats = g_stats;
    }
}

bool pktlog_is_connected(void)
{
    return g_sock_fd >= 0;
}
