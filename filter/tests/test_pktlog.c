/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      test_pktlog
 * Назначение:  модульные тесты клиента журнала пакетов (pktlog_client)
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "packet_record.h"
#include "parser.h"
#include "pktlog_client.h"
#include "rules.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
    } else { \
        fprintf(stderr, "FAILED [%s:%d]: %s\n", __FILE__, __LINE__, #cond); \
        assert(cond); \
    } \
} while (0)

static void test_record_structure_layout(void)
{
    TEST_ASSERT(sizeof(packet_record_t) == 55);

    packet_record_t rec;
    uint8_t *p = (uint8_t *)&rec;

    TEST_ASSERT((uint8_t *)&rec.ts_us - p == 0);
    TEST_ASSERT((uint8_t *)&rec.action - p == 8);
    TEST_ASSERT((uint8_t *)&rec.in_iface - p == 9);
    TEST_ASSERT((uint8_t *)&rec.out_count - p == 10);
    TEST_ASSERT((uint8_t *)&rec.out_ifaces - p == 11);
    TEST_ASSERT((uint8_t *)&rec.rule_id - p == 17);
    TEST_ASSERT((uint8_t *)&rec.conn_id - p == 19);
    TEST_ASSERT((uint8_t *)&rec.eth_proto - p == 23);
    TEST_ASSERT((uint8_t *)&rec.ip_proto - p == 24);
    TEST_ASSERT((uint8_t *)&rec.smac - p == 25);
    TEST_ASSERT((uint8_t *)&rec.dmac - p == 33);
    TEST_ASSERT((uint8_t *)&rec.src_ip - p == 41);
    TEST_ASSERT((uint8_t *)&rec.dst_ip - p == 45);
    TEST_ASSERT((uint8_t *)&rec.sport - p == 49);
    TEST_ASSERT((uint8_t *)&rec.dport - p == 51);
    TEST_ASSERT((uint8_t *)&rec.icmp_type - p == 53);
    TEST_ASSERT((uint8_t *)&rec.icmp_code - p == 54);
}

static void test_offline_buffering_and_overflow(void)
{
    /* Инициализация с несуществующим сокетом */
    const char *bad_sock = "/tmp/non_existent_fw_test_sock.sock";
    unlink(bad_sock);

    TEST_ASSERT(pktlog_init_path(bad_sock) == 0);
    TEST_ASSERT(!pktlog_is_connected());

    packet_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.rule_id = 42;

    /* Запись должна буферизоваться в очереди без блокировки */
    for (int i = 0; i < 100; i++) {
        TEST_ASSERT(pktlog_write_record(&rec) == 0);
    }

    pktlog_stats_t stats;
    pktlog_get_stats(&stats);
    TEST_ASSERT(stats.records_queued == 100);
    TEST_ASSERT(stats.records_dropped == 0);
    TEST_ASSERT(stats.records_sent == 0);

    /* Тест переполнения: заполняем буфер до предела */
    for (int i = 100; i < PKTLOG_DEFAULT_QUEUE_CAPACITY; i++) {
        TEST_ASSERT(pktlog_write_record(&rec) == 0);
    }

    /* Следующая запись должна отброситься */
    TEST_ASSERT(pktlog_write_record(&rec) == -1);

    pktlog_get_stats(&stats);
    TEST_ASSERT(stats.records_dropped == 1);
    TEST_ASSERT(stats.records_queued == PKTLOG_DEFAULT_QUEUE_CAPACITY);

    pktlog_cleanup();
}

static void test_mock_server_transfer(void)
{
    const char *sock_path = "/tmp/fw_test_pktlog_srv.sock";
    unlink(sock_path);

    /* Создание mock-сервера ПС-2 */
    int srv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    TEST_ASSERT(srv_fd >= 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    TEST_ASSERT(bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(listen(srv_fd, 5) == 0);

    /* Инициализация клиента */
    TEST_ASSERT(pktlog_init_path(sock_path) == 0);

    /* Принятие соединения на сервере */
    int cli_fd = accept(srv_fd, NULL, NULL);
    TEST_ASSERT(cli_fd >= 0);

    /* Подготовка тестового пакета и решения */
    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.in_iface = 1;
    pkt.eth_proto = ETH_PROTO_ANY;
    pkt.eth_type = 0x0800;
    pkt.ip_proto = 6; /* TCP */
    pkt.smac = 0x001122334455ULL;
    pkt.dmac = 0xAABBCCDDEEFFULL;
    pkt.src_ip = 0x0A000001U; /* 10.0.0.1 */
    pkt.dst_ip = 0xC0A80101U; /* 192.168.1.1 */
    pkt.sport = 12345;
    pkt.dport = 443;

    rule_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.verdict = RULE_MATCH_ACCEPT;
    dec.rule_id = 77;
    dec.out_count = 2;
    dec.out_ifaces[0] = 2;
    dec.out_ifaces[1] = 3;
    dec.out_ifaces[2] = -1;

    /* Логирование пакета */
    TEST_ASSERT(pktlog_log_packet(&pkt, &dec, 9999) == 0);

    /* Чтение 55 байт сервером */
    uint8_t buf[55];
    ssize_t n = recv(cli_fd, buf, sizeof(buf), 0);
    TEST_ASSERT(n == 55);

    const packet_record_t *r = (const packet_record_t *)buf;
    TEST_ASSERT(r->action == 0); /* accept */
    TEST_ASSERT(r->in_iface == 1);
    TEST_ASSERT(r->out_count == 2);
    TEST_ASSERT(r->out_ifaces[0] == 2);
    TEST_ASSERT(r->out_ifaces[1] == 3);
    TEST_ASSERT(r->out_ifaces[2] == 0xFF); /* Padding 0xFF */
    TEST_ASSERT(r->out_ifaces[3] == 0xFF);
    TEST_ASSERT(r->rule_id == 77);
    TEST_ASSERT(r->conn_id == 9999);
    TEST_ASSERT(r->eth_proto == 0); /* IPv4 */
    TEST_ASSERT(r->ip_proto == 6);
    TEST_ASSERT(r->smac == 0x001122334455ULL);
    TEST_ASSERT(r->dmac == 0xAABBCCDDEEFFULL);
    TEST_ASSERT(r->src_ip == 0x0A000001U);
    TEST_ASSERT(r->dst_ip == 0xC0A80101U);
    TEST_ASSERT(r->sport == 12345);
    TEST_ASSERT(r->dport == 443);
    TEST_ASSERT(r->ts_us > 0);

    pktlog_stats_t stats;
    pktlog_get_stats(&stats);
    TEST_ASSERT(stats.records_sent == 1);

    close(cli_fd);
    close(srv_fd);
    unlink(sock_path);
    pktlog_cleanup();
}

int main(void)
{
    printf("Running pktlog_client tests...\n");

    test_record_structure_layout();
    test_offline_buffering_and_overflow();
    test_mock_server_transfer();

    printf("ALL PKTLOG TESTS PASSED (%d/%d checks passed)\n", tests_passed, tests_run);
    return 0;
}
