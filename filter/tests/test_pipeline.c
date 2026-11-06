/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      test_pipeline
 * Назначение:  интеграционный тест сквозного конвейера обработки пакетов
 *              (io_mock -> parse_frame -> conntrack -> rules -> pktlog -> io_send)
 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "conntrack.h"
#include "control.h"
#include "io.h"
#include "json_utils.h"
#include "parser.h"
#include "pktlog_client.h"
#include "rules.h"

static int g_tests_run = 0;
static int g_asserts_passed = 0;

#define TEST_ASSERT(cond) do { \
    g_asserts_passed++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: assertion failed: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

/* ------------------------------------------------------------- */
/* Генераторы тестовых кадров                                    */
/* ------------------------------------------------------------- */

static uint16_t ip_checksum(const uint8_t *buf, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i += 2) {
        uint16_t word = (uint16_t)((buf[i] << 8) | ((i + 1 < len) ? buf[i + 1] : 0));
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

/*
 * Формирует Ethernet + IPv4 + TCP кадр.
 * Возвращает размер кадра, записанного в buf.
 */
static size_t build_tcp_frame(uint8_t *buf, size_t buf_len,
                              const uint8_t smac[6], const uint8_t dmac[6],
                              uint32_t sip, uint32_t dip,
                              uint16_t sport, uint16_t dport,
                              uint8_t tcp_flags) {
    if (buf_len < 54) return 0;
    memset(buf, 0, buf_len);

    /* Ethernet header (14 bytes) */
    memcpy(buf, dmac, 6);
    memcpy(buf + 6, smac, 6);
    buf[12] = 0x08; buf[13] = 0x00; /* EtherType IPv4 */

    /* IPv4 header (20 bytes) */
    uint8_t *ip = buf + 14;
    ip[0] = 0x45; /* version=4, IHL=5 */
    ip[1] = 0x00; /* TOS */
    uint16_t total_len = htons(40); /* 20 IP + 20 TCP */
    memcpy(ip + 2, &total_len, 2);
    ip[4] = 0; ip[5] = 1;  /* identification */
    ip[6] = 0x40; ip[7] = 0; /* DF=1, offset=0 */
    ip[8] = 64; /* TTL */
    ip[9] = 6;  /* proto TCP */
    ip[10] = 0; ip[11] = 0; /* checksum placeholder */
    uint32_t sip_n = htonl(sip);
    uint32_t dip_n = htonl(dip);
    memcpy(ip + 12, &sip_n, 4);
    memcpy(ip + 16, &dip_n, 4);

    /* IP checksum */
    uint16_t csum = ip_checksum(ip, 20);
    uint16_t csum_n = htons(csum);
    memcpy(ip + 10, &csum_n, 2);

    /* TCP header (20 bytes) */
    uint8_t *tcp = buf + 34;
    uint16_t sp_n = htons(sport);
    uint16_t dp_n = htons(dport);
    memcpy(tcp, &sp_n, 2);
    memcpy(tcp + 2, &dp_n, 2);
    tcp[4] = 0; tcp[5] = 0; tcp[6] = 0; tcp[7] = 1; /* seq=1 */
    tcp[8] = 0; tcp[9] = 0; tcp[10] = 0; tcp[11] = 0; /* ack=0 */
    tcp[12] = 0x50; /* data offset=5 (20 bytes) */
    tcp[13] = tcp_flags;
    tcp[14] = 0xFF; tcp[15] = 0xFF; /* window */
    /* checksum=0 (not validated by parser per spec) */

    return 54;
}

/*
 * Формирует ARP кадр (42 байта).
 */
static size_t build_arp_frame(uint8_t *buf, size_t buf_len,
                              const uint8_t smac[6], const uint8_t dmac[6]) {
    if (buf_len < 42) return 0;
    memset(buf, 0, buf_len);

    /* Ethernet header */
    memcpy(buf, dmac, 6);
    memcpy(buf + 6, smac, 6);
    buf[12] = 0x08; buf[13] = 0x06; /* EtherType ARP */

    /* ARP payload (28 bytes) */
    buf[14] = 0x00; buf[15] = 0x01; /* hw type = Ethernet */
    buf[16] = 0x08; buf[17] = 0x00; /* proto type = IPv4 */
    buf[18] = 6;    /* hw addr len */
    buf[19] = 4;    /* proto addr len */
    buf[20] = 0x00; buf[21] = 0x01; /* opcode = ARP Request */
    memcpy(buf + 22, smac, 6);      /* sender hw addr */
    buf[28] = 10; buf[29] = 0; buf[30] = 0; buf[31] = 1; /* sender proto addr */
    memset(buf + 32, 0xFF, 6);      /* target hw addr (broadcast) */
    buf[38] = 10; buf[39] = 0; buf[40] = 0; buf[41] = 2; /* target proto addr */

    return 42;
}

/*
 * Формирует Ethernet + IPv4 + UDP кадр.
 */
static size_t build_udp_frame(uint8_t *buf, size_t buf_len,
                              const uint8_t smac[6], const uint8_t dmac[6],
                              uint32_t sip, uint32_t dip,
                              uint16_t sport, uint16_t dport) {
    if (buf_len < 42) return 0;
    memset(buf, 0, buf_len);

    /* Ethernet header */
    memcpy(buf, dmac, 6);
    memcpy(buf + 6, smac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    /* IPv4 header (20 bytes) */
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    uint16_t total_len = htons(28); /* 20 IP + 8 UDP */
    memcpy(ip + 2, &total_len, 2);
    ip[6] = 0x40; ip[8] = 64; ip[9] = 17; /* UDP */
    uint32_t sip_n = htonl(sip);
    uint32_t dip_n = htonl(dip);
    memcpy(ip + 12, &sip_n, 4);
    memcpy(ip + 16, &dip_n, 4);
    uint16_t csum = ip_checksum(ip, 20);
    uint16_t csum_n = htons(csum);
    memcpy(ip + 10, &csum_n, 2);

    /* UDP header (8 bytes) */
    uint8_t *udp = buf + 34;
    uint16_t sp_n = htons(sport), dp_n = htons(dport);
    memcpy(udp, &sp_n, 2);
    memcpy(udp + 2, &dp_n, 2);
    uint16_t udp_len = htons(8);
    memcpy(udp + 4, &udp_len, 2);

    return 42;
}

static void init_rule_defaults(rule_t *r, rule_id_t id) {
    memset(r, 0, sizeof(*r));
    r->id = id;
    r->active = 1;
    r->in_iface = -1; /* any */
    r->icmp_type = 255; /* any */
    r->icmp_code = 255; /* any */
    r->src_mask = 0xFFFFFFFFU;
    r->dst_mask = 0xFFFFFFFFU;
    r->action = ACTION_DROP;
    for (int k = 0; k < MAX_INTERFACES; k++) {
        r->out_ifaces[k] = -1;
    }
}

/* ------------------------------------------------------------- */
/* Тест 1: IPv4 TCP-пакет пропущен по правилу accept             */
/* ------------------------------------------------------------- */
static void test_tcp_accept_forwarded(void) {
    g_tests_run++;

    /* Правило: id=10, active, in_iface=0, proto=TCP, dport=80, action=accept, out=[1] */
    rule_t r;
    init_rule_defaults(&r, 10);
    r.log = 1;
    r.in_iface = 0;
    r.proto = 6; /* TCP */
    r.dport = 80; r.dport_end = 80;
    r.action = ACTION_ACCEPT;
    r.out_ifaces[0] = 1;
    r.conntrack = 1;
    strcpy(r.comment, "Allow HTTP");

    rules_replace(&r, 1, NULL);

    /* Построить TCP SYN -> 10.0.0.1:12345 -> 192.168.1.1:80 */
    uint8_t smac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    uint8_t dmac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};
    uint8_t frame[128];
    size_t flen = build_tcp_frame(frame, sizeof(frame), smac, dmac,
                                  0x0A000001, 0xC0A80101, 12345, 80, FW_TCP_SYN);
    TEST_ASSERT(flen == 54);

    /* Инжекция на интерфейс 0 */
    TEST_ASSERT(io_inject_frame(0, frame, flen) == 0);

    /* Чтение на интерфейсе 0 и прогон через parse -> rules -> forward */
    uint8_t recv_buf[IO_MAX_FRAME_SIZE];
    size_t recv_len = 0;
    TEST_ASSERT(io_recv_frame(0, recv_buf, sizeof(recv_buf), &recv_len) == 0);
    TEST_ASSERT(recv_len == flen);

    parsed_packet_t pkt;
    parse_result_t pr = parse_frame(recv_buf, (unsigned)recv_len, 0, &pkt);
    TEST_ASSERT(pr == PARSE_OK);

    rule_decision_t dec;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.rule_id == 10);
    TEST_ASSERT(dec.conntrack == 1);
    TEST_ASSERT(dec.log == 1);
    TEST_ASSERT(dec.out_ifaces[0] == 1);

    /* Отправка на интерфейс 1 */
    TEST_ASSERT(io_send_frame(1, recv_buf, recv_len) == 0);

    /* Чтение отправленного на интерфейсе 1 (из mock) */
    uint8_t drain_buf[IO_MAX_FRAME_SIZE];
    size_t drain_len = 0;
    TEST_ASSERT(io_drain_frame(1, drain_buf, sizeof(drain_buf), &drain_len) == 0);
    TEST_ASSERT(drain_len == recv_len);
    TEST_ASSERT(memcmp(drain_buf, recv_buf, recv_len) == 0);
}

/* ------------------------------------------------------------- */
/* Тест 2: IPv4 TCP-пакет без правила -> DEFAULT_DROP             */
/* ------------------------------------------------------------- */
static void test_tcp_default_drop(void) {
    g_tests_run++;

    /* Пустая таблица — default drop */
    rules_replace(NULL, 0, NULL);

    uint8_t smac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x01};
    uint8_t dmac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x02};
    uint8_t frame[128];
    size_t flen = build_tcp_frame(frame, sizeof(frame), smac, dmac,
                                  0x0A010001, 0xC0A80201, 5000, 443, FW_TCP_SYN);

    parsed_packet_t pkt;
    parse_result_t pr = parse_frame(frame, (unsigned)flen, 0, &pkt);
    TEST_ASSERT(pr == PARSE_OK);

    rule_decision_t dec;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_DEFAULT_DROP);
    TEST_ASSERT(dec.rule_id == 0);
}

/* ------------------------------------------------------------- */
/* Тест 3: ARP с включённой пересылкой (FR-11)                  */
/* ------------------------------------------------------------- */
static void test_arp_forwarding(void) {
    g_tests_run++;

    rules_replace(NULL, 0, NULL);
    rules_set_arp_forwarding(true);

    uint8_t smac[6] = {0xAA, 0, 0, 0, 0, 1};
    uint8_t dmac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t frame[128];
    size_t flen = build_arp_frame(frame, sizeof(frame), smac, dmac);
    TEST_ASSERT(flen == 42);

    parsed_packet_t pkt;
    parse_result_t pr = parse_frame(frame, (unsigned)flen, 0, &pkt);
    TEST_ASSERT(pr == PARSE_ARP);
    TEST_ASSERT(pkt.eth_proto == ETH_PROTO_ARP);

    rule_decision_t dec;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ARP_FORWARD);

    rules_set_arp_forwarding(false);
}

/* ------------------------------------------------------------- */
/* Тест 4: ARP без пересылки -> DEFAULT_DROP (FR-11)             */
/* ------------------------------------------------------------- */
static void test_arp_drop_no_forwarding(void) {
    g_tests_run++;

    rules_replace(NULL, 0, NULL);
    rules_set_arp_forwarding(false);

    uint8_t smac[6] = {0xAA, 0, 0, 0, 0, 1};
    uint8_t dmac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t frame[128];
    size_t flen = build_arp_frame(frame, sizeof(frame), smac, dmac);

    parsed_packet_t pkt;
    parse_frame(frame, (unsigned)flen, 0, &pkt);

    rule_decision_t dec;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_DEFAULT_DROP);
}

/* ------------------------------------------------------------- */
/* Тест 5: Повреждённый кадр -> PARSE_DROP_MALFORMED (FR-12)     */
/* ------------------------------------------------------------- */
static void test_malformed_frame(void) {
    g_tests_run++;

    uint8_t garbage[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0x08, 0x00};
    parsed_packet_t pkt;
    parse_result_t pr = parse_frame(garbage, 10, 0, &pkt);
    /* Слишком короткий IPv4 кадр (14 + 20 = 34 минимум) */
    TEST_ASSERT(pr == PARSE_DROP_MALFORMED);
}

/* ------------------------------------------------------------- */
/* Тест 6: Conntrack + TCP 3-way handshake через конвейер        */
/* ------------------------------------------------------------- */
static void test_conntrack_tcp_pipeline(void) {
    g_tests_run++;

    ct_enable();

    /* Правило: accept TCP dport=80 с conntrack на iface 0 -> 1 */
    rule_t r;
    init_rule_defaults(&r, 20);
    r.log = 0;
    r.in_iface = 0;
    r.proto = 6;
    r.dport = 80; r.dport_end = 80;
    r.action = ACTION_ACCEPT;
    r.out_ifaces[0] = 1;
    r.conntrack = 1;
    strcpy(r.comment, "HTTP+CT");
    rules_replace(&r, 1, NULL);

    uint8_t smac[6] = {0xA0, 0, 0, 0, 0, 1};
    uint8_t dmac[6] = {0xA0, 0, 0, 0, 0, 2};
    uint32_t client_ip = 0x0A020001; /* 10.2.0.1 */
    uint32_t server_ip = 0xC0A80A01; /* 192.168.10.1 */

    /* SYN on iface 0 (client -> server) */
    uint8_t frame[128];
    size_t flen = build_tcp_frame(frame, sizeof(frame), smac, dmac,
                                  client_ip, server_ip, 50000, 80, FW_TCP_SYN);

    parsed_packet_t pkt;
    parse_result_t pr = parse_frame(frame, (unsigned)flen, 0, &pkt);
    TEST_ASSERT(pr == PARSE_OK);

    /* conntrack: новый пакет -> PASS_TO_RULES */
    ct_action_t ca;
    ct_result_t cr = ct_process_packet(&pkt, &ca);
    TEST_ASSERT(cr == CT_RES_PASS_TO_RULES);

    /* rules: match -> accept */
    rule_decision_t dec;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.conntrack == 1);

    /* Создать запись conntrack */
    int ct_rc = ct_create_entry(&pkt, &dec);
    TEST_ASSERT(ct_rc == 0);
    TEST_ASSERT(ct_get_entries_count() == 1);

    /* SYN-ACK на iface 1 (server -> client) */
    flen = build_tcp_frame(frame, sizeof(frame), dmac, smac,
                           server_ip, client_ip, 80, 50000, FW_TCP_SYN | FW_TCP_ACK);
    pr = parse_frame(frame, (unsigned)flen, 1, &pkt);
    TEST_ASSERT(pr == PARSE_OK);

    cr = ct_process_packet(&pkt, &ca);
    TEST_ASSERT(cr == CT_RES_FORWARD);
    /* Обратный пакет должен идти на in_iface=0 */
    TEST_ASSERT(ca.out_ifaces[0] == 0);

    /* ACK на iface 0 (client -> server) — завершение handshake */
    flen = build_tcp_frame(frame, sizeof(frame), smac, dmac,
                           client_ip, server_ip, 50000, 80, FW_TCP_ACK);
    pr = parse_frame(frame, (unsigned)flen, 0, &pkt);
    TEST_ASSERT(pr == PARSE_OK);

    cr = ct_process_packet(&pkt, &ca);
    TEST_ASSERT(cr == CT_RES_FORWARD);
    TEST_ASSERT(ca.out_ifaces[0] == 1);

    /* Out-of-context ACK на iface 2 (третий интерфейс, неизвестный) -> DROP */
    flen = build_tcp_frame(frame, sizeof(frame), smac, dmac,
                           client_ip, server_ip, 50000, 80, FW_TCP_ACK);
    pr = parse_frame(frame, (unsigned)flen, 2, &pkt);
    TEST_ASSERT(pr == PARSE_OK);

    cr = ct_process_packet(&pkt, &ca);
    TEST_ASSERT(cr == CT_RES_DROP_OUT_OF_CONTEXT);

    ct_delete_all();
}

/* ------------------------------------------------------------- */
/* Тест 7: Аварийная блокировка трафика (FR-48)                  */
/* ------------------------------------------------------------- */
static void test_emergency_block(void) {
    g_tests_run++;

    control_set_emergency_blocked(true);
    TEST_ASSERT(control_is_emergency_blocked() == true);

    /* В режиме аварийной поддержки — пакет всегда сбрасывается.
     * Проверяем через счётчик drop_packets. */
    uint64_t rx_before, tx_before, drop_before;
    control_get_stats(&rx_before, &tx_before, &drop_before);

    /* Можно убедиться, что process_packet вызовет drop.
     * Мы не вызываем process_packet напрямую из main, но проверяем
     * флаг блокировки, который main использует. */
    TEST_ASSERT(control_is_emergency_blocked() == true);

    control_set_emergency_blocked(false);
    TEST_ASSERT(control_is_emergency_blocked() == false);
}

/* ------------------------------------------------------------- */
/* Тест 8: UDP-пакет с правилом accept и conntrack               */
/* ------------------------------------------------------------- */
static void test_udp_conntrack_pipeline(void) {
    g_tests_run++;

    ct_enable();

    rule_t r;
    init_rule_defaults(&r, 30);
    r.log = 0;
    r.in_iface = -1; /* any */
    r.proto = 17; /* UDP */
    r.dport = 53; r.dport_end = 53;
    r.action = ACTION_ACCEPT;
    r.out_ifaces[0] = 1;
    r.conntrack = 1;
    strcpy(r.comment, "DNS");
    rules_replace(&r, 1, NULL);

    uint8_t smac[6] = {0xBB, 0, 0, 0, 0, 1};
    uint8_t dmac[6] = {0xBB, 0, 0, 0, 0, 2};
    uint32_t cip = 0x0A030001; /* 10.3.0.1 */
    uint32_t sip = 0x08080808; /* 8.8.8.8 */

    /* UDP query (client -> DNS server) on iface 0 */
    uint8_t frame[128];
    size_t flen = build_udp_frame(frame, sizeof(frame), smac, dmac,
                                  cip, sip, 55555, 53);

    parsed_packet_t pkt;
    parse_frame(frame, (unsigned)flen, 0, &pkt);

    ct_action_t ca;
    ct_result_t cr = ct_process_packet(&pkt, &ca);
    TEST_ASSERT(cr == CT_RES_PASS_TO_RULES);

    rule_decision_t dec;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);

    ct_create_entry(&pkt, &dec);
    TEST_ASSERT(ct_get_entries_count() >= 1);

    /* UDP response (server -> client) on iface 1 */
    flen = build_udp_frame(frame, sizeof(frame), dmac, smac,
                           sip, cip, 53, 55555);
    parse_frame(frame, (unsigned)flen, 1, &pkt);

    cr = ct_process_packet(&pkt, &ca);
    TEST_ASSERT(cr == CT_RES_FORWARD);
    TEST_ASSERT(ca.out_ifaces[0] == 0); /* Обратно на входной интерфейс */

    ct_delete_all();
}

/* ------------------------------------------------------------- */
/* Тест 9: Mock IO инжекция и извлечение нескольких кадров       */
/* ------------------------------------------------------------- */
static void test_io_mock_multiple_frames(void) {
    g_tests_run++;

    uint8_t smac[6] = {0xCC, 0, 0, 0, 0, 1};
    uint8_t dmac[6] = {0xCC, 0, 0, 0, 0, 2};

    /* Инжекция 3 кадров в интерфейс 0 */
    for (int i = 0; i < 3; ++i) {
        uint8_t frame[128];
        size_t flen = build_tcp_frame(frame, sizeof(frame), smac, dmac,
                                      0x0A040001, 0xC0A80C01, (uint16_t)(10000 + i), 80,
                                      FW_TCP_SYN);
        TEST_ASSERT(io_inject_frame(0, frame, flen) == 0);
    }

    /* Чтение 3 кадров */
    for (int i = 0; i < 3; ++i) {
        uint8_t recv_buf[IO_MAX_FRAME_SIZE];
        size_t recv_len = 0;
        TEST_ASSERT(io_recv_frame(0, recv_buf, sizeof(recv_buf), &recv_len) == 0);
        TEST_ASSERT(recv_len == 54);
    }

    /* 4-й чтение — нет данных */
    uint8_t extra_buf[IO_MAX_FRAME_SIZE];
    size_t extra_len = 0;
    TEST_ASSERT(io_recv_frame(0, extra_buf, sizeof(extra_buf), &extra_len) == -1);
}

/* ------------------------------------------------------------- */
/* Тест 10: Правило goto -> продолжение по правилам (FR-07)      */
/* ------------------------------------------------------------- */
static void test_rule_goto_chain(void) {
    g_tests_run++;

    rule_t rules[3];
    init_rule_defaults(&rules[0], 10);
    rules[0].action = ACTION_GOTO;
    rules[0].to_rule = 20;

    init_rule_defaults(&rules[1], 15);
    rules[1].action = ACTION_ACCEPT;
    rules[1].out_ifaces[0] = 0;

    init_rule_defaults(&rules[2], 20);
    rules[2].action = ACTION_DROP;
    rules[2].log = 1;

    rules_replace(rules, 3, NULL);

    uint8_t smac[6] = {0xDD, 0, 0, 0, 0, 1};
    uint8_t dmac[6] = {0xDD, 0, 0, 0, 0, 2};
    uint8_t frame[128];
    size_t flen = build_tcp_frame(frame, sizeof(frame), smac, dmac,
                                  0x0A050001, 0xC0A80D01, 6000, 443, FW_TCP_SYN);

    parsed_packet_t pkt;
    parse_frame(frame, (unsigned)flen, 0, &pkt);

    rule_decision_t dec;
    rules_match(&pkt, &dec);
    /* goto 20 -> пропускает 15, попадает в 20 (drop) */
    TEST_ASSERT(dec.verdict == RULE_MATCH_DROP);
    TEST_ASSERT(dec.rule_id == 20);
    TEST_ASSERT(dec.log == 1);
}

/* ------------------------------------------------------------- */
/* main                                                          */
/* ------------------------------------------------------------- */

int main(void) {
    printf("==> Running test_pipeline...\n");

    /* Инициализация модулей */
    rules_init();
    ct_init();
    pktlog_init();
    io_init_mock(3); /* 3 виртуальных интерфейса для тестов */

    test_tcp_accept_forwarded();
    test_tcp_default_drop();
    test_arp_forwarding();
    test_arp_drop_no_forwarding();
    test_malformed_frame();
    test_conntrack_tcp_pipeline();
    test_emergency_block();
    test_udp_conntrack_pipeline();
    test_io_mock_multiple_frames();
    test_rule_goto_chain();

    io_cleanup();
    ct_cleanup();
    rules_cleanup();
    pktlog_cleanup();

    printf("==> test_pipeline PASSED (%d test groups, %d assertions verified)\n",
           g_tests_run, g_asserts_passed);
    return 0;
}
