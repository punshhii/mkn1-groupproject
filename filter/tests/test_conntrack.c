/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      test_conntrack
 * Назначение:  модульные тесты контроля состояний соединений (conntrack)
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "conntrack.h"
#include "parser.h"
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

static void test_tcp_full_lifecycle(void)
{
    conntrack_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.tcp_syn_timeout_sec = 5;
    cfg.tcp_est_timeout_sec = 3600;
    cfg.tcp_fin_timeout_sec = 30;
    cfg.state_table_size = 1024;
    cfg.conntrack_enabled = true;

    TEST_ASSERT(ct_init_config(&cfg) == 0);

    /* 1. Прямой SYN от клиента */
    parsed_packet_t syn_pkt;
    memset(&syn_pkt, 0, sizeof(syn_pkt));
    syn_pkt.in_iface = 1;
    syn_pkt.eth_type = 0x0800;
    syn_pkt.ip_proto = 6;
    syn_pkt.src_ip = 0x0A000001U; /* 10.0.0.1 */
    syn_pkt.dst_ip = 0xC0A80101U; /* 192.168.1.1 */
    syn_pkt.sport = 10000;
    syn_pkt.dport = 80;
    syn_pkt.tcp_flags = FW_TCP_SYN;

    ct_action_t act;
    /* Должен вернуть PASS_TO_RULES, так как сессии ещё нет */
    TEST_ASSERT(ct_process_packet(&syn_pkt, &act) == CT_RES_PASS_TO_RULES);

    /* Модуль правил разрешил пакет и запросил conntrack */
    rule_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.verdict = RULE_MATCH_ACCEPT;
    dec.rule_id = 10;
    dec.log = 1;
    dec.conntrack = 1;
    dec.out_count = 1;
    dec.out_ifaces[0] = 2;
    dec.out_ifaces[1] = -1;

    TEST_ASSERT(ct_create_entry(&syn_pkt, &dec) == 0);
    TEST_ASSERT(ct_get_entries_count() == 1);

    /* 2. Сервер отвечает SYN-ACK на порт 2 */
    parsed_packet_t synack_pkt;
    memset(&synack_pkt, 0, sizeof(synack_pkt));
    synack_pkt.in_iface = 2;
    synack_pkt.eth_type = 0x0800;
    synack_pkt.ip_proto = 6;
    synack_pkt.src_ip = 0xC0A80101U;
    synack_pkt.dst_ip = 0x0A000001U;
    synack_pkt.sport = 80;
    synack_pkt.dport = 10000;
    synack_pkt.tcp_flags = FW_TCP_SYN | FW_TCP_ACK;

    TEST_ASSERT(ct_process_packet(&synack_pkt, &act) == CT_RES_FORWARD);
    TEST_ASSERT(act.out_count == 1);
    TEST_ASSERT(act.out_ifaces[0] == 1); /* Пересылается на входной интерфейс */
    TEST_ASSERT(act.rule_id == 10);

    /* 3. Клиент подтверждает ACK */
    parsed_packet_t ack_pkt;
    memset(&ack_pkt, 0, sizeof(ack_pkt));
    ack_pkt.in_iface = 1;
    ack_pkt.eth_type = 0x0800;
    ack_pkt.ip_proto = 6;
    ack_pkt.src_ip = 0x0A000001U;
    ack_pkt.dst_ip = 0xC0A80101U;
    ack_pkt.sport = 10000;
    ack_pkt.dport = 80;
    ack_pkt.tcp_flags = FW_TCP_ACK;

    TEST_ASSERT(ct_process_packet(&ack_pkt, &act) == CT_RES_FORWARD);
    TEST_ASSERT(act.out_count == 1);
    TEST_ASSERT(act.out_ifaces[0] == 2);

    /* Состояние должно стать ESTABLISHED */
    ct_entry_info_t info[2];
    TEST_ASSERT(ct_dump_entries(info, 2) == 1);
    TEST_ASSERT(info[0].state == CT_TCP_ESTABLISHED);

    /* 4. Трафик данных */
    ack_pkt.tcp_flags = FW_TCP_ACK | FW_TCP_PSH;
    TEST_ASSERT(ct_process_packet(&ack_pkt, &act) == CT_RES_FORWARD);
    TEST_ASSERT(act.out_ifaces[0] == 2);

    /* 5. Завершение сессии FIN */
    ack_pkt.tcp_flags = FW_TCP_FIN | FW_TCP_ACK;
    TEST_ASSERT(ct_process_packet(&ack_pkt, &act) == CT_RES_FORWARD);
    TEST_ASSERT(ct_dump_entries(info, 2) == 1);
    TEST_ASSERT(info[0].state == CT_TCP_FIN_WAIT);

    ct_cleanup();
}

static void test_tcp_rst_closure(void)
{
    TEST_ASSERT(ct_init() == 0);

    /* Устанавливаем сессию */
    parsed_packet_t syn;
    memset(&syn, 0, sizeof(syn));
    syn.in_iface = 1;
    syn.eth_type = 0x0800;
    syn.ip_proto = 6;
    syn.src_ip = 0x0A000001U;
    syn.dst_ip = 0xC0A80101U;
    syn.sport = 20000;
    syn.dport = 80;
    syn.tcp_flags = FW_TCP_SYN;

    rule_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.verdict = RULE_MATCH_ACCEPT;
    dec.rule_id = 5;
    dec.out_count = 1;
    dec.out_ifaces[0] = 2;

    ct_create_entry(&syn, &dec);

    /* SYN-ACK */
    parsed_packet_t synack = syn;
    synack.in_iface = 2;
    synack.src_ip = syn.dst_ip;
    synack.dst_ip = syn.src_ip;
    synack.sport = syn.dport;
    synack.dport = syn.sport;
    synack.tcp_flags = FW_TCP_SYN | FW_TCP_ACK;
    ct_action_t act;
    ct_process_packet(&synack, &act);

    /* ACK -> ESTABLISHED */
    parsed_packet_t ack = syn;
    ack.tcp_flags = FW_TCP_ACK;
    ct_process_packet(&ack, &act);
    TEST_ASSERT(ct_get_entries_count() == 1);

    /* RST в ESTABLISHED: закрывает соединение и удаляет запись (FR-16) */
    parsed_packet_t rst = syn;
    rst.tcp_flags = FW_TCP_RST;
    TEST_ASSERT(ct_process_packet(&rst, &act) == CT_RES_FORWARD);
    TEST_ASSERT(ct_get_entries_count() == 0); /* Запись удалена */

    /* Следующий пакет соединения уже не находит сессию */
    TEST_ASSERT(ct_process_packet(&ack, &act) == CT_RES_DROP_OUT_OF_CONTEXT);

    ct_cleanup();
}

static void test_tcp_invalid_flags_out_of_context(void)
{
    TEST_ASSERT(ct_init() == 0);

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.in_iface = 1;
    pkt.eth_type = 0x0800;
    pkt.ip_proto = 6;
    pkt.src_ip = 0x0A000002U;
    pkt.dst_ip = 0xC0A80102U;
    pkt.sport = 30000;
    pkt.dport = 443;

    ct_action_t act;

    /* 1. SYN-ACK без SYN вне контекста -> DROP (FR-16, FR-22) */
    pkt.tcp_flags = FW_TCP_SYN | FW_TCP_ACK;
    TEST_ASSERT(ct_process_packet(&pkt, &act) == CT_RES_DROP_OUT_OF_CONTEXT);

    /* 2. ACK без соединения вне контекста -> DROP */
    pkt.tcp_flags = FW_TCP_ACK;
    TEST_ASSERT(ct_process_packet(&pkt, &act) == CT_RES_DROP_OUT_OF_CONTEXT);

    /* 3. RST вне соединения -> DROP */
    pkt.tcp_flags = FW_TCP_RST;
    TEST_ASSERT(ct_process_packet(&pkt, &act) == CT_RES_DROP_OUT_OF_CONTEXT);

    /* 4. FIN вне соединения -> DROP */
    pkt.tcp_flags = FW_TCP_FIN;
    TEST_ASSERT(ct_process_packet(&pkt, &act) == CT_RES_DROP_OUT_OF_CONTEXT);

    ct_cleanup();
}

static void test_interface_verification(void)
{
    TEST_ASSERT(ct_init() == 0);

    parsed_packet_t syn;
    memset(&syn, 0, sizeof(syn));
    syn.in_iface = 1;
    syn.eth_type = 0x0800;
    syn.ip_proto = 6;
    syn.src_ip = 0x0A000003U;
    syn.dst_ip = 0xC0A80103U;
    syn.sport = 40000;
    syn.dport = 80;
    syn.tcp_flags = FW_TCP_SYN;

    rule_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.verdict = RULE_MATCH_ACCEPT;
    dec.rule_id = 15;
    dec.log = 1;
    dec.out_count = 1;
    dec.out_ifaces[0] = 2; /* Выходной порт 2 */

    ct_create_entry(&syn, &dec);

    ct_action_t act;

    /* Прямой пакет пришёл на порт 3 вместо порта 1 (FR-15: блокировка) */
    syn.in_iface = 3;
    TEST_ASSERT(ct_process_packet(&syn, &act) == CT_RES_DROP_OUT_OF_CONTEXT);
    TEST_ASSERT(act.rule_id == 15);
    TEST_ASSERT(act.rule_log == 1);

    /* Обратный пакет пришёл на порт 1 вместо порта 2 (FR-15: блокировка) */
    parsed_packet_t rev = syn;
    rev.in_iface = 1;
    rev.src_ip = syn.dst_ip;
    rev.dst_ip = syn.src_ip;
    rev.sport = syn.dport;
    rev.dport = syn.sport;
    rev.tcp_flags = FW_TCP_SYN | FW_TCP_ACK;
    TEST_ASSERT(ct_process_packet(&rev, &act) == CT_RES_DROP_OUT_OF_CONTEXT);

    ct_cleanup();
}

static void test_udp_state_machine(void)
{
    TEST_ASSERT(ct_init() == 0);

    /* 1. Первый UDP пакет */
    parsed_packet_t udp1;
    memset(&udp1, 0, sizeof(udp1));
    udp1.in_iface = 1;
    udp1.eth_type = 0x0800;
    udp1.ip_proto = 17;
    udp1.src_ip = 0x0A000005U;
    udp1.dst_ip = 0xC0A80105U;
    udp1.sport = 5353;
    udp1.dport = 53;

    ct_action_t act;
    TEST_ASSERT(ct_process_packet(&udp1, &act) == CT_RES_PASS_TO_RULES);

    rule_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.verdict = RULE_MATCH_ACCEPT;
    dec.rule_id = 33;
    dec.out_count = 1;
    dec.out_ifaces[0] = 2;

    TEST_ASSERT(ct_create_entry(&udp1, &dec) == 0);

    ct_entry_info_t info[2];
    TEST_ASSERT(ct_dump_entries(info, 2) == 1);
    TEST_ASSERT(info[0].state == CT_UDP_UNREPLIED);

    /* 2. Обратный UDP пакет */
    parsed_packet_t udp_rev = udp1;
    udp_rev.in_iface = 2;
    udp_rev.src_ip = udp1.dst_ip;
    udp_rev.dst_ip = udp1.src_ip;
    udp_rev.sport = udp1.dport;
    udp_rev.dport = udp1.sport;

    TEST_ASSERT(ct_process_packet(&udp_rev, &act) == CT_RES_FORWARD);
    TEST_ASSERT(act.out_count == 1);
    TEST_ASSERT(act.out_ifaces[0] == 1);

    /* Состояние перешло в REPLIED */
    TEST_ASSERT(ct_dump_entries(info, 2) == 1);
    TEST_ASSERT(info[0].state == CT_UDP_REPLIED);

    ct_cleanup();
}

static void test_icmp_echo_state_machine(void)
{
    TEST_ASSERT(ct_init() == 0);

    /* 1. Echo Reply без Request вне соединения -> блокировка (FR-18) */
    parsed_packet_t reply_no_req;
    memset(&reply_no_req, 0, sizeof(reply_no_req));
    reply_no_req.in_iface = 2;
    reply_no_req.eth_type = 0x0800;
    reply_no_req.ip_proto = 1;
    reply_no_req.icmp_type = 0; /* Echo Reply */
    reply_no_req.icmp_id = 0xABCD;

    ct_action_t act;
    TEST_ASSERT(ct_process_packet(&reply_no_req, &act) == CT_RES_DROP_OUT_OF_CONTEXT);

    /* 2. Echo Request */
    parsed_packet_t req;
    memset(&req, 0, sizeof(req));
    req.in_iface = 1;
    req.eth_type = 0x0800;
    req.ip_proto = 1;
    req.src_ip = 0x0A000009U;
    req.dst_ip = 0xC0A80109U;
    req.icmp_type = 8; /* Echo Request */
    req.icmp_id = 0xABCD;

    TEST_ASSERT(ct_process_packet(&req, &act) == CT_RES_PASS_TO_RULES);

    rule_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.verdict = RULE_MATCH_ACCEPT;
    dec.rule_id = 50;
    dec.out_count = 1;
    dec.out_ifaces[0] = 2;

    TEST_ASSERT(ct_create_entry(&req, &dec) == 0);

    /* 3. Echo Reply с тем же ID на выходной интерфейс разрешается */
    parsed_packet_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.in_iface = 2;
    reply.eth_type = 0x0800;
    reply.ip_proto = 1;
    reply.src_ip = req.dst_ip;
    reply.dst_ip = req.src_ip;
    reply.icmp_type = 0;
    reply.icmp_id = 0xABCD;

    TEST_ASSERT(ct_process_packet(&reply, &act) == CT_RES_FORWARD);
    TEST_ASSERT(act.out_count == 1);
    TEST_ASSERT(act.out_ifaces[0] == 1);

    ct_cleanup();
}

static void test_timeouts_and_purges(void)
{
    TEST_ASSERT(ct_init() == 0);

    /* Создаем 3 сессии: две от правила 10, одну от правила 20 */
    rule_decision_t dec10;
    memset(&dec10, 0, sizeof(dec10));
    dec10.rule_id = 10;
    dec10.out_count = 1;
    dec10.out_ifaces[0] = 2;

    rule_decision_t dec20 = dec10;
    dec20.rule_id = 20;

    parsed_packet_t p1;
    memset(&p1, 0, sizeof(p1));
    p1.in_iface = 1;
    p1.eth_type = 0x0800;
    p1.ip_proto = 17;
    p1.src_ip = 0x0A000001U;
    p1.dst_ip = 0xC0A80101U;
    p1.sport = 1111;
    p1.dport = 2222;
    ct_create_entry(&p1, &dec10);

    parsed_packet_t p2 = p1;
    p2.sport = 3333;
    ct_create_entry(&p2, &dec10);

    parsed_packet_t p3 = p1;
    p3.sport = 4444;
    ct_create_entry(&p3, &dec20);

    TEST_ASSERT(ct_get_entries_count() == 3);

    /* Очистка записей правила 10 (FR-23) */
    rule_id_t purge_ids[1] = {10};
    uint32_t removed = ct_purge_by_rule_ids(purge_ids, 1);
    TEST_ASSERT(removed == 2);
    TEST_ASSERT(ct_get_entries_count() == 1);

    /* Оставшаяся сессия принадлежит правилу 20 */
    ct_entry_info_t info[2];
    ct_dump_entries(info, 2);
    TEST_ASSERT(info[0].rule_id == 20);

    /* Удаление по ID (FR-21) */
    TEST_ASSERT(ct_delete_entry(info[0].conn_id) == 0);
    TEST_ASSERT(ct_get_entries_count() == 0);

    ct_cleanup();
}

static void test_disable_and_clear(void)
{
    TEST_ASSERT(ct_init() == 0);
    TEST_ASSERT(ct_is_enabled());

    /* Создаем сессию */
    parsed_packet_t p;
    memset(&p, 0, sizeof(p));
    p.in_iface = 1;
    p.eth_type = 0x0800;
    p.ip_proto = 17;
    p.sport = 1234;

    rule_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.rule_id = 1;
    dec.out_count = 1;
    dec.out_ifaces[0] = 2;
    ct_create_entry(&p, &dec);
    TEST_ASSERT(ct_get_entries_count() == 1);

    /* Отключаем conntrack (FR-20) -> таблица очищается */
    ct_disable();
    TEST_ASSERT(!ct_is_enabled());
    TEST_ASSERT(ct_get_entries_count() == 0);

    /* При отключенном conntrack любой пакет уходит в rules */
    ct_action_t act;
    TEST_ASSERT(ct_process_packet(&p, &act) == CT_RES_PASS_TO_RULES);

    ct_cleanup();
}

int main(void)
{
    printf("Running conntrack tests...\n");

    test_tcp_full_lifecycle();
    test_tcp_rst_closure();
    test_tcp_invalid_flags_out_of_context();
    test_interface_verification();
    test_udp_state_machine();
    test_icmp_echo_state_machine();
    test_timeouts_and_purges();
    test_disable_and_clear();

    printf("ALL CONNTRACK TESTS PASSED (%d/%d checks passed)\n", tests_passed, tests_run);
    return 0;
}
