/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      test_rules
 * Назначение:  модульные тесты движка правил фильтрации (rules)
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "io.h"
#include "parser.h"
#include "rules.h"
#include "net_utils.h"

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

static void init_rule_defaults(rule_t *r, rule_id_t id)
{
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

static void test_empty_table(void)
{
    rules_init();

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.eth_type = 0x0800;
    pkt.src_ip = 0x0A000001U;
    pkt.dst_ip = 0xC0A80101U;

    rule_decision_t dec;
    rules_match(&pkt, &dec);

    /* FR-08: отсутствие правил приводит к drop с rule_id = 0 */
    TEST_ASSERT(dec.verdict == RULE_MATCH_DEFAULT_DROP);
    TEST_ASSERT(dec.rule_id == 0);
    TEST_ASSERT(dec.log == 0);

    rules_cleanup();
}

static void test_ip_matches(void)
{
    rules_init();

    rule_t r[3];
    /* Правило 10: точный IP 192.168.1.50 -> accept out=[1] */
    init_rule_defaults(&r[0], 10);
    r[0].src = 0xC0A80132U;
    r[0].src_end = r[0].src;
    r[0].action = ACTION_ACCEPT;
    r[0].out_ifaces[0] = 1;

    /* Правило 20: подсеть CIDR /24 10.0.0.0/24 -> accept out=[2] */
    init_rule_defaults(&r[1], 20);
    r[1].src = 0x0A000000U;
    r[1].src_mask = 0xFFFFFF00U;
    r[1].src_end = r[1].src;
    r[1].action = ACTION_ACCEPT;
    r[1].out_ifaces[0] = 2;

    /* Правило 30: диапазон 172.16.1.10 - 172.16.1.20 -> accept out=[3] */
    init_rule_defaults(&r[2], 30);
    r[2].src = 0xAC10010AU;
    r[2].src_end = 0xAC100114U;
    r[2].action = ACTION_ACCEPT;
    r[2].out_ifaces[0] = 3;

    TEST_ASSERT(rules_replace(r, 3, NULL) == 0);

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.eth_type = 0x0800;
    rule_decision_t dec;

    /* 1. Точный IP */
    pkt.src_ip = 0xC0A80132U;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.rule_id == 10);
    TEST_ASSERT(dec.out_ifaces[0] == 1);

    /* 2. CIDR /24 */
    pkt.src_ip = 0x0A0000C8U; /* 10.0.0.200 */
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.rule_id == 20);
    TEST_ASSERT(dec.out_ifaces[0] == 2);

    /* 3. Диапазон */
    pkt.src_ip = 0xAC10010FU; /* 172.16.1.15 */
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.rule_id == 30);
    TEST_ASSERT(dec.out_ifaces[0] == 3);

    /* Непопадание в диапазон */
    pkt.src_ip = 0xAC100115U; /* 172.16.1.21 */
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_DEFAULT_DROP);
    TEST_ASSERT(dec.rule_id == 0);

    rules_cleanup();
}

static void test_port_and_mac_matches(void)
{
    rules_init();

    rule_t r[2];
    /* Правило 5: MAC-адрес источника + TCP dport 80 */
    init_rule_defaults(&r[0], 5);
    r[0].smac = 0x001122334455ULL;
    r[0].proto = 6; /* TCP */
    r[0].dport = 80;
    r[0].action = ACTION_ACCEPT;
    r[0].out_ifaces[0] = 1;

    /* Правило 15: диапазон портов 1024..2048 UDP */
    init_rule_defaults(&r[1], 15);
    r[1].proto = 17; /* UDP */
    r[1].dport = 1024;
    r[1].dport_end = 2048;
    r[1].action = ACTION_ACCEPT;
    r[1].out_ifaces[0] = 2;

    TEST_ASSERT(rules_replace(r, 2, NULL) == 0);

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.eth_type = 0x0800;
    pkt.smac = 0x001122334455ULL;
    pkt.ip_proto = 6;
    pkt.dport = 80;

    rule_decision_t dec;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.rule_id == 5);

    /* Неверный MAC */
    pkt.smac = 0x00AABBCCDDEEULL;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_DEFAULT_DROP);

    /* UDP порт из диапазона */
    pkt.ip_proto = 17;
    pkt.dport = 1500;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.rule_id == 15);

    rules_cleanup();
}

static void test_icmp_match(void)
{
    rules_init();

    rule_t r;
    init_rule_defaults(&r, 1);
    r.proto = 1; /* ICMP */
    r.icmp_type = 8; /* Echo Request */
    r.icmp_code = 0;
    r.action = ACTION_ACCEPT;
    r.out_ifaces[0] = 0;

    TEST_ASSERT(rules_replace(&r, 1, NULL) == 0);

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.eth_type = 0x0800;
    pkt.ip_proto = 1;
    pkt.icmp_type = 8;
    pkt.icmp_code = 0;

    rule_decision_t dec;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.rule_id == 1);

    /* Echo Reply (type 0) не совпадает */
    pkt.icmp_type = 0;
    rules_match(&pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_DEFAULT_DROP);

    rules_cleanup();
}

static void test_first_match_and_inactive(void)
{
    rules_init();

    rule_t r[3];
    /* Правило 10: неактивно, accept out=[1] */
    init_rule_defaults(&r[0], 10);
    r[0].active = 0; /* Неактивно */
    r[0].action = ACTION_ACCEPT;
    r[0].out_ifaces[0] = 1;

    /* Правило 20: активно, drop */
    init_rule_defaults(&r[1], 20);
    r[1].active = 1;
    r[1].action = ACTION_DROP;

    /* Правило 30: активно, accept out=[2] */
    init_rule_defaults(&r[2], 30);
    r[2].active = 1;
    r[2].action = ACTION_ACCEPT;
    r[2].out_ifaces[0] = 2;

    TEST_ASSERT(rules_replace(r, 3, NULL) == 0);

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.eth_type = 0x0800;

    rule_decision_t dec;
    rules_match(&pkt, &dec);

    /* FR-06: правило 10 пропущено, первое сработавшее — правило 20 (drop) */
    TEST_ASSERT(dec.verdict == RULE_MATCH_DROP);
    TEST_ASSERT(dec.rule_id == 20);

    rules_cleanup();
}

static void test_goto_action(void)
{
    rules_init();

    rule_t r[4];
    /* Правило 10: goto 30 */
    init_rule_defaults(&r[0], 10);
    r[0].action = ACTION_GOTO;
    r[0].to_rule = 30;

    /* Правило 20: drop (должно быть пропущено благодаря goto) */
    init_rule_defaults(&r[1], 20);
    r[1].action = ACTION_DROP;

    /* Правило 30: не подошло по условию (in_iface = 1, а в пакете 0) */
    init_rule_defaults(&r[2], 30);
    r[2].in_iface = 1;
    r[2].action = ACTION_DROP;

    /* Правило 40: accept out=[0] */
    init_rule_defaults(&r[3], 40);
    r[3].action = ACTION_ACCEPT;
    r[3].out_ifaces[0] = 0;

    TEST_ASSERT(rules_replace(r, 4, NULL) == 0);

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.eth_type = 0x0800;
    pkt.in_iface = 0;

    rule_decision_t dec;
    rules_match(&pkt, &dec);

    /* Переход к 30, 30 не подошло -> продолжается к 40 */
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.rule_id == 40);

    rule_t active[4];
    rules_get_active(active, 4);
    TEST_ASSERT(active[0].hits == 1); /* Правило 10 (goto) сработало */
    TEST_ASSERT(active[1].hits == 0); /* Правило 20 перешагнули */
    TEST_ASSERT(active[2].hits == 0); /* Правило 30 не подошло */
    TEST_ASSERT(active[3].hits == 1); /* Правило 40 разрешило */

    rules_cleanup();
}

static void test_rules_validation(void)
{
    const char *err = NULL;

    /* 1. Неупорядоченные ID */
    rule_t r_bad_order[2];
    init_rule_defaults(&r_bad_order[0], 20);
    init_rule_defaults(&r_bad_order[1], 10);
    TEST_ASSERT(rules_validate(r_bad_order, 2, &err) != 0);

    /* 2. Дублирующийся ID */
    rule_t r_dup[2];
    init_rule_defaults(&r_dup[0], 10);
    init_rule_defaults(&r_dup[1], 10);
    TEST_ASSERT(rules_validate(r_dup, 2, &err) != 0);

    /* 3. in_iface входит в out_ifaces (FR-13) */
    rule_t r_loop;
    init_rule_defaults(&r_loop, 1);
    r_loop.in_iface = 2;
    r_loop.action = ACTION_ACCEPT;
    r_loop.out_ifaces[0] = 1;
    r_loop.out_ifaces[1] = 2; /* Ошибка: входной интерфейс в выходных */
    TEST_ASSERT(rules_validate(&r_loop, 1, &err) != 0);

    /* 4. goto на самого себя или меньший номер (FR-13) */
    rule_t r_goto_self;
    init_rule_defaults(&r_goto_self, 10);
    r_goto_self.action = ACTION_GOTO;
    r_goto_self.to_rule = 10;
    TEST_ASSERT(rules_validate(&r_goto_self, 1, &err) != 0);

    /* 5. goto на несуществующее правило (FR-13) */
    rule_t r_goto_none;
    init_rule_defaults(&r_goto_none, 10);
    r_goto_none.action = ACTION_GOTO;
    r_goto_none.to_rule = 99;
    TEST_ASSERT(rules_validate(&r_goto_none, 1, &err) != 0);
}

static void test_mgmt_interface_validation(void)
{
    io_init_mock(3);
    /* mock0 - транзитный, mock1 - управляющий (is_mgmt), mock2 - транзитный */
    io_set_iface_mgmt(1, true);

    TEST_ASSERT(io_is_mgmt_iface(1) == true);
    TEST_ASSERT(io_is_mgmt_iface(0) == false);
    TEST_ASSERT(io_is_mgmt_iface(2) == false);

    /* 1. Проверка, что управляющий интерфейс не открывается (дескриптор == -1) */
    TEST_ASSERT(io_get_fd(1) == -1);
    TEST_ASSERT(io_get_fd(0) >= 0);
    TEST_ASSERT(io_get_fd(2) >= 0);

    const char *err = NULL;

    /* 2. Правило с in_iface = управляющий интерфейс (1) отклоняется с M06 */
    rule_t r_mgmt_in;
    init_rule_defaults(&r_mgmt_in, 10);
    r_mgmt_in.in_iface = 1;
    r_mgmt_in.action = ACTION_DROP;
    TEST_ASSERT(rules_validate(&r_mgmt_in, 1, &err) != 0);
    TEST_ASSERT(err != NULL && strcmp(err, "M06") == 0);

    /* 3. Правило с out_ifaces, содержащим управляющий интерфейс (1), отклоняется с M06 */
    rule_t r_mgmt_out;
    init_rule_defaults(&r_mgmt_out, 20);
    r_mgmt_out.in_iface = 0;
    r_mgmt_out.action = ACTION_ACCEPT;
    r_mgmt_out.out_ifaces[0] = 1; /* Ошибка: управляющий интерфейс в out_ifaces */
    TEST_ASSERT(rules_validate(&r_mgmt_out, 1, &err) != 0);
    TEST_ASSERT(err != NULL && strcmp(err, "M06") == 0);

    /* 4. Правило с транзитными интерфейсами (in=0, out=[2]) успешно валидируется */
    rule_t r_valid;
    init_rule_defaults(&r_valid, 30);
    r_valid.in_iface = 0;
    r_valid.action = ACTION_ACCEPT;
    r_valid.out_ifaces[0] = 2;
    TEST_ASSERT(rules_validate(&r_valid, 1, &err) == 0);

    io_cleanup();
}

static void test_arp_and_other_eth(void)
{
    rules_init();
    rules_set_arp_forwarding(true); /* ARP пересылка включена */

    parsed_packet_t arp_pkt;
    memset(&arp_pkt, 0, sizeof(arp_pkt));
    arp_pkt.eth_proto = ETH_PROTO_ARP;

    rule_decision_t dec;

    /* 1. Нет правил, пересылка ARP включена -> RULE_MATCH_ARP_FORWARD */
    rules_match(&arp_pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ARP_FORWARD);

    /* 2. Отключаем пересылку ARP -> RULE_MATCH_DEFAULT_DROP */
    rules_set_arp_forwarding(false);
    rules_match(&arp_pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_DEFAULT_DROP);

    /* 3. Правило для eth-proto=arp action=accept */
    rule_t r_arp;
    init_rule_defaults(&r_arp, 1);
    r_arp.eth_proto = ETH_PROTO_ARP;
    r_arp.action = ACTION_ACCEPT;
    r_arp.out_ifaces[0] = 1;
    TEST_ASSERT(rules_replace(&r_arp, 1, NULL) == 0);

    rules_match(&arp_pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_ACCEPT);
    TEST_ASSERT(dec.rule_id == 1);

    /* 4. IPv6 (eth-proto=other) */
    parsed_packet_t ipv6_pkt;
    memset(&ipv6_pkt, 0, sizeof(ipv6_pkt));
    ipv6_pkt.eth_proto = ETH_PROTO_OTHER;

    rules_match(&ipv6_pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_DEFAULT_DROP);

    rule_t r_other;
    init_rule_defaults(&r_other, 2);
    r_other.eth_proto = ETH_PROTO_OTHER;
    r_other.action = ACTION_DROP;
    TEST_ASSERT(rules_replace(&r_other, 1, NULL) == 0);

    rules_match(&ipv6_pkt, &dec);
    TEST_ASSERT(dec.verdict == RULE_MATCH_DROP);
    TEST_ASSERT(dec.rule_id == 2);

    rules_cleanup();
}

static void test_hits_preservation_and_modified_rules(void)
{
    rules_init();

    rule_t old_r[2];
    init_rule_defaults(&old_r[0], 10);
    old_r[0].action = ACTION_ACCEPT;
    old_r[0].out_ifaces[0] = 1;

    init_rule_defaults(&old_r[1], 20);
    old_r[1].action = ACTION_DROP;

    TEST_ASSERT(rules_replace(old_r, 2, NULL) == 0);

    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.eth_type = 0x0800;

    rule_decision_t dec;
    /* Генерируем 5 срабатываний правила 10 */
    for (int i = 0; i < 5; i++) {
        rules_match(&pkt, &dec);
    }

    rule_t cur[2];
    rules_get_active(cur, 2);
    TEST_ASSERT(cur[0].hits == 5);

    /* Заменяем таблицу: правило 10 сохраняется без изменений, правило 20 удаляется, добавляется 30 */
    rule_t new_r[2];
    init_rule_defaults(&new_r[0], 10);
    new_r[0].action = ACTION_ACCEPT;
    new_r[0].out_ifaces[0] = 1;

    init_rule_defaults(&new_r[1], 30);
    new_r[1].action = ACTION_DROP;

    rule_id_list_t modified;
    TEST_ASSERT(rules_replace(new_r, 2, &modified) == 0);

    /* Проверяем, что hits правила 10 сохранились */
    rule_t updated[2];
    rules_get_active(updated, 2);
    TEST_ASSERT(updated[0].id == 10);
    TEST_ASSERT(updated[0].hits == 5);

    /* Проверяем, что удалённое правило 20 попало в список модифицированных (FR-23) */
    TEST_ASSERT(modified.count == 1);
    TEST_ASSERT(modified.ids[0] == 20);

    rules_cleanup();
}

int main(void)
{
    printf("Running rules engine tests...\n");

    test_empty_table();
    test_ip_matches();
    test_port_and_mac_matches();
    test_icmp_match();
    test_first_match_and_inactive();
    test_goto_action();
    test_rules_validation();
    test_mgmt_interface_validation();
    test_arp_and_other_eth();
    test_hits_preservation_and_modified_rules();

    printf("ALL RULES TESTS PASSED (%d/%d checks passed)\n", tests_passed, tests_run);
    return 0;
}
