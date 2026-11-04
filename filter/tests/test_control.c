/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      test_control
 * Назначение:  модульные тесты сервера управления и диспетчера IPC-команд
 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "control.h"
#include "conntrack.h"
#include "io.h"
#include "json_utils.h"
#include "parser.h"
#include "pktlog_client.h"
#include "rules.h"

#define TEST_SOCK_PATH       "/tmp/test_fw_filter.sock"
#define TEST_LOGD_SOCK_PATH  "/tmp/test_fw_logd.sock"

static int g_tests_run = 0;
static int g_asserts_passed = 0;

#define TEST_ASSERT(cond) do { \
    g_asserts_passed++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: assertion failed: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

/* Вспомогательный обмен запрос/ответ через Unix-сокет */
static char *client_exchange(const char *sock_path, const char *req_json) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return NULL;
    }

    size_t req_len = strlen(req_json);
    if (send(fd, req_json, req_len, 0) != (ssize_t)req_len) {
        close(fd);
        return NULL;
    }
    if (send(fd, "\n", 1, 0) != 1) {
        close(fd);
        return NULL;
    }

    /* Обработать запрос на сервере */
    control_process();

    char buf[16384];
    ssize_t r = recv(fd, buf, sizeof(buf) - 1, 0);
    close(fd);

    if (r <= 0) return NULL;
    buf[r] = '\0';
    return strdup(buf);
}

/* -------------------------------------------------------------
 * Тест: JSON парсер и построитель
 * ------------------------------------------------------------- */
static void test_json_parser_basic(void) {
    g_tests_run++;
    char err[64];
    const char *jstr = "{\"num\": 42, \"str\": \"hello\\nworld\", \"bool\": true, \"arr\": [1, 2, 3], \"null_val\": null}";
    json_value_t *val = json_parse(jstr, err, sizeof(err));
    TEST_ASSERT(val != NULL);
    TEST_ASSERT(json_obj_get_int(val, "num", 0) == 42);
    TEST_ASSERT(strcmp(json_obj_get_str(val, "str", ""), "hello\nworld") == 0);
    TEST_ASSERT(json_obj_get_bool(val, "bool", false) == true);

    const json_value_t *arr = json_obj_get(val, "arr");
    TEST_ASSERT(arr != NULL);
    TEST_ASSERT(json_arr_len(arr) == 3);

    const json_value_t *elem1 = json_arr_get(arr, 0);
    TEST_ASSERT(elem1 && elem1->type == JSON_TYPE_NUMBER && elem1->u.num_val == 1.0);

    const json_value_t *nv = json_obj_get(val, "null_val");
    TEST_ASSERT(nv && nv->type == JSON_TYPE_NULL);

    json_free(val);
}

/* -------------------------------------------------------------
 * Тест: Сериализация и десериализация правил в JSON
 * ------------------------------------------------------------- */
static void test_rule_json_roundtrip(void) {
    g_tests_run++;
    const char *r_json = "{"
        "\"id\": 10,"
        "\"active\": true,"
        "\"log\": true,"
        "\"in_iface\": 0,"
        "\"smac\": null,"
        "\"dmac\": null,"
        "\"src\": \"10.0.0.0/24\","
        "\"dst\": \"192.168.1.1\","
        "\"proto\": \"tcp\","
        "\"eth_proto\": \"any\","
        "\"sport\": \"1024-65535\","
        "\"dport\": 80,"
        "\"icmp_type\": null,"
        "\"icmp_code\": null,"
        "\"action\": \"accept\","
        "\"out_ifaces\": [1, 2],"
        "\"to_rule\": null,"
        "\"conntrack\": true,"
        "\"comment\": \"Allow Web\","
        "\"hits\": 15"
    "}";

    json_value_t *val = json_parse(r_json, NULL, 0);
    TEST_ASSERT(val != NULL);

    rule_t rule;
    int rc = json_parse_rule(val, &rule);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(rule.id == 10);
    TEST_ASSERT(rule.active == 1);
    TEST_ASSERT(rule.log == 1);
    TEST_ASSERT(rule.in_iface == 0);
    TEST_ASSERT(rule.proto == 6);
    TEST_ASSERT(rule.sport == 1024 && rule.sport_end == 65535);
    TEST_ASSERT(rule.dport == 80 && rule.dport_end == 80);
    TEST_ASSERT(rule.action == ACTION_ACCEPT);
    TEST_ASSERT(rule.out_ifaces[0] == 1 && rule.out_ifaces[1] == 2 && rule.out_ifaces[2] == -1);
    TEST_ASSERT(rule.conntrack == 1);
    TEST_ASSERT(strcmp(rule.comment, "Allow Web") == 0);
    TEST_ASSERT(rule.hits == 15);

    json_free(val);

    json_buf_t buf;
    json_buf_init(&buf);
    json_serialize_rule(&buf, &rule);
    TEST_ASSERT(buf.len > 0);

    /* Разобрать сериализованное заново */
    json_value_t *val2 = json_parse(buf.data, NULL, 0);
    TEST_ASSERT(val2 != NULL);

    rule_t rule2;
    rc = json_parse_rule(val2, &rule2);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(rule2.id == 10);
    TEST_ASSERT(rule2.proto == 6);
    TEST_ASSERT(rule2.sport == 1024 && rule2.sport_end == 65535);
    TEST_ASSERT(rule2.dport == 80);
    TEST_ASSERT(rule2.action == ACTION_ACCEPT);
    TEST_ASSERT(rule2.out_ifaces[0] == 1 && rule2.out_ifaces[1] == 2);
    TEST_ASSERT(rule2.hits == 15);

    json_free(val2);
    json_buf_free(&buf);
}

/* -------------------------------------------------------------
 * Тест: Запуск сервера управления, базовые команды и дедупликация
 * ------------------------------------------------------------- */
static void test_control_server_lifecycle(void) {
    g_tests_run++;

    rules_init();
    ct_init();
    pktlog_init();

    int rc = control_init(TEST_SOCK_PATH, TEST_LOGD_SOCK_PATH);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(control_get_fd() >= 0);

    /* 1. Команда state.status */
    const char *req_status = "{\"msg_id\": 101, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"state.status\", \"payload\": {}}";
    char *resp = client_exchange(TEST_SOCK_PATH, req_status);
    TEST_ASSERT(resp != NULL);

    json_value_t *vresp = json_parse(resp, NULL, 0);
    TEST_ASSERT(vresp != NULL);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "status", ""), "ok") == 0);
    TEST_ASSERT(json_obj_get_int(vresp, "reply_to", 0) == 101);

    const json_value_t *pl = json_obj_get(vresp, "payload");
    TEST_ASSERT(pl != NULL);
    TEST_ASSERT(json_obj_get_bool(pl, "enabled", false) == true);
    TEST_ASSERT(json_obj_get_bool(pl, "emergency_mode", true) == false);

    json_free(vresp);
    free(resp);

    /* 2. Повтор запроса с тем же msg_id (дедупликация) */
    resp = client_exchange(TEST_SOCK_PATH, req_status);
    TEST_ASSERT(resp != NULL);
    vresp = json_parse(resp, NULL, 0);
    TEST_ASSERT(vresp != NULL);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "status", ""), "ok") == 0);
    TEST_ASSERT(json_obj_get_int(vresp, "reply_to", 0) == 101);
    json_free(vresp);
    free(resp);

    /* 3. Команда rule.replace с правилами */
    const char *req_replace = "{\"msg_id\": 102, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"rule.replace\", \"payload\": {\"rules\": ["
        "{\"id\": 100, \"active\": true, \"log\": false, \"in_iface\": 0, \"action\": \"accept\", \"out_ifaces\": [1], \"conntrack\": false, \"comment\": \"rule100\"},"
        "{\"id\": 200, \"active\": true, \"log\": false, \"in_iface\": 1, \"action\": \"drop\", \"comment\": \"rule200\"}"
        "]}}";
    resp = client_exchange(TEST_SOCK_PATH, req_replace);
    TEST_ASSERT(resp != NULL);
    vresp = json_parse(resp, NULL, 0);
    TEST_ASSERT(vresp != NULL);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "status", ""), "ok") == 0);
    pl = json_obj_get(vresp, "payload");
    TEST_ASSERT(pl != NULL);
    TEST_ASSERT(json_obj_get_int(pl, "rule_count", 0) == 2);
    json_free(vresp);
    free(resp);

    /* 4. Команда rule.get */
    const char *req_rget = "{\"msg_id\": 103, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"rule.get\", \"payload\": {}}";
    resp = client_exchange(TEST_SOCK_PATH, req_rget);
    TEST_ASSERT(resp != NULL);
    vresp = json_parse(resp, NULL, 0);
    TEST_ASSERT(vresp != NULL);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "status", ""), "ok") == 0);
    pl = json_obj_get(vresp, "payload");
    TEST_ASSERT(pl != NULL);
    const json_value_t *rules_arr = json_obj_get(pl, "rules");
    TEST_ASSERT(rules_arr && json_arr_len(rules_arr) == 2);
    json_free(vresp);
    free(resp);

    /* 5. Невалидные правила в rule.replace -> ошибка M06 */
    const char *req_invalid = "{\"msg_id\": 104, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"rule.replace\", \"payload\": {\"rules\": ["
        "{\"id\": 0, \"active\": true, \"action\": \"accept\"}"
        "]}}";
    resp = client_exchange(TEST_SOCK_PATH, req_invalid);
    TEST_ASSERT(resp != NULL);
    vresp = json_parse(resp, NULL, 0);
    TEST_ASSERT(vresp != NULL);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "status", ""), "error") == 0);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "error_code", ""), "M06") == 0);
    json_free(vresp);
    free(resp);

    /* 6. traffic.block и traffic.unblock */
    const char *req_block = "{\"msg_id\": 105, \"type\": \"request\", \"src\": \"integrityd\", \"dst\": \"filter\", \"cmd\": \"traffic.block\", \"payload\": {}}";
    resp = client_exchange(TEST_SOCK_PATH, req_block);
    TEST_ASSERT(resp != NULL);
    TEST_ASSERT(control_is_emergency_blocked() == true);
    free(resp);

    const char *req_unblock = "{\"msg_id\": 106, \"type\": \"request\", \"src\": \"integrityd\", \"dst\": \"filter\", \"cmd\": \"traffic.unblock\", \"payload\": {}}";
    resp = client_exchange(TEST_SOCK_PATH, req_unblock);
    TEST_ASSERT(resp != NULL);
    TEST_ASSERT(control_is_emergency_blocked() == false);
    free(resp);

    /* 7. state.delete с несуществующим ID -> ошибка M13 */
    const char *req_del = "{\"msg_id\": 107, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"state.delete\", \"payload\": {\"conn_id\": 999999}}";
    resp = client_exchange(TEST_SOCK_PATH, req_del);
    TEST_ASSERT(resp != NULL);
    vresp = json_parse(resp, NULL, 0);
    TEST_ASSERT(vresp != NULL);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "status", ""), "error") == 0);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "error_code", ""), "M13") == 0);
    json_free(vresp);
    free(resp);

    /* 7.1. Проверка state.list с полями client_* и server_* */
    parsed_packet_t pkt_syn;
    memset(&pkt_syn, 0, sizeof(pkt_syn));
    pkt_syn.eth_type = 0x0800;
    pkt_syn.ip_proto = 6;
    pkt_syn.src_ip = 0x0A000001; /* 10.0.0.1 */
    pkt_syn.dst_ip = 0xC0A80101; /* 192.168.1.1 */
    pkt_syn.sport = 54321;
    pkt_syn.dport = 80;
    pkt_syn.tcp_flags = FW_TCP_SYN;
    pkt_syn.in_iface = 0;
    pkt_syn.raw_len = 64;

    rule_decision_t rdec;
    memset(&rdec, 0, sizeof(rdec));
    rdec.rule_id = 100;
    rdec.conntrack = 1;
    rdec.out_count = 1;
    rdec.out_ifaces[0] = 1;
    ct_create_entry(&pkt_syn, &rdec);

    const char *req_slist = "{\"msg_id\": 177, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"state.list\", \"payload\": {}}";
    resp = client_exchange(TEST_SOCK_PATH, req_slist);
    TEST_ASSERT(resp != NULL);
    TEST_ASSERT(strstr(resp, "\"client_ip\":\"10.0.0.1\"") != NULL);
    TEST_ASSERT(strstr(resp, "\"server_ip\":\"192.168.1.1\"") != NULL);
    TEST_ASSERT(strstr(resp, "\"client_port\":54321") != NULL);
    TEST_ASSERT(strstr(resp, "\"server_port\":80") != NULL);
    TEST_ASSERT(strstr(resp, "\"client_packets\":") != NULL);
    TEST_ASSERT(strstr(resp, "\"server_packets\":") != NULL);
    free(resp);

    /* 7.2. Проверка, что правило с управляющим интерфейсом отклоняется с M06 */
    io_set_iface_mgmt(5, true);
    const char *req_mgmt_rule =
        "{\"msg_id\": 178, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", "
        "\"cmd\": \"rule.replace\", \"payload\": {\"rules\": ["
        "{\"id\": 500, \"active\": true, \"in_iface\": 5, \"action\": \"drop\"}"
        "]}}";
    resp = client_exchange(TEST_SOCK_PATH, req_mgmt_rule);
    TEST_ASSERT(resp != NULL);
    vresp = json_parse(resp, NULL, 0);
    TEST_ASSERT(vresp != NULL);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "status", ""), "error") == 0);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "error_code", ""), "M06") == 0);
    json_free(vresp);
    free(resp);
    io_set_iface_mgmt(5, false);

    /* 8. stats.get */
    control_inc_stat_rx();
    control_inc_stat_rx();
    control_inc_stat_tx();
    control_inc_stat_drop();

    const char *req_stats = "{\"msg_id\": 108, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"stats.get\", \"payload\": {}}";
    resp = client_exchange(TEST_SOCK_PATH, req_stats);
    TEST_ASSERT(resp != NULL);
    vresp = json_parse(resp, NULL, 0);
    TEST_ASSERT(vresp != NULL);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "status", ""), "ok") == 0);
    pl = json_obj_get(vresp, "payload");
    TEST_ASSERT(pl != NULL);
    TEST_ASSERT(json_obj_get_int(pl, "rx_packets", 0) == 2);
    TEST_ASSERT(json_obj_get_int(pl, "tx_packets", 0) == 1);
    TEST_ASSERT(json_obj_get_int(pl, "drop_packets", 0) == 1);
    TEST_ASSERT(json_obj_get_int(pl, "active_rules", 0) == 2);
    json_free(vresp);
    free(resp);

    /* 9. Неизвестная команда -> M14 */
    const char *req_unknown = "{\"msg_id\": 109, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"bad.cmd\", \"payload\": {}}";
    resp = client_exchange(TEST_SOCK_PATH, req_unknown);
    TEST_ASSERT(resp != NULL);
    vresp = json_parse(resp, NULL, 0);
    TEST_ASSERT(vresp != NULL);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "status", ""), "error") == 0);
    TEST_ASSERT(strcmp(json_obj_get_str(vresp, "error_code", ""), "M14") == 0);
    json_free(vresp);
    free(resp);

    control_cleanup();
    ct_cleanup();
    rules_cleanup();
    pktlog_cleanup();
}

/* -------------------------------------------------------------
 * Тест: state.enable / state.disable и отправка событий E14 / E15 в logd
 * ------------------------------------------------------------- */
static void test_logd_events_emission(void) {
    g_tests_run++;

    unlink(TEST_LOGD_SOCK_PATH);
    int logd_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    TEST_ASSERT(logd_fd >= 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TEST_LOGD_SOCK_PATH, sizeof(addr.sun_path) - 1);
    TEST_ASSERT(bind(logd_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    TEST_ASSERT(listen(logd_fd, 5) == 0);

    rules_init();
    ct_init();
    pktlog_init();
    control_init(TEST_SOCK_PATH, TEST_LOGD_SOCK_PATH);

    /* state.disable -> генерация E15 */
    const char *req_dis = "{\"msg_id\": 201, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"state.disable\", \"payload\": {}}";
    char *resp = client_exchange(TEST_SOCK_PATH, req_dis);
    TEST_ASSERT(resp != NULL);
    free(resp);
    TEST_ASSERT(ct_is_enabled() == false);

    /* state.enable -> генерация E14 */
    const char *req_en = "{\"msg_id\": 202, \"type\": \"request\", \"src\": \"cli\", \"dst\": \"filter\", \"cmd\": \"state.enable\", \"payload\": {}}";
    resp = client_exchange(TEST_SOCK_PATH, req_en);
    TEST_ASSERT(resp != NULL);
    free(resp);
    TEST_ASSERT(ct_is_enabled() == true);

    /* Принять соединения от control и прочитать события */
    char recv_events[4096] = {0};
    size_t total_recv = 0;

    for (int conn = 0; conn < 2; ++conn) {
        int client_fd = accept(logd_fd, NULL, NULL);
        if (client_fd < 0) break;

        while (1) {
            char chunk[1024];
            ssize_t r = recv(client_fd, chunk, sizeof(chunk), 0);
            if (r <= 0) break;
            if (total_recv + (size_t)r < sizeof(recv_events)) {
                memcpy(recv_events + total_recv, chunk, (size_t)r);
                total_recv += (size_t)r;
            }
        }
        close(client_fd);
    }
    close(logd_fd);
    unlink(TEST_LOGD_SOCK_PATH);

    /* Проверить, что в принятом потоке есть E15 и E14 */
    TEST_ASSERT(strstr(recv_events, "\"event_code\":\"E15\"") != NULL);
    TEST_ASSERT(strstr(recv_events, "\"event_code\":\"E14\"") != NULL);
    TEST_ASSERT(strstr(recv_events, "\"command\":\"state.disable\"") != NULL);
    TEST_ASSERT(strstr(recv_events, "\"command\":\"state.enable\"") != NULL);

    control_cleanup();
    ct_cleanup();
    rules_cleanup();
    pktlog_cleanup();
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--server") == 0) {
        const char *sp = argv[2];
        const char *lp = (argc >= 4) ? argv[3] : NULL;
        rules_init();
        ct_init();
        pktlog_init();
        if (control_init(sp, lp) != 0) {
            fprintf(stderr, "Failed to init control server on %s\n", sp);
            return 1;
        }
        printf("READY\n");
        fflush(stdout);
        while (1) {
            control_process();
            usleep(1000);
        }
        return 0;
    }

    printf("==> Running test_control...\n");

    test_json_parser_basic();
    test_rule_json_roundtrip();
    test_control_server_lifecycle();
    test_logd_events_emission();

    printf("==> test_control PASSED (%d test groups, %d assertions verified)\n",
           g_tests_run, g_asserts_passed);
    return 0;
}
