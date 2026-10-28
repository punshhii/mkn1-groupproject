/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      control
 * Назначение:  сервер управления и диспетчер IPC-команд (/run/fw/filter.sock)
 */
#define _POSIX_C_SOURCE 200809L
#include "control.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "conntrack.h"
#include "json_utils.h"
#include "net_utils.h"
#include "pktlog_client.h"
#include "rules.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define MAX_CLIENTS        16
#define CLIENT_BUF_INIT    16384
#define CLIENT_BUF_MAX     (16 * 1024 * 1024)
#define DEDUP_CACHE_SIZE   256
#define MAX_LOGD_EVENTS    1000

/* Клиентское соединение */
typedef struct {
    int    fd;
    char  *buf;
    size_t len;
    size_t cap;
} client_conn_t;

/* Кэш дедупликации ответов */
typedef struct {
    int64_t msg_id;
    char   *response;
} dedup_entry_t;

static int           s_server_fd = -1;
static char          s_sock_path[MAX_PATH_LEN] = {0};
static char          s_logd_sock_path[MAX_PATH_LEN] = {0};
static client_conn_t s_clients[MAX_CLIENTS];

static bool          s_emergency_blocked = false;
static uint64_t      s_stat_rx = 0;
static uint64_t      s_stat_tx = 0;
static uint64_t      s_stat_drop = 0;
static uint64_t      s_next_msg_id = 1;

static dedup_entry_t s_dedup_cache[DEDUP_CACHE_SIZE];
static size_t        s_dedup_idx = 0;

static char         *s_logd_event_queue[MAX_LOGD_EVENTS];
static size_t        s_logd_q_head = 0;
static size_t        s_logd_q_tail = 0;
static size_t        s_logd_q_count = 0;

/* -------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------- */

static void get_iso8601_now(char *buf, size_t buf_len) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    gmtime_r(&ts.tv_sec, &tm_info);
    int ms = (int)(ts.tv_nsec / 1000000L);
    snprintf(buf, buf_len, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
             tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ms);
}

static int mkdir_p(const char *path) {
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return 0;
    for (size_t i = 1; i < len; ++i) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            mkdir(tmp, 0755);
            tmp[i] = '/';
        }
    }
    return 0;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_nosigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)fd;
#endif
}

/* -------------------------------------------------------------
 * Logd Event Queue (FR-28)
 * ------------------------------------------------------------- */

static void queue_logd_event(const char *event_code, const char *command, const char *details) {
    char ts[64];
    get_iso8601_now(ts, sizeof(ts));

    json_buf_t buf;
    json_buf_init(&buf);
    json_buf_printf(&buf,
        "{\"msg_id\":%llu,\"type\":\"event\",\"src\":\"filter\",\"dst\":\"logd\","
        "\"cmd\":\"log.write.event\",\"ts\":\"%s\","
        "\"payload\":{\"event_code\":\"%s\",\"result\":1,\"actor_type\":1,"
        "\"actor_id\":\"filter\",\"command\":\"%s\",\"details\":",
        (unsigned long long)(s_next_msg_id++),
        ts, event_code, command);
    json_buf_append_escaped(&buf, details);
    json_buf_append(&buf, "}}");

    if (s_logd_q_count >= MAX_LOGD_EVENTS) {
        /* Drop oldest event */
        free(s_logd_event_queue[s_logd_q_head]);
        s_logd_event_queue[s_logd_q_head] = NULL;
        s_logd_q_head = (s_logd_q_head + 1) % MAX_LOGD_EVENTS;
        s_logd_q_count--;
    }

    s_logd_event_queue[s_logd_q_tail] = strdup(buf.data);
    s_logd_q_tail = (s_logd_q_tail + 1) % MAX_LOGD_EVENTS;
    s_logd_q_count++;

    json_buf_free(&buf);
    control_flush_logd_events();
}

int control_flush_logd_events(void) {
    if (s_logd_q_count == 0 || s_logd_sock_path[0] == '\0') return 0;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    set_nosigpipe(fd);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, s_logd_sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return 0;
    }

    int sent_count = 0;
    while (s_logd_q_count > 0) {
        char *ev = s_logd_event_queue[s_logd_q_head];
        if (ev) {
            size_t elen = strlen(ev);
            ssize_t w = send(fd, ev, elen, MSG_NOSIGNAL);
            if (w == (ssize_t)elen) {
                send(fd, "\n", 1, MSG_NOSIGNAL);
                free(ev);
                s_logd_event_queue[s_logd_q_head] = NULL;
                s_logd_q_head = (s_logd_q_head + 1) % MAX_LOGD_EVENTS;
                s_logd_q_count--;
                sent_count++;
            } else {
                break;
            }
        } else {
            s_logd_q_head = (s_logd_q_head + 1) % MAX_LOGD_EVENTS;
            s_logd_q_count--;
        }
    }

    close(fd);
    return sent_count;
}

/* -------------------------------------------------------------
 * Command Handlers
 * ------------------------------------------------------------- */

static int handle_rule_replace(const json_value_t *payload, json_buf_t *res_pl, const char **err_code, const char **err_msg) {
    const json_value_t *rules_val = json_obj_get(payload, "rules");
    if (!rules_val || rules_val->type != JSON_TYPE_ARRAY) {
        *err_code = "M06";
        *err_msg = "Ошибка: неверное значение поля «rules». Допустимые значения: массив правил";
        return -1;
    }

    size_t count = json_arr_len(rules_val);
    if (count > MAX_RULES) {
        *err_code = "M06";
        *err_msg = "Ошибка: превышено максимальное количество правил (65535)";
        return -1;
    }

    rule_t *new_rules = NULL;
    if (count > 0) {
        new_rules = (rule_t *)calloc(count, sizeof(rule_t));
        if (!new_rules) {
            *err_code = "M06";
            *err_msg = "Ошибка выделения памяти для правил";
            return -1;
        }

        for (size_t i = 0; i < count; ++i) {
            const json_value_t *rv = json_arr_get(rules_val, i);
            if (json_parse_rule(rv, &new_rules[i]) != 0) {
                free(new_rules);
                *err_code = "M06";
                *err_msg = "Ошибка: неверный формат структуры правила";
                return -1;
            }
        }
    }

    const char *val_ec = NULL;
    if (rules_validate(new_rules, (uint32_t)count, &val_ec) != 0) {
        free(new_rules);
        *err_code = val_ec ? val_ec : "M06";
        *err_msg = "Ошибка валидации правил фильтрации";
        return -1;
    }

    rule_id_list_t modified;
    modified.count = 0;
    if (rules_replace(new_rules, (uint32_t)count, &modified) != 0) {
        free(new_rules);
        *err_code = "M06";
        *err_msg = "Ошибка атомарной замены таблицы правил";
        return -1;
    }
    if (new_rules) free(new_rules);

    uint32_t purged = 0;
    if (modified.count > 0) {
        purged = ct_purge_by_rule_ids(modified.ids, modified.count);
    }

    json_buf_printf(res_pl, "{\"rule_count\":%zu,\"purged_sessions\":%u}", count, purged);
    return 0;
}

static int handle_rule_get(json_buf_t *res_pl) {
    uint32_t count = rules_get_count();
    uint32_t max_fetch = (count > 0) ? count : 1;
    rule_t *rules = (rule_t *)calloc(max_fetch, sizeof(rule_t));
    if (!rules) {
        json_buf_append(res_pl, "{\"rules\":[]}");
        return 0;
    }

    uint32_t actual = rules_get_active(rules, max_fetch);

    json_buf_append(res_pl, "{\"rules\":[");
    for (uint32_t i = 0; i < actual; ++i) {
        if (i > 0) json_buf_append(res_pl, ",");
        json_serialize_rule(res_pl, &rules[i]);
    }
    json_buf_append(res_pl, "]}");
    free(rules);
    return 0;
}

static int handle_state_enable(json_buf_t *res_pl) {
    ct_enable();
    queue_logd_event("E14", "state.enable", "Включение механизма контроля состояний");
    json_buf_append(res_pl, "{\"enabled\":true}");
    return 0;
}

static int handle_state_disable(json_buf_t *res_pl) {
    ct_disable();
    queue_logd_event("E15", "state.disable", "Отключение механизма контроля состояний");
    json_buf_append(res_pl, "{\"enabled\":false}");
    return 0;
}

static const char *ct_state_str(ct_state_t st) {
    switch (st) {
        case CT_TCP_SYN_SENT:    return "SYN_SENT";
        case CT_TCP_SYN_RECV:    return "SYN_RECV";
        case CT_TCP_ESTABLISHED: return "ESTABLISHED";
        case CT_TCP_FIN_WAIT:    return "FIN_WAIT";
        case CT_UDP_UNREPLIED:   return "UDP_UNREPLIED";
        case CT_UDP_REPLIED:     return "UDP_REPLIED";
        case CT_ICMP_REQUEST:    return "ICMP_REQUEST";
        default:                 return "UNKNOWN";
    }
}

static const char *proto_name_str(uint8_t proto) {
    switch (proto) {
        case 6:  return "tcp";
        case 17: return "udp";
        case 1:  return "icmp";
        default: return "unknown";
    }
}

static int handle_state_list(json_buf_t *res_pl) {
    uint32_t total = ct_get_entries_count();
    uint32_t max_fetch = (total > 4096) ? 4096 : (total > 0 ? total : 1);
    ct_entry_info_t *entries = (ct_entry_info_t *)calloc(max_fetch, sizeof(ct_entry_info_t));
    if (!entries) {
        json_buf_append(res_pl, "{\"entries\":[]}");
        return 0;
    }

    uint32_t count = ct_dump_entries(entries, max_fetch);

    json_buf_append(res_pl, "{\"entries\":[");
    for (uint32_t i = 0; i < count; ++i) {
        if (i > 0) json_buf_append(res_pl, ",");
        char src_str[16], dst_str[16];
        ip_to_str(entries[i].src_ip, src_str, sizeof(src_str));
        ip_to_str(entries[i].dst_ip, dst_str, sizeof(dst_str));

        json_buf_printf(res_pl,
            "{\"conn_id\":%u,\"proto\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
            "\"sport\":%u,\"dport\":%u,\"state\":\"%s\",\"in_iface\":%d,\"out_ifaces\":[",
            entries[i].conn_id,
            proto_name_str(entries[i].proto),
            src_str, dst_str,
            entries[i].sport, entries[i].dport,
            ct_state_str(entries[i].state),
            entries[i].in_iface);

        bool first_out = true;
        for (int o = 0; o < MAX_INTERFACES && entries[i].out_ifaces[o] >= 0; ++o) {
            if (!first_out) json_buf_append(res_pl, ",");
            first_out = false;
            json_buf_printf(res_pl, "%d", entries[i].out_ifaces[o]);
        }
        json_buf_printf(res_pl, "],\"rule_id\":%u,\"expires_in_sec\":%u}",
                        entries[i].rule_id, entries[i].expires_in_sec);
    }
    json_buf_append(res_pl, "]}");
    free(entries);
    return 0;
}

static int handle_state_status(json_buf_t *res_pl) {
    conntrack_config_t cfg;
    ct_get_config(&cfg);

    json_buf_printf(res_pl,
        "{\"enabled\":%s,\"active_sessions\":%u,\"max_sessions\":%u,"
        "\"arp_forwarding\":%s,\"emergency_mode\":%s,"
        "\"tcp_syn_timeout_sec\":%u,\"tcp_est_timeout_sec\":%u,\"tcp_fin_timeout_sec\":%u,"
        "\"udp_timeout_no_reply\":%u,\"udp_timeout_reply\":%u,\"icmp_timeout_sec\":%u}",
        ct_is_enabled() ? "true" : "false",
        ct_get_entries_count(),
        cfg.state_table_size,
        rules_get_arp_forwarding() ? "true" : "false",
        s_emergency_blocked ? "true" : "false",
        cfg.tcp_syn_timeout_sec,
        cfg.tcp_est_timeout_sec,
        cfg.tcp_fin_timeout_sec,
        cfg.udp_timeout_no_reply,
        cfg.udp_timeout_reply,
        cfg.icmp_timeout_sec);
    return 0;
}

static int handle_state_delete(const json_value_t *payload, json_buf_t *res_pl, const char **err_code, const char **err_msg) {
    int64_t conn_id = json_obj_get_int(payload, "conn_id", 0);
    if (conn_id <= 0) {
        *err_code = "M13";
        *err_msg = "Записи не найдены";
        return -1;
    }

    if (ct_delete_entry((uint32_t)conn_id) != 0) {
        *err_code = "M13";
        *err_msg = "Записи не найдены";
        return -1;
    }

    json_buf_printf(res_pl, "{\"deleted\":true,\"conn_id\":%lld}", (long long)conn_id);
    return 0;
}

static int handle_state_delete_all(json_buf_t *res_pl) {
    uint32_t count = ct_get_entries_count();
    ct_delete_all();
    json_buf_printf(res_pl, "{\"deleted\":%u}", count);
    return 0;
}

static int handle_traffic_block(json_buf_t *res_pl) {
    s_emergency_blocked = true;
    uint32_t purged = ct_get_entries_count();
    ct_delete_all();
    json_buf_printf(res_pl, "{\"blocked\":true,\"purged_sessions\":%u}", purged);
    return 0;
}

static int handle_traffic_unblock(json_buf_t *res_pl) {
    s_emergency_blocked = false;
    json_buf_append(res_pl, "{\"blocked\":false}");
    return 0;
}

static int handle_state_clear(json_buf_t *res_pl) {
    uint32_t purged = ct_get_entries_count();
    ct_delete_all();
    json_buf_printf(res_pl, "{\"cleared\":true,\"deleted\":%u}", purged);
    return 0;
}

static int handle_stats_get(json_buf_t *res_pl) {
    pktlog_stats_t pstats;
    memset(&pstats, 0, sizeof(pstats));
    pktlog_get_stats(&pstats);

    json_buf_printf(res_pl,
        "{\"rx_packets\":%llu,\"tx_packets\":%llu,\"drop_packets\":%llu,"
        "\"active_rules\":%u,\"active_sessions\":%u,\"pktlog_dropped\":%llu}",
        (unsigned long long)s_stat_rx,
        (unsigned long long)s_stat_tx,
        (unsigned long long)s_stat_drop,
        rules_get_count(),
        ct_get_entries_count(),
        (unsigned long long)pstats.records_dropped);
    return 0;
}

/* -------------------------------------------------------------
 * Request Dispatcher & Deduplication
 * ------------------------------------------------------------- */

static char *process_json_request(const char *req_str) {
    char err_buf[128];
    json_value_t *req = json_parse(req_str, err_buf, sizeof(err_buf));
    if (!req) {
        json_buf_t b;
        json_buf_init(&b);
        char ts[64];
        get_iso8601_now(ts, sizeof(ts));
        json_buf_printf(&b,
            "{\"msg_id\":%llu,\"type\":\"response\",\"src\":\"filter\",\"dst\":\"unknown\","
            "\"reply_to\":null,\"ts\":\"%s\",\"status\":\"error\",\"error_code\":\"M06\","
            "\"error_message\":\"Invalid JSON request\",\"payload\":{}}\n",
            (unsigned long long)(s_next_msg_id++), ts);
        char *res = strdup(b.data);
        json_buf_free(&b);
        return res;
    }

    int64_t msg_id = json_obj_get_int(req, "msg_id", 0);
    const char *src = json_obj_get_str(req, "src", "cli");
    const char *cmd = json_obj_get_str(req, "cmd", "");
    const json_value_t *payload = json_obj_get(req, "payload");

    /* Deduplication check (PROTOCOL.md: повторный msg_id получает прежний ответ) */
    if (msg_id != 0) {
        for (size_t i = 0; i < DEDUP_CACHE_SIZE; ++i) {
            if (s_dedup_cache[i].msg_id == msg_id && s_dedup_cache[i].response != NULL) {
                json_free(req);
                return strdup(s_dedup_cache[i].response);
            }
        }
    }

    json_buf_t res_pl;
    json_buf_init(&res_pl);
    const char *err_code = NULL;
    const char *err_msg = NULL;
    int ret = 0;

    if (strcmp(cmd, "rule.replace") == 0) {
        ret = handle_rule_replace(payload, &res_pl, &err_code, &err_msg);
    } else if (strcmp(cmd, "rule.get") == 0) {
        ret = handle_rule_get(&res_pl);
    } else if (strcmp(cmd, "state.enable") == 0) {
        ret = handle_state_enable(&res_pl);
    } else if (strcmp(cmd, "state.disable") == 0) {
        ret = handle_state_disable(&res_pl);
    } else if (strcmp(cmd, "state.list") == 0) {
        ret = handle_state_list(&res_pl);
    } else if (strcmp(cmd, "state.status") == 0) {
        ret = handle_state_status(&res_pl);
    } else if (strcmp(cmd, "state.delete") == 0) {
        ret = handle_state_delete(payload, &res_pl, &err_code, &err_msg);
    } else if (strcmp(cmd, "state.delete_all") == 0) {
        ret = handle_state_delete_all(&res_pl);
    } else if (strcmp(cmd, "traffic.block") == 0) {
        ret = handle_traffic_block(&res_pl);
    } else if (strcmp(cmd, "traffic.unblock") == 0) {
        ret = handle_traffic_unblock(&res_pl);
    } else if (strcmp(cmd, "state.clear") == 0) {
        ret = handle_state_clear(&res_pl);
    } else if (strcmp(cmd, "stats.get") == 0) {
        ret = handle_stats_get(&res_pl);
    } else {
        err_code = "M14";
        err_msg = "Ошибка: неизвестная команда. Введите help";
        ret = -1;
    }

    char ts[64];
    get_iso8601_now(ts, sizeof(ts));

    json_buf_t resp;
    json_buf_init(&resp);
    json_buf_printf(&resp,
        "{\"msg_id\":%llu,\"type\":\"response\",\"src\":\"filter\",\"dst\":",
        (unsigned long long)(s_next_msg_id++));
    json_buf_append_escaped(&resp, src);

    if (msg_id != 0) {
        json_buf_printf(&resp, ",\"reply_to\":%lld,", (long long)msg_id);
    } else {
        json_buf_append(&resp, ",\"reply_to\":null,");
    }

    json_buf_printf(&resp, "\"ts\":\"%s\",", ts);

    if (ret == 0) {
        json_buf_append(&resp, "\"status\":\"ok\",\"error_code\":null,\"error_message\":null,\"payload\":");
        if (res_pl.len > 0) {
            json_buf_append(&resp, res_pl.data);
        } else {
            json_buf_append(&resp, "{}");
        }
    } else {
        json_buf_append(&resp, "\"status\":\"error\",\"error_code\":");
        json_buf_append_escaped(&resp, err_code);
        json_buf_append(&resp, ",\"error_message\":");
        json_buf_append_escaped(&resp, err_msg);
        json_buf_append(&resp, ",\"payload\":{}");
    }
    json_buf_append(&resp, "}\n");

    char *final_resp = strdup(resp.data);

    /* Store in dedup cache */
    if (msg_id != 0) {
        if (s_dedup_cache[s_dedup_idx].response) {
            free(s_dedup_cache[s_dedup_idx].response);
        }
        s_dedup_cache[s_dedup_idx].msg_id = msg_id;
        s_dedup_cache[s_dedup_idx].response = strdup(final_resp);
        s_dedup_idx = (s_dedup_idx + 1) % DEDUP_CACHE_SIZE;
    }

    json_buf_free(&res_pl);
    json_buf_free(&resp);
    json_free(req);

    return final_resp;
}

/* -------------------------------------------------------------
 * Lifecycle & Server Operations
 * ------------------------------------------------------------- */

int control_init(const char *sock_path, const char *logd_sock_path) {
    control_cleanup();

    const char *sp = sock_path ? sock_path : CONTROL_DEFAULT_SOCKET_PATH;
    const char *lp = logd_sock_path ? logd_sock_path : CONTROL_DEFAULT_LOGD_SOCKET_PATH;
    strncpy(s_sock_path, sp, sizeof(s_sock_path) - 1);
    strncpy(s_logd_sock_path, lp, sizeof(s_logd_sock_path) - 1);

    mkdir_p(s_sock_path);
    unlink(s_sock_path);

    s_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s_server_fd < 0) return -1;

    set_nonblocking(s_server_fd);
    set_nosigpipe(s_server_fd);

    int opt = 1;
    setsockopt(s_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, s_sock_path, sizeof(addr.sun_path) - 1);

    if (bind(s_server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(s_server_fd);
        s_server_fd = -1;
        return -1;
    }

    chmod(s_sock_path, 0600);

    if (listen(s_server_fd, 16) != 0) {
        close(s_server_fd);
        s_server_fd = -1;
        unlink(s_sock_path);
        return -1;
    }

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        s_clients[i].fd = -1;
        s_clients[i].buf = NULL;
        s_clients[i].len = 0;
        s_clients[i].cap = 0;
    }

    return 0;
}

void control_cleanup(void) {
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (s_clients[i].fd >= 0) {
            close(s_clients[i].fd);
            s_clients[i].fd = -1;
        }
        if (s_clients[i].buf) {
            free(s_clients[i].buf);
            s_clients[i].buf = NULL;
        }
        s_clients[i].len = 0;
        s_clients[i].cap = 0;
    }

    if (s_server_fd >= 0) {
        close(s_server_fd);
        s_server_fd = -1;
    }
    if (s_sock_path[0] != '\0') {
        unlink(s_sock_path);
        s_sock_path[0] = '\0';
    }

    for (size_t i = 0; i < DEDUP_CACHE_SIZE; ++i) {
        if (s_dedup_cache[i].response) {
            free(s_dedup_cache[i].response);
            s_dedup_cache[i].response = NULL;
        }
        s_dedup_cache[i].msg_id = 0;
    }
    s_dedup_idx = 0;

    for (size_t i = 0; i < MAX_LOGD_EVENTS; ++i) {
        if (s_logd_event_queue[i]) {
            free(s_logd_event_queue[i]);
            s_logd_event_queue[i] = NULL;
        }
    }
    s_logd_q_head = 0;
    s_logd_q_tail = 0;
    s_logd_q_count = 0;
}

int control_get_fd(void) {
    return s_server_fd;
}

int control_get_poll_fds(int *fds, int max_fds) {
    if (!fds || max_fds <= 0) return 0;
    int count = 0;
    if (s_server_fd >= 0 && count < max_fds) {
        fds[count++] = s_server_fd;
    }
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (s_clients[i].fd >= 0 && count < max_fds) {
            fds[count++] = s_clients[i].fd;
        }
    }
    return count;
}

static void close_client(int slot) {
    if (s_clients[slot].fd >= 0) {
        close(s_clients[slot].fd);
        s_clients[slot].fd = -1;
    }
    if (s_clients[slot].buf) {
        free(s_clients[slot].buf);
        s_clients[slot].buf = NULL;
    }
    s_clients[slot].len = 0;
    s_clients[slot].cap = 0;
}

int control_process(void) {
    if (s_server_fd < 0) return -1;

    int processed_count = 0;

    /* Accept incoming connections */
    while (1) {
        int cfd = accept(s_server_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            break;
        }
        set_nonblocking(cfd);
        set_nosigpipe(cfd);

        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (s_clients[i].fd < 0) {
                slot = i;
                break;
            }
        }
        if (slot >= 0) {
            s_clients[slot].fd = cfd;
            s_clients[slot].cap = CLIENT_BUF_INIT;
            s_clients[slot].len = 0;
            s_clients[slot].buf = (char *)malloc(s_clients[slot].cap);
        } else {
            close(cfd);
        }
    }

    /* Process connected clients */
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (s_clients[i].fd < 0) continue;

        char temp_buf[4096];
        while (1) {
            ssize_t r = read(s_clients[i].fd, temp_buf, sizeof(temp_buf));
            if (r > 0) {
                if (s_clients[i].len + (size_t)r + 1 > s_clients[i].cap) {
                    if (s_clients[i].cap * 2 <= CLIENT_BUF_MAX) {
                        size_t ncap = s_clients[i].cap * 2;
                        char *nb = (char *)realloc(s_clients[i].buf, ncap);
                        if (nb) {
                            s_clients[i].buf = nb;
                            s_clients[i].cap = ncap;
                        } else {
                            close_client(i);
                            break;
                        }
                    } else {
                        close_client(i);
                        break;
                    }
                }
                memcpy(s_clients[i].buf + s_clients[i].len, temp_buf, (size_t)r);
                s_clients[i].len += (size_t)r;
                s_clients[i].buf[s_clients[i].len] = '\0';
            } else if (r == 0) {
                close_client(i);
                break;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                close_client(i);
                break;
            }
        }

        if (s_clients[i].fd < 0 || s_clients[i].len == 0) continue;

        /* Look for newline delimited JSON messages */
        while (1) {
            char *nl = memchr(s_clients[i].buf, '\n', s_clients[i].len);
            if (!nl) break;

            *nl = '\0';
            size_t msg_len = (size_t)(nl - s_clients[i].buf);

            char *resp_str = process_json_request(s_clients[i].buf);
            if (resp_str) {
                size_t rlen = strlen(resp_str);
                send(s_clients[i].fd, resp_str, rlen, MSG_NOSIGNAL);
                free(resp_str);
            }
            processed_count++;

            size_t remaining = s_clients[i].len - (msg_len + 1);
            if (remaining > 0) {
                memmove(s_clients[i].buf, nl + 1, remaining);
            }
            s_clients[i].len = remaining;
            s_clients[i].buf[s_clients[i].len] = '\0';
        }
    }

    /* Try flushing logd event queue */
    if (s_logd_q_count > 0) {
        control_flush_logd_events();
    }

    return processed_count;
}

bool control_is_emergency_blocked(void) {
    return s_emergency_blocked;
}

void control_set_emergency_blocked(bool blocked) {
    s_emergency_blocked = blocked;
}

void control_inc_stat_rx(void) {
    s_stat_rx++;
}

void control_inc_stat_tx(void) {
    s_stat_tx++;
}

void control_inc_stat_drop(void) {
    s_stat_drop++;
}

void control_get_stats(uint64_t *rx, uint64_t *tx, uint64_t *drop) {
    if (rx) *rx = s_stat_rx;
    if (tx) *tx = s_stat_tx;
    if (drop) *drop = s_stat_drop;
}
