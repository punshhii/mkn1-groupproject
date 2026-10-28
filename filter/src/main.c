/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      main
 * Назначение:  точка входа fw-filter — загрузка конфигурации, инициализация модулей,
 *              основной цикл событий poll, конвейер фильтрации пакетов,
 *              обработка сигналов SIGINT/SIGTERM
 * Методы:
 *   - main — инициализация модулей и основной цикл
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "conntrack.h"
#include "control.h"
#include "io.h"
#include "json_utils.h"
#include "net_utils.h"
#include "parser.h"
#include "pktlog_client.h"
#include "rules.h"

/* ------------------------------------------------------------- */
/* Глобальный флаг для корректной остановки                      */
/* ------------------------------------------------------------- */

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ------------------------------------------------------------- */
/* Загрузка конфигурации и политики                              */
/* ------------------------------------------------------------- */

static int load_config(const char *config_path) {
    const char *path = config_path;
    if (!path) path = "/etc/fw/config.json";

    FILE *f = fopen(path, "r");
    if (!f) {
        /* Попробовать дефолтный конфиг из поставки */
        path = "/etc/default/config.json";
        f = fopen(path, "r");
    }
    if (!f) {
        fprintf(stderr, "fw-filter: no config found, using defaults\n");
        return 0; /* Работаем с дефолтами */
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > 1024 * 1024) {
        fclose(f);
        return 0;
    }

    char *json_str = (char *)malloc((size_t)fsize + 1);
    if (!json_str) { fclose(f); return -1; }

    size_t rd = fread(json_str, 1, (size_t)fsize, f);
    fclose(f);
    json_str[rd] = '\0';

    json_value_t *root = json_parse(json_str, NULL, 0);
    free(json_str);
    if (!root) return 0;

    /* Секция conntrack */
    const json_value_t *ct = json_obj_get(root, "conntrack");
    if (ct) {
        conntrack_config_t cfg;
        ct_get_config(&cfg);

        cfg.tcp_syn_timeout_sec  = (uint32_t)json_obj_get_int(ct, "tcp_syn_timeout_sec",  cfg.tcp_syn_timeout_sec);
        cfg.tcp_est_timeout_sec  = (uint32_t)json_obj_get_int(ct, "tcp_est_timeout_sec",  cfg.tcp_est_timeout_sec);
        cfg.tcp_fin_timeout_sec  = (uint32_t)json_obj_get_int(ct, "tcp_fin_timeout_sec",  cfg.tcp_fin_timeout_sec);
        cfg.udp_timeout_no_reply = (uint32_t)json_obj_get_int(ct, "udp_timeout_no_reply", cfg.udp_timeout_no_reply);
        cfg.udp_timeout_reply    = (uint32_t)json_obj_get_int(ct, "udp_timeout_reply",    cfg.udp_timeout_reply);
        cfg.icmp_timeout_sec     = (uint32_t)json_obj_get_int(ct, "icmp_timeout_sec",     cfg.icmp_timeout_sec);
        cfg.state_table_size     = (uint32_t)json_obj_get_int(ct, "state_table_size",     cfg.state_table_size);
        cfg.conntrack_enabled    = json_obj_get_bool(ct, "conntrack_enabled", cfg.conntrack_enabled);

        ct_set_config(&cfg);
        if (cfg.conntrack_enabled) ct_enable();
        else ct_disable();

        bool arp_fwd = json_obj_get_bool(ct, "arp_forwarding", false);
        rules_set_arp_forwarding(arp_fwd);
    }

    json_free(root);
    return 0;
}

static int load_policy(const char *policy_path) {
    const char *path = policy_path;
    if (!path) path = "/etc/fw/policy.json";

    FILE *f = fopen(path, "r");
    if (!f) {
        path = "/etc/default/policy.json";
        f = fopen(path, "r");
    }
    if (!f) {
        fprintf(stderr, "fw-filter: no policy found, starting with empty rules\n");
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > 16 * 1024 * 1024) {
        fclose(f);
        return 0;
    }

    char *json_str = (char *)malloc((size_t)fsize + 1);
    if (!json_str) { fclose(f); return -1; }

    size_t rd = fread(json_str, 1, (size_t)fsize, f);
    fclose(f);
    json_str[rd] = '\0';

    json_value_t *root = json_parse(json_str, NULL, 0);
    free(json_str);
    if (!root) {
        fprintf(stderr, "fw-filter: failed to parse policy %s\n", path);
        return 0;
    }

    const json_value_t *rules_arr = json_obj_get(root, "rules");
    if (!rules_arr || rules_arr->type != JSON_TYPE_ARRAY) {
        json_free(root);
        return 0;
    }

    size_t count = json_arr_len(rules_arr);
    if (count == 0) {
        json_free(root);
        return 0;
    }

    rule_t *new_rules = (rule_t *)calloc(count, sizeof(rule_t));
    if (!new_rules) {
        json_free(root);
        return -1;
    }

    size_t valid = 0;
    for (size_t i = 0; i < count; ++i) {
        const json_value_t *rv = json_arr_get(rules_arr, i);
        if (rv && json_parse_rule(rv, &new_rules[valid]) == 0) {
            valid++;
        }
    }

    if (valid > 0) {
        const char *ec = NULL;
        if (rules_validate(new_rules, (uint32_t)valid, &ec) == 0) {
            rules_replace(new_rules, (uint32_t)valid, NULL);
            fprintf(stderr, "fw-filter: loaded %zu rules from %s\n", valid, path);
        } else {
            fprintf(stderr, "fw-filter: policy validation failed: %s\n", ec ? ec : "unknown");
        }
    }

    free(new_rules);
    json_free(root);
    return 0;
}

/* ------------------------------------------------------------- */
/* Конвейер обработки одного пакета (FR-01, FR-05..FR-22)        */
/* ------------------------------------------------------------- */

static void process_packet(const uint8_t *frame, size_t frame_len, int8_t in_iface) {
    control_inc_stat_rx();

    /* 1. Режим аварийной блокировки (FR-48) */
    if (control_is_emergency_blocked()) {
        control_inc_stat_drop();
        return;
    }

    /* 2. Разбор заголовков (FR-12) */
    parsed_packet_t pkt;
    parse_result_t pr = parse_frame(frame, (unsigned)frame_len, in_iface, &pkt);

    if (pr == PARSE_DROP_MALFORMED) {
        /* FR-12: повреждённый заголовок — кадр удаляется */
        control_inc_stat_drop();
        return;
    }

    /* 3. ARP и другие L2-протоколы (FR-11) */
    if (pr == PARSE_ARP || pr == PARSE_OTHER_ETH) {
        rule_decision_t dec;
        rules_match(&pkt, &dec);

        if (dec.verdict == RULE_MATCH_ACCEPT) {
            /* Передать на выходные интерфейсы */
            for (uint8_t o = 0; o < dec.out_count; ++o) {
                int8_t oi = dec.out_ifaces[o];
                if (oi >= 0 && oi != in_iface) {
                    io_send_frame(oi, frame, frame_len);
                }
            }
            if (dec.log) pktlog_log_packet(&pkt, &dec, 0);
            control_inc_stat_tx();
        } else if (dec.verdict == RULE_MATCH_ARP_FORWARD) {
            /* FR-11: ARP с включённой пересылкой — отправить на все интерфейсы кроме входного */
            uint8_t iface_count = io_get_iface_count();
            for (uint8_t o = 0; o < iface_count; ++o) {
                if ((int8_t)o != in_iface) {
                    io_send_frame((int)o, frame, frame_len);
                }
            }
            control_inc_stat_tx();
        } else {
            /* DROP / DEFAULT_DROP */
            if (dec.log) pktlog_log_packet(&pkt, &dec, 0);
            control_inc_stat_drop();
        }
        return;
    }

    /* 4. IPv4-пакет: проверка conntrack */
    if (ct_is_enabled()) {
        ct_action_t ct_act;
        ct_result_t cr = ct_process_packet(&pkt, &ct_act);

        if (cr == CT_RES_FORWARD) {
            /* Пакет принадлежит существующему соединению — пересылка */
            for (uint8_t o = 0; o < ct_act.out_count; ++o) {
                int8_t oi = ct_act.out_ifaces[o];
                if (oi >= 0) {
                    io_send_frame(oi, frame, frame_len);
                }
            }
            control_inc_stat_tx();
            return;
        }

        if (cr == CT_RES_DROP_OUT_OF_CONTEXT) {
            /* FR-15, FR-16, FR-22: пакет вне контекста — сброс */
            control_inc_stat_drop();
            return;
        }

        /* CT_RES_PASS_TO_RULES: передать в модуль правил */
    }

    /* 5. Просмотр правил (FR-05..FR-09) */
    rule_decision_t dec;
    rules_match(&pkt, &dec);

    if (dec.verdict == RULE_MATCH_ACCEPT) {
        /* 5.1. Создать запись conntrack если conntrack==1 и первый пакет соединения */
        uint32_t conn_id = 0;
        if (dec.conntrack && ct_is_enabled()) {
            if (ct_create_entry(&pkt, &dec) == 0) {
                /* Получить conn_id из только что созданной записи */
                ct_action_t ca;
                ct_result_t check = ct_process_packet(&pkt, &ca);
                if (check == CT_RES_FORWARD) {
                    conn_id = ca.conn_id;
                }
            }
        }

        /* 5.2. Логирование */
        if (dec.log) pktlog_log_packet(&pkt, &dec, conn_id);

        /* 5.3. Пересылка на выходные интерфейсы */
        for (uint8_t o = 0; o < dec.out_count; ++o) {
            int8_t oi = dec.out_ifaces[o];
            if (oi >= 0) {
                io_send_frame(oi, frame, frame_len);
            }
        }
        control_inc_stat_tx();

    } else {
        /* RULE_MATCH_DROP / RULE_MATCH_DEFAULT_DROP */
        if (dec.log) pktlog_log_packet(&pkt, &dec, 0);
        control_inc_stat_drop();
    }
}

/* ------------------------------------------------------------- */
/* Основной цикл событий                                         */
/* ------------------------------------------------------------- */

int main(int argc, char **argv) {
    const char *config_path = NULL;
    const char *policy_path = NULL;
    const char *sock_path   = NULL;
    const char *logd_path   = NULL;

    /* Простой разбор аргументов командной строки */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)      config_path = argv[++i];
        else if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc) policy_path = argv[++i];
        else if (strcmp(argv[i], "--sock") == 0 && i + 1 < argc)   sock_path   = argv[++i];
        else if (strcmp(argv[i], "--logd") == 0 && i + 1 < argc)   logd_path   = argv[++i];
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: fw-filter [--config path] [--policy path] [--sock path] [--logd path]\n");
            return 0;
        }
    }

    setup_signals();

    /* 1. Инициализация модулей */
    if (rules_init() != 0) {
        fprintf(stderr, "fw-filter: rules_init failed\n");
        return 1;
    }
    if (ct_init() != 0) {
        fprintf(stderr, "fw-filter: ct_init failed\n");
        rules_cleanup();
        return 1;
    }
    if (pktlog_init() != 0) {
        fprintf(stderr, "fw-filter: pktlog_init failed\n");
        ct_cleanup();
        rules_cleanup();
        return 1;
    }
    if (io_init(config_path) != 0) {
        fprintf(stderr, "fw-filter: io_init failed\n");
        pktlog_cleanup();
        ct_cleanup();
        rules_cleanup();
        return 1;
    }

    /* 2. Загрузка конфигурации и политики */
    load_config(config_path);
    load_policy(policy_path);

    /* 3. Запуск сервера управления IPC */
    if (control_init(sock_path, logd_path) != 0) {
        fprintf(stderr, "fw-filter: control_init failed\n");
        io_cleanup();
        pktlog_cleanup();
        ct_cleanup();
        rules_cleanup();
        return 1;
    }

    fprintf(stderr, "fw-filter: started (%u interfaces, %u rules)\n",
            io_get_iface_count(), rules_get_count());

    uint8_t iface_count = io_get_iface_count();
    time_t last_tick = time(NULL);

    /* 4. Основной цикл обработки */
    while (g_running) {
        struct pollfd pfds[32];
        int nfds = 0;

        /* Опрос сетевых интерфейсов */
        for (int i = 0; i < (int)iface_count && nfds < 16; ++i) {
            int ifd = io_get_fd(i);
            if (ifd >= 0) {
                pfds[nfds].fd = ifd;
                pfds[nfds].events = POLLIN;
                pfds[nfds].revents = 0;
                nfds++;
            }
        }

        /* Опрос сокета управления и активных клиентов */
        int ctrl_fds[16];
        int nctrl = control_get_poll_fds(ctrl_fds, 16);
        int ctrl_start_idx = nfds;
        for (int i = 0; i < nctrl && nfds < 32; ++i) {
            pfds[nfds].fd = ctrl_fds[i];
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        int ret = poll(pfds, (nfds_t)nfds, 100); /* 100 мс таймаут */

        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Обработка входящих кадров на каждом интерфейсе */
        for (int i = 0; i < (int)iface_count; ++i) {
            if (i < ctrl_start_idx && (pfds[i].revents & POLLIN)) {
                uint8_t frame[IO_MAX_FRAME_SIZE];
                size_t frame_len = 0;
                while (io_recv_frame(i, frame, sizeof(frame), &frame_len) == 0) {
                    process_packet(frame, frame_len, (int8_t)i);
                }
            }
        }

        /* Обработка IPC-команд на сокете управления и клиентах */
        bool ctrl_ready = false;
        for (int i = ctrl_start_idx; i < nfds; ++i) {
            if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                ctrl_ready = true;
                break;
            }
        }
        if (ctrl_ready) {
            control_process();
        }

        /* Периодические задачи (1 раз в секунду) */
        time_t now = time(NULL);
        if (now != last_tick) {
            last_tick = now;
            ct_expire_entries(now);
            pktlog_flush();
            control_flush_logd_events();
        }
    }

    /* 5. Корректная остановка */
    fprintf(stderr, "fw-filter: shutting down...\n");

    control_cleanup();
    pktlog_cleanup();
    ct_cleanup();
    rules_cleanup();
    io_cleanup();

    fprintf(stderr, "fw-filter: stopped\n");
    return 0;
}
