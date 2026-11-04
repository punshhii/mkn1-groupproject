/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      conntrack
 * Назначение:  контроль состояний соединений (stateful packet inspection) для TCP, UDP, ICMP
 * Методы:
 *   - ct_init — инициализация таблицы состояний и таймеров
 *   - ct_cleanup — освобождение ресурсов
 *   - ct_enable / ct_disable — включение и отключение механизма (FR-20)
 *   - ct_is_enabled — проверка активности контроля состояний
 *   - ct_process_packet — сопоставление пакета с существующим соединением (FR-15, FR-16)
 *   - ct_create_entry — создание новой записи для первого пакета (FR-14)
 *   - ct_expire_entries — очистка истёкших записей по таймаутам (FR-19)
 *   - ct_delete_entry — удаление одной записи по conn_id (FR-21)
 *   - ct_delete_all — удаление всех записей (FR-21)
 *   - ct_purge_by_rule_ids — удаление записей изменённых/удалённых правил (FR-23)
 *   - ct_get_config / ct_set_config — управление параметрами механизма
 *   - ct_get_entries_count — опрос текущего числа соединений
 *   - ct_dump_entries — выгрузка списка сессий для CLI/Web
 */
#include "conntrack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ct_entry {
    uint32_t         conn_id;
    uint8_t          proto;
    ip4_t            orig_src_ip;
    ip4_t            orig_dst_ip;
    uint16_t         orig_sport;
    uint16_t         orig_dport;

    uint64_t         client_packets;
    uint64_t         client_bytes;
    uint64_t         server_packets;
    uint64_t         server_bytes;

    int8_t           in_iface;
    int8_t           out_ifaces[MAX_INTERFACES];
    uint8_t          out_count;

    rule_id_t        rule_id;
    uint8_t          rule_log;

    ct_state_t       state;
    time_t           expire_time;

    struct ct_entry *next;
} ct_entry_t;

static conntrack_config_t g_cfg;
static ct_entry_t       **g_buckets = NULL;
static uint32_t           g_table_size = 0;
static uint32_t           g_entries_count = 0;
static uint32_t           g_next_conn_id = 1;

static void set_default_config(conntrack_config_t *cfg)
{
    cfg->tcp_syn_timeout_sec = 5;
    cfg->tcp_est_timeout_sec = 3600;
    cfg->tcp_fin_timeout_sec = 30;
    cfg->udp_timeout_no_reply = 15;
    cfg->udp_timeout_reply = 60;
    cfg->icmp_timeout_sec = 5;
    cfg->state_table_size = CT_DEFAULT_TABLE_SIZE;
    cfg->conntrack_enabled = true;
}

static uint32_t hash_5tuple(uint8_t proto, ip4_t s_ip, ip4_t d_ip, uint16_t s_p, uint16_t d_p)
{
    ip4_t ip_min = (s_ip < d_ip) ? s_ip : d_ip;
    ip4_t ip_max = (s_ip < d_ip) ? d_ip : s_ip;

    uint16_t p_min;
    uint16_t p_max;
    if (proto == 1) {
        /* Для ICMP sport = icmp_id, dport = 0 */
        p_min = s_p;
        p_max = 0;
    } else {
        p_min = (s_p < d_p) ? s_p : d_p;
        p_max = (s_p < d_p) ? d_p : s_p;
    }

    uint32_t h = (uint32_t)proto ^ ip_min ^ (ip_max << 5) ^ ((uint32_t)p_min << 16) ^ (uint32_t)p_max;
    h = (h ^ (h >> 16)) * 0x45d9f3bU;
    h = (h ^ (h >> 16)) * 0x45d9f3bU;
    h = h ^ (h >> 16);
    return h % g_table_size;
}

int ct_init(void)
{
    return ct_init_config(NULL);
}

int ct_init_config(const conntrack_config_t *cfg)
{
    ct_cleanup();

    if (cfg) {
        g_cfg = *cfg;
    } else {
        set_default_config(&g_cfg);
    }

    if (g_cfg.state_table_size == 0) {
        g_cfg.state_table_size = CT_DEFAULT_TABLE_SIZE;
    }

    g_table_size = g_cfg.state_table_size;
    g_buckets = calloc(g_table_size, sizeof(ct_entry_t *));
    if (!g_buckets) {
        return -1;
    }

    g_entries_count = 0;
    g_next_conn_id = 1;
    return 0;
}

void ct_cleanup(void)
{
    ct_delete_all();
    free(g_buckets);
    g_buckets = NULL;
    g_table_size = 0;
}

void ct_enable(void)
{
    g_cfg.conntrack_enabled = true;
}

void ct_disable(void)
{
    g_cfg.conntrack_enabled = false;
    ct_delete_all();
}

bool ct_is_enabled(void)
{
    return g_cfg.conntrack_enabled;
}

static bool match_entry_dir(const ct_entry_t *e, const parsed_packet_t *pkt, ct_dir_t *out_dir)
{
    if (e->proto != pkt->ip_proto) {
        return false;
    }

    if (pkt->ip_proto == 6 || pkt->ip_proto == 17) {
        /* TCP или UDP */
        if (pkt->src_ip == e->orig_src_ip && pkt->dst_ip == e->orig_dst_ip &&
            pkt->sport == e->orig_sport && pkt->dport == e->orig_dport) {
            *out_dir = CT_DIR_ORIGINAL;
            return true;
        }
        if (pkt->src_ip == e->orig_dst_ip && pkt->dst_ip == e->orig_src_ip &&
            pkt->sport == e->orig_dport && pkt->dport == e->orig_sport) {
            *out_dir = CT_DIR_REPLY;
            return true;
        }
    } else if (pkt->ip_proto == 1) {
        /* ICMP Echo */
        if (pkt->icmp_type == 8 && pkt->src_ip == e->orig_src_ip && pkt->dst_ip == e->orig_dst_ip &&
            pkt->icmp_id == e->orig_sport) {
            *out_dir = CT_DIR_ORIGINAL;
            return true;
        }
        if (pkt->icmp_type == 0 && pkt->src_ip == e->orig_dst_ip && pkt->dst_ip == e->orig_src_ip &&
            pkt->icmp_id == e->orig_sport) {
            *out_dir = CT_DIR_REPLY;
            return true;
        }
    }
    return false;
}

static ct_entry_t *find_entry(const parsed_packet_t *pkt, ct_dir_t *out_dir, ct_entry_t ***prev_ptr)
{
    if (!g_buckets || g_table_size == 0) return NULL;

    uint16_t s_p = (pkt->ip_proto == 1) ? pkt->icmp_id : pkt->sport;
    uint16_t d_p = (pkt->ip_proto == 1) ? 0 : pkt->dport;

    uint32_t b = hash_5tuple(pkt->ip_proto, pkt->src_ip, pkt->dst_ip, s_p, d_p);
    ct_entry_t **curr = &g_buckets[b];

    while (*curr) {
        ct_entry_t *e = *curr;
        if (match_entry_dir(e, pkt, out_dir)) {
            if (prev_ptr) {
                *prev_ptr = curr;
            }
            return e;
        }
        curr = &e->next;
    }
    return NULL;
}

static void remove_entry_node(ct_entry_t **prev_node, ct_entry_t *e)
{
    *prev_node = e->next;
    free(e);
    if (g_entries_count > 0) {
        g_entries_count--;
    }
}

ct_result_t ct_process_packet(const parsed_packet_t *pkt, ct_action_t *out_act)
{
    if (!out_act) return CT_RES_PASS_TO_RULES;
    memset(out_act, 0, sizeof(*out_act));
    for (int k = 0; k < MAX_INTERFACES; k++) {
        out_act->out_ifaces[k] = -1;
    }

    /* Если контроль состояний отключён или пакет не IPv4/TCP/UDP/ICMP */
    if (!g_cfg.conntrack_enabled || !pkt || pkt->eth_type != 0x0800) {
        out_act->result = CT_RES_PASS_TO_RULES;
        return CT_RES_PASS_TO_RULES;
    }

    if (pkt->ip_proto != 6 && pkt->ip_proto != 17 && pkt->ip_proto != 1) {
        out_act->result = CT_RES_PASS_TO_RULES;
        return CT_RES_PASS_TO_RULES;
    }

    time_t now = time(NULL);
    ct_dir_t dir;
    ct_entry_t **prev_ptr = NULL;
    ct_entry_t *e = find_entry(pkt, &dir, &prev_ptr);

    if (!e) {
        /* Соединение в таблице не найдено */
        if (pkt->ip_proto == 6) {
            /* TCP: первый пакет обязан иметь строго SYN без ACK (FR-16) */
            uint8_t syn_ack = pkt->tcp_flags & (FW_TCP_SYN | FW_TCP_ACK);
            if (syn_ack == FW_TCP_SYN) {
                /* Кандидат на открытие соединения */
                out_act->result = CT_RES_PASS_TO_RULES;
                return CT_RES_PASS_TO_RULES;
            }
            /* Пакет TCP с неверными флагами вне соединения (SYN-ACK, ACK, FIN, RST) -> блокировка (FR-16, FR-22) */
            out_act->result = CT_RES_DROP_OUT_OF_CONTEXT;
            out_act->rule_id = 0;
            return CT_RES_DROP_OUT_OF_CONTEXT;
        }

        if (pkt->ip_proto == 1) {
            /* ICMP: Echo Reply без запроса блокируется (FR-18) */
            if (pkt->icmp_type == 0) {
                out_act->result = CT_RES_DROP_OUT_OF_CONTEXT;
                out_act->rule_id = 0;
                return CT_RES_DROP_OUT_OF_CONTEXT;
            }
        }

        /* Первый UDP или ICMP Echo Request */
        out_act->result = CT_RES_PASS_TO_RULES;
        return CT_RES_PASS_TO_RULES;
    }

    /* Соединение найдено: проверка соответствия интерфейса (FR-15) */
    out_act->conn_id = e->conn_id;
    out_act->rule_id = e->rule_id;
    out_act->rule_log = e->rule_log;

    if (dir == CT_DIR_ORIGINAL) {
        /* Прямой пакет ДОЛЖЕН поступить на in_iface */
        if (pkt->in_iface != e->in_iface) {
            out_act->result = CT_RES_DROP_OUT_OF_CONTEXT;
            return CT_RES_DROP_OUT_OF_CONTEXT;
        }
        e->client_packets++;
        e->client_bytes += pkt->raw_len;
        /* Пересылается на выходные интерфейсы записи */
        out_act->out_count = e->out_count;
        for (int k = 0; k < MAX_INTERFACES; k++) {
            out_act->out_ifaces[k] = e->out_ifaces[k];
        }
    } else {
        /* Обратный пакет ДОЛЖЕН поступить на один из out_ifaces */
        bool iface_valid = false;
        for (uint8_t k = 0; k < e->out_count; k++) {
            if (pkt->in_iface == e->out_ifaces[k]) {
                iface_valid = true;
                break;
            }
        }
        if (!iface_valid) {
            out_act->result = CT_RES_DROP_OUT_OF_CONTEXT;
            return CT_RES_DROP_OUT_OF_CONTEXT;
        }
        e->server_packets++;
        e->server_bytes += pkt->raw_len;
        /* Пересылается на входной интерфейс записи */
        out_act->out_count = 1;
        out_act->out_ifaces[0] = e->in_iface;
    }

    /* Валидация автомата состояний */
    if (pkt->ip_proto == 6) {
        /* TCP автомат (FR-16) */
        if (e->state == CT_TCP_SYN_SENT) {
            if (dir == CT_DIR_REPLY && (pkt->tcp_flags & (FW_TCP_SYN | FW_TCP_ACK)) == (FW_TCP_SYN | FW_TCP_ACK)) {
                e->state = CT_TCP_SYN_RECV;
                e->expire_time = now + g_cfg.tcp_syn_timeout_sec;
            } else if (dir == CT_DIR_ORIGINAL && (pkt->tcp_flags & FW_TCP_SYN)) {
                /* Повторный SYN клиента */
                e->expire_time = now + g_cfg.tcp_syn_timeout_sec;
            } else if (pkt->tcp_flags & FW_TCP_RST) {
                remove_entry_node(prev_ptr, e);
                out_act->result = CT_RES_FORWARD;
                return CT_RES_FORWARD;
            } else {
                out_act->result = CT_RES_DROP_OUT_OF_CONTEXT;
                return CT_RES_DROP_OUT_OF_CONTEXT;
            }
        } else if (e->state == CT_TCP_SYN_RECV) {
            if (dir == CT_DIR_ORIGINAL && (pkt->tcp_flags & FW_TCP_ACK)) {
                e->state = CT_TCP_ESTABLISHED;
                e->expire_time = now + g_cfg.tcp_est_timeout_sec;
            } else if (dir == CT_DIR_REPLY && (pkt->tcp_flags & (FW_TCP_SYN | FW_TCP_ACK))) {
                /* Повторный SYN-ACK сервера */
                e->expire_time = now + g_cfg.tcp_syn_timeout_sec;
            } else if (pkt->tcp_flags & FW_TCP_RST) {
                remove_entry_node(prev_ptr, e);
                out_act->result = CT_RES_FORWARD;
                return CT_RES_FORWARD;
            } else {
                out_act->result = CT_RES_DROP_OUT_OF_CONTEXT;
                return CT_RES_DROP_OUT_OF_CONTEXT;
            }
        } else if (e->state == CT_TCP_ESTABLISHED) {
            if (pkt->tcp_flags & FW_TCP_RST) {
                /* RST в установленном соединении закрывает его и удаляет запись (FR-16) */
                remove_entry_node(prev_ptr, e);
                out_act->result = CT_RES_FORWARD;
                return CT_RES_FORWARD;
            } else if (pkt->tcp_flags & FW_TCP_FIN) {
                e->state = CT_TCP_FIN_WAIT;
                e->expire_time = now + g_cfg.tcp_fin_timeout_sec;
            } else {
                e->expire_time = now + g_cfg.tcp_est_timeout_sec;
            }
        } else if (e->state == CT_TCP_FIN_WAIT) {
            if (pkt->tcp_flags & FW_TCP_RST) {
                remove_entry_node(prev_ptr, e);
                out_act->result = CT_RES_FORWARD;
                return CT_RES_FORWARD;
            }
            e->expire_time = now + g_cfg.tcp_fin_timeout_sec;
        }
    } else if (pkt->ip_proto == 17) {
        /* UDP автомат (FR-17) */
        if (e->state == CT_UDP_UNREPLIED) {
            if (dir == CT_DIR_REPLY) {
                e->state = CT_UDP_REPLIED;
                e->expire_time = now + g_cfg.udp_timeout_reply;
            } else {
                e->expire_time = now + g_cfg.udp_timeout_no_reply;
            }
        } else {
            e->expire_time = now + g_cfg.udp_timeout_reply;
        }
    } else if (pkt->ip_proto == 1) {
        /* ICMP автомат (FR-18) */
        e->expire_time = now + g_cfg.icmp_timeout_sec;
    }

    out_act->result = CT_RES_FORWARD;
    return CT_RES_FORWARD;
}

int ct_create_entry(const parsed_packet_t *pkt, const rule_decision_t *dec)
{
    if (!g_cfg.conntrack_enabled || !pkt || !dec) return -1;
    if (g_entries_count >= g_cfg.state_table_size) {
        return -1; /* Таблица переполнена */
    }

    /* Проверка допустимости открытия соединения */
    if (pkt->ip_proto == 6) {
        /* Только SYN без ACK (FR-16) */
        if ((pkt->tcp_flags & (FW_TCP_SYN | FW_TCP_ACK)) != FW_TCP_SYN) {
            return -1;
        }
    } else if (pkt->ip_proto == 1) {
        /* Только Echo Request (FR-18) */
        if (pkt->icmp_type != 8) {
            return -1;
        }
    } else if (pkt->ip_proto != 17) {
        return -1; /* Conntrack только для TCP, UDP и ICMP Echo */
    }

    /* Проверка, нет ли уже такого соединения */
    ct_dir_t dummy_dir;
    if (find_entry(pkt, &dummy_dir, NULL) != NULL) {
        return 0; /* Уже существует */
    }

    ct_entry_t *e = calloc(1, sizeof(ct_entry_t));
    if (!e) return -1;

    e->conn_id = g_next_conn_id++;
    if (g_next_conn_id == 0) g_next_conn_id = 1;

    e->proto = pkt->ip_proto;
    e->orig_src_ip = pkt->src_ip;
    e->orig_dst_ip = pkt->dst_ip;
    e->in_iface = pkt->in_iface;

    e->client_packets = 1;
    e->client_bytes = pkt->raw_len;
    e->server_packets = 0;
    e->server_bytes = 0;

    if (pkt->ip_proto == 1) {
        e->orig_sport = pkt->icmp_id;
        e->orig_dport = 0;
    } else {
        e->orig_sport = pkt->sport;
        e->orig_dport = pkt->dport;
    }

    e->out_count = dec->out_count;
    for (int k = 0; k < MAX_INTERFACES; k++) {
        e->out_ifaces[k] = dec->out_ifaces[k];
    }
    e->rule_id = dec->rule_id;
    e->rule_log = dec->log;

    time_t now = time(NULL);
    if (pkt->ip_proto == 6) {
        e->state = CT_TCP_SYN_SENT;
        e->expire_time = now + g_cfg.tcp_syn_timeout_sec;
    } else if (pkt->ip_proto == 17) {
        e->state = CT_UDP_UNREPLIED;
        e->expire_time = now + g_cfg.udp_timeout_no_reply;
    } else {
        e->state = CT_ICMP_REQUEST;
        e->expire_time = now + g_cfg.icmp_timeout_sec;
    }

    uint16_t s_p = (pkt->ip_proto == 1) ? pkt->icmp_id : pkt->sport;
    uint16_t d_p = (pkt->ip_proto == 1) ? 0 : pkt->dport;
    uint32_t b = hash_5tuple(pkt->ip_proto, pkt->src_ip, pkt->dst_ip, s_p, d_p);

    e->next = g_buckets[b];
    g_buckets[b] = e;
    g_entries_count++;

    return 0;
}

uint32_t ct_expire_entries(time_t now)
{
    if (!g_buckets || g_entries_count == 0) return 0;
    if (now == 0) {
        now = time(NULL);
    }

    uint32_t removed = 0;
    for (uint32_t b = 0; b < g_table_size; b++) {
        ct_entry_t **curr = &g_buckets[b];
        while (*curr) {
            ct_entry_t *e = *curr;
            if (e->expire_time <= now) {
                remove_entry_node(curr, e);
                removed++;
            } else {
                curr = &e->next;
            }
        }
    }
    return removed;
}

int ct_delete_entry(uint32_t conn_id)
{
    if (!g_buckets || conn_id == 0) return -1;

    for (uint32_t b = 0; b < g_table_size; b++) {
        ct_entry_t **curr = &g_buckets[b];
        while (*curr) {
            ct_entry_t *e = *curr;
            if (e->conn_id == conn_id) {
                remove_entry_node(curr, e);
                return 0;
            }
            curr = &e->next;
        }
    }
    return -1;
}

void ct_delete_all(void)
{
    if (!g_buckets) return;

    for (uint32_t b = 0; b < g_table_size; b++) {
        ct_entry_t *curr = g_buckets[b];
        while (curr) {
            ct_entry_t *next = curr->next;
            free(curr);
            curr = next;
        }
        g_buckets[b] = NULL;
    }
    g_entries_count = 0;
}

uint32_t ct_purge_by_rule_ids(const rule_id_t *rule_ids, uint32_t count)
{
    if (!g_buckets || !rule_ids || count == 0 || g_entries_count == 0) {
        return 0;
    }

    uint32_t removed = 0;
    for (uint32_t b = 0; b < g_table_size; b++) {
        ct_entry_t **curr = &g_buckets[b];
        while (*curr) {
            ct_entry_t *e = *curr;
            bool purge = false;
            for (uint32_t i = 0; i < count; i++) {
                if (e->rule_id == rule_ids[i]) {
                    purge = true;
                    break;
                }
            }
            if (purge) {
                remove_entry_node(curr, e);
                removed++;
            } else {
                curr = &e->next;
            }
        }
    }
    return removed;
}

void ct_get_config(conntrack_config_t *out_cfg)
{
    if (out_cfg) {
        *out_cfg = g_cfg;
    }
}

void ct_set_config(const conntrack_config_t *new_cfg)
{
    if (new_cfg) {
        g_cfg = *new_cfg;
    }
}

uint32_t ct_get_entries_count(void)
{
    return g_entries_count;
}

uint32_t ct_dump_entries(ct_entry_info_t *out_entries, uint32_t max_count)
{
    if (!out_entries || max_count == 0 || !g_buckets) return 0;

    time_t now = time(NULL);
    uint32_t count = 0;

    for (uint32_t b = 0; b < g_table_size && count < max_count; b++) {
        ct_entry_t *e = g_buckets[b];
        while (e && count < max_count) {
            ct_entry_info_t *info = &out_entries[count++];
            info->conn_id = e->conn_id;
            info->proto = e->proto;
            info->client_ip = e->orig_src_ip;
            info->server_ip = e->orig_dst_ip;
            info->client_port = e->orig_sport;
            info->server_port = e->orig_dport;
            info->src_ip = e->orig_src_ip;
            info->dst_ip = e->orig_dst_ip;
            info->sport = e->orig_sport;
            info->dport = e->orig_dport;
            info->client_packets = e->client_packets;
            info->client_bytes = e->client_bytes;
            info->server_packets = e->server_packets;
            info->server_bytes = e->server_bytes;
            info->in_iface = e->in_iface;
            for (int k = 0; k < MAX_INTERFACES; k++) {
                info->out_ifaces[k] = e->out_ifaces[k];
            }
            info->rule_id = e->rule_id;
            info->state = e->state;
            info->expires_in_sec = (e->expire_time > now) ? (uint32_t)(e->expire_time - now) : 0;
            e = e->next;
        }
    }
    return count;
}
