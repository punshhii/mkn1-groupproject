/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      rules
 * Назначение:  движок правил политики доступа (first-match, accept, goto, drop, атомарная замена)
 * Методы:
 *   - rules_init — инициализация движка правил
 *   - rules_cleanup — освобождение ресурсов
 *   - rules_set_arp_forwarding — переключение режима пересылки ARP
 *   - rules_get_arp_forwarding — опрос режима пересылки ARP
 *   - rules_match — сопоставить сетевой пакет с активными правилами
 *   - rules_validate — валидация набора правил согласно FR-13
 *   - rules_replace — атомарная замена таблицы с сохранением счётчиков hits (FR-10, FR-23)
 *   - rules_get_active — получение активной таблицы со счётчиками
 *   - rules_get_count — получение числа правил в активной таблице
 */
#include "rules.h"
#include "io.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    rule_t   *rules;
    uint32_t  count;
} rule_table_t;

static _Atomic(rule_table_t *) g_active_table = NULL;
static bool g_arp_forwarding = false;

static rule_table_t *table_alloc(uint32_t count)
{
    rule_table_t *tbl = malloc(sizeof(rule_table_t));
    if (!tbl) return NULL;
    tbl->count = count;
    if (count > 0) {
        tbl->rules = calloc(count, sizeof(rule_t));
        if (!tbl->rules) {
            free(tbl);
            return NULL;
        }
    } else {
        tbl->rules = NULL;
    }
    return tbl;
}

static void table_free(rule_table_t *tbl)
{
    if (!tbl) return;
    free(tbl->rules);
    free(tbl);
}

int rules_init(void)
{
    g_arp_forwarding = false;
    rule_table_t *tbl = table_alloc(0);
    if (!tbl) return -1;

    rule_table_t *old = atomic_exchange(&g_active_table, tbl);
    table_free(old);
    return 0;
}

void rules_cleanup(void)
{
    rule_table_t *old = atomic_exchange(&g_active_table, NULL);
    table_free(old);
}

void rules_set_arp_forwarding(bool enabled)
{
    g_arp_forwarding = enabled;
}

bool rules_get_arp_forwarding(void)
{
    return g_arp_forwarding;
}

static bool rule_matches(const rule_t *r, const parsed_packet_t *p)
{
    /* 1. Входной интерфейс */
    if (r->in_iface != -1 && r->in_iface != p->in_iface) {
        return false;
    }

    /* 2. MAC-адреса */
    if (r->smac != 0 && r->smac != p->smac) {
        return false;
    }
    if (r->dmac != 0 && r->dmac != p->dmac) {
        return false;
    }

    /* 3. Протокол Ethernet */
    if (r->eth_proto == ETH_PROTO_ARP) {
        if (p->eth_proto != ETH_PROTO_ARP) {
            return false;
        }
    } else if (r->eth_proto == ETH_PROTO_OTHER) {
        if (p->eth_proto != ETH_PROTO_OTHER) {
            return false;
        }
    }

    /* Если пакет ARP или OTHER, а правило требует IPv4/L4 условия — совпадения нет */
    if (p->eth_proto == ETH_PROTO_ARP || p->eth_proto == ETH_PROTO_OTHER) {
        if (r->proto != 0 || r->src != 0 || r->dst != 0 ||
            r->sport != 0 || r->dport != 0 ||
            r->icmp_type != 255 || r->icmp_code != 255) {
            return false;
        }
        return true;
    }

    /* 4. IPv4: Адрес источника */
    if (r->src != 0) {
        if (p->eth_type != 0x0800) {
            return false;
        }
        if (r->src_end > r->src) {
            /* Диапазон адресов */
            if (p->src_ip < r->src || p->src_ip > r->src_end) {
                return false;
            }
        } else {
            /* CIDR / одиночный адрес */
            if ((p->src_ip & r->src_mask) != (r->src & r->src_mask)) {
                return false;
            }
        }
    }

    /* 5. IPv4: Адрес назначения */
    if (r->dst != 0) {
        if (p->eth_type != 0x0800) {
            return false;
        }
        if (r->dst_end > r->dst) {
            /* Диапазон адресов */
            if (p->dst_ip < r->dst || p->dst_ip > r->dst_end) {
                return false;
            }
        } else {
            /* CIDR / одиночный адрес */
            if ((p->dst_ip & r->dst_mask) != (r->dst & r->dst_mask)) {
                return false;
            }
        }
    }

    /* 6. Протокол IP */
    if (r->proto != 0) {
        if (p->eth_type != 0x0800 || p->ip_proto != r->proto) {
            return false;
        }
    }

    /* 7. Порты TCP / UDP */
    if (r->sport != 0) {
        if (p->ip_proto != 6 && p->ip_proto != 17) {
            return false;
        }
        if (r->sport_end > r->sport) {
            if (p->sport < r->sport || p->sport > r->sport_end) {
                return false;
            }
        } else {
            if (p->sport != r->sport) {
                return false;
            }
        }
    }

    if (r->dport != 0) {
        if (p->ip_proto != 6 && p->ip_proto != 17) {
            return false;
        }
        if (r->dport_end > r->dport) {
            if (p->dport < r->dport || p->dport > r->dport_end) {
                return false;
            }
        } else {
            if (p->dport != r->dport) {
                return false;
            }
        }
    }

    /* 8. ICMPv4 тип и код */
    if (r->icmp_type != 255) {
        if (p->ip_proto != 1 || p->icmp_type != r->icmp_type) {
            return false;
        }
    }
    if (r->icmp_code != 255) {
        if (p->ip_proto != 1 || p->icmp_code != r->icmp_code) {
            return false;
        }
    }

    return true;
}

void rules_match(const parsed_packet_t *pkt, rule_decision_t *out_dec)
{
    if (!out_dec) return;
    memset(out_dec, 0, sizeof(*out_dec));
    for (int k = 0; k < MAX_INTERFACES; k++) {
        out_dec->out_ifaces[k] = -1;
    }

    rule_table_t *tbl = atomic_load(&g_active_table);
    if (!tbl || tbl->count == 0 || !pkt) {
        if (pkt && pkt->eth_proto == ETH_PROTO_ARP && g_arp_forwarding) {
            out_dec->verdict = RULE_MATCH_ARP_FORWARD;
        } else {
            out_dec->verdict = RULE_MATCH_DEFAULT_DROP;
        }
        out_dec->rule_id = 0;
        return;
    }

    uint32_t i = 0;
    while (i < tbl->count) {
        rule_t *r = &tbl->rules[i];

        if (!r->active) {
            i++;
            continue;
        }

        if (!rule_matches(r, pkt)) {
            i++;
            continue;
        }

        /* Совпадение найдено */
        if (r->action == ACTION_GOTO) {
            r->hits++;
            /* Найти правило с id == r->to_rule */
            uint32_t target_idx = tbl->count;
            for (uint32_t j = i + 1; j < tbl->count; j++) {
                if (tbl->rules[j].id == r->to_rule) {
                    target_idx = j;
                    break;
                }
            }
            if (target_idx < tbl->count) {
                i = target_idx;
                continue;
            }
            /* Если целевое правило не найдено, продолжаем со следующего */
            i++;
            continue;
        }

        if (r->action == ACTION_ACCEPT) {
            r->hits++;
            out_dec->verdict = RULE_MATCH_ACCEPT;
            out_dec->rule_id = r->id;
            out_dec->log = r->log;
            out_dec->conntrack = r->conntrack;
            out_dec->out_count = 0;
            for (int k = 0; k < MAX_INTERFACES; k++) {
                out_dec->out_ifaces[k] = r->out_ifaces[k];
                if (r->out_ifaces[k] >= 0) {
                    out_dec->out_count++;
                }
            }
            return;
        }

        if (r->action == ACTION_DROP) {
            r->hits++;
            out_dec->verdict = RULE_MATCH_DROP;
            out_dec->rule_id = r->id;
            out_dec->log = r->log;
            out_dec->conntrack = 0;
            out_dec->out_count = 0;
            return;
        }

        i++;
    }

    /* Ни одно правило не совпало */
    if (pkt->eth_proto == ETH_PROTO_ARP && g_arp_forwarding) {
        out_dec->verdict = RULE_MATCH_ARP_FORWARD;
    } else {
        out_dec->verdict = RULE_MATCH_DEFAULT_DROP;
    }
    out_dec->rule_id = 0;
    out_dec->log = 0;
}

int rules_validate(const rule_t *rules, uint32_t count, const char **err_code)
{
    if (count > MAX_RULES) {
        if (err_code) *err_code = "M06";
        return -1;
    }

    for (uint32_t i = 0; i < count; i++) {
        const rule_t *r = &rules[i];

        /* ID в диапазоне 1..65535 */
        if (r->id == 0) {
            if (err_code) *err_code = "M06";
            return -1;
        }

        /* Строгое возрастание номеров правил */
        if (i + 1 < count) {
            if (rules[i].id >= rules[i + 1].id) {
                if (err_code) *err_code = "M07";
                return -1;
            }
        }

        /* Валидность действий */
        if (r->action != ACTION_ACCEPT && r->action != ACTION_GOTO && r->action != ACTION_DROP) {
            if (err_code) *err_code = "M06";
            return -1;
        }

        /* Входной интерфейс не должен быть управляющим (M06) */
        if (r->in_iface >= 0) {
            if (r->in_iface >= MAX_INTERFACES || io_is_mgmt_iface(r->in_iface)) {
                if (err_code) *err_code = "M06";
                return -1;
            }
        }

        /* Для accept: выходные интерфейсы не должны содержать входной и управляющие (FR-13, M06) */
        if (r->action == ACTION_ACCEPT) {
            bool has_out = false;
            for (int k = 0; k < MAX_INTERFACES && r->out_ifaces[k] >= 0; k++) {
                has_out = true;
                if (r->out_ifaces[k] >= MAX_INTERFACES || io_is_mgmt_iface(r->out_ifaces[k])) {
                    if (err_code) *err_code = "M06";
                    return -1;
                }
                if (r->in_iface >= 0 && r->out_ifaces[k] == r->in_iface) {
                    if (err_code) *err_code = "M06";
                    return -1;
                }
            }
            if (!has_out) {
                if (err_code) *err_code = "M06";
                return -1;
            }
        }

        /* Для goto: to_rule > id и to_rule существует (FR-13) */
        if (r->action == ACTION_GOTO) {
            if (r->to_rule <= r->id) {
                if (err_code) *err_code = "M06";
                return -1;
            }
            bool found = false;
            for (uint32_t j = i + 1; j < count; j++) {
                if (rules[j].id == r->to_rule) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (err_code) *err_code = "M07";
                return -1;
            }
        }

        /* conntrack только при action=accept */
        if (r->conntrack && r->action != ACTION_ACCEPT) {
            if (err_code) *err_code = "M06";
            return -1;
        }

        /* Порты допустимы только при proto=tcp (6) или udp (17) */
        if (r->sport != 0 || r->sport_end != 0 || r->dport != 0 || r->dport_end != 0) {
            if (r->proto != 6 && r->proto != 17 && r->proto != 0) {
                if (err_code) *err_code = "M06";
                return -1;
            }
        }

        /* ICMP тип и код только при proto=icmp (1) */
        if (r->icmp_type != 255 || r->icmp_code != 255) {
            if (r->proto != 1 && r->proto != 0) {
                if (err_code) *err_code = "M06";
                return -1;
            }
        }
    }

    if (err_code) *err_code = NULL;
    return 0;
}

static bool rules_are_identical(const rule_t *a, const rule_t *b)
{
    if (a->id != b->id) return false;
    if (a->active != b->active) return false;
    if (a->log != b->log) return false;
    if (a->in_iface != b->in_iface) return false;
    if (a->smac != b->smac || a->dmac != b->dmac) return false;
    if (a->src != b->src || a->src_mask != b->src_mask || a->src_end != b->src_end) return false;
    if (a->dst != b->dst || a->dst_mask != b->dst_mask || a->dst_end != b->dst_end) return false;
    if (a->proto != b->proto || a->eth_proto != b->eth_proto) return false;
    if (a->sport != b->sport || a->sport_end != b->sport_end) return false;
    if (a->dport != b->dport || a->dport_end != b->dport_end) return false;
    if (a->icmp_type != b->icmp_type || a->icmp_code != b->icmp_code) return false;
    if (a->action != b->action) return false;
    if (a->to_rule != b->to_rule) return false;
    if (a->conntrack != b->conntrack) return false;
    for (int k = 0; k < MAX_INTERFACES; k++) {
        if (a->out_ifaces[k] != b->out_ifaces[k]) return false;
    }
    return true;
}

int rules_replace(const rule_t *new_rules, uint32_t count, rule_id_list_t *out_modified_rules)
{
    const char *err = NULL;
    if (count > 0 && (!new_rules || rules_validate(new_rules, count, &err) != 0)) {
        return -1;
    }

    rule_table_t *new_tbl = table_alloc(count);
    if (!new_tbl) return -1;

    rule_table_t *old_tbl = atomic_load(&g_active_table);

    if (out_modified_rules) {
        out_modified_rules->count = 0;
    }

    /* Копирование правил и перенос hits для неизменённых правил */
    for (uint32_t i = 0; i < count; i++) {
        new_tbl->rules[i] = new_rules[i];
        new_tbl->rules[i].hits = 0;

        if (old_tbl) {
            for (uint32_t j = 0; j < old_tbl->count; j++) {
                if (old_tbl->rules[j].id == new_rules[i].id) {
                    if (rules_are_identical(&old_tbl->rules[j], &new_rules[i])) {
                        new_tbl->rules[i].hits = old_tbl->rules[j].hits;
                    }
                    break;
                }
            }
        }
    }

    /* Определение изменённых, отключённых или удалённых правил (для conntrack FR-23) */
    if (old_tbl && out_modified_rules) {
        for (uint32_t i = 0; i < old_tbl->count; i++) {
            const rule_t *old_r = &old_tbl->rules[i];
            bool found_identical = false;

            for (uint32_t j = 0; j < count; j++) {
                if (new_tbl->rules[j].id == old_r->id) {
                    if (new_tbl->rules[j].active && rules_are_identical(old_r, &new_tbl->rules[j])) {
                        found_identical = true;
                    }
                    break;
                }
            }

            if (!found_identical) {
                if (out_modified_rules->count < MAX_RULES) {
                    out_modified_rules->ids[out_modified_rules->count++] = old_r->id;
                }
            }
        }
    }

    /* Атомарная подмена указателя (FR-10) */
    rule_table_t *prev = atomic_exchange(&g_active_table, new_tbl);
    table_free(prev);

    return 0;
}

uint32_t rules_get_active(rule_t *out_rules, uint32_t max_count)
{
    if (!out_rules || max_count == 0) return 0;

    rule_table_t *tbl = atomic_load(&g_active_table);
    if (!tbl || tbl->count == 0) return 0;

    uint32_t to_copy = (tbl->count < max_count) ? tbl->count : max_count;
    for (uint32_t i = 0; i < to_copy; i++) {
        out_rules[i] = tbl->rules[i];
    }
    return to_copy;
}

uint32_t rules_get_count(void)
{
    rule_table_t *tbl = atomic_load(&g_active_table);
    return tbl ? tbl->count : 0;
}
