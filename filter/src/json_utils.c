/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      json_utils
 * Назначение:  легковесный разбор и форматирование JSON для протокола управления
 */
#include "json_utils.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io.h"
#include "net_utils.h"

/* -------------------------------------------------------------
 * Dynamic Buffer
 * ------------------------------------------------------------- */

void json_buf_init(json_buf_t *buf) {
    if (!buf) return;
    buf->len = 0;
    buf->cap = 256;
    buf->data = (char *)malloc(buf->cap);
    if (buf->data) {
        buf->data[0] = '\0';
    } else {
        buf->cap = 0;
    }
}

void json_buf_free(json_buf_t *buf) {
    if (!buf) return;
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->len = 0;
    buf->cap = 0;
}

static bool json_buf_ensure(json_buf_t *buf, size_t extra) {
    if (!buf || !buf->data) return false;
    if (buf->len + extra + 1 > buf->cap) {
        size_t new_cap = (buf->cap * 2 > buf->len + extra + 1) ? buf->cap * 2 : buf->len + extra + 64;
        char *new_data = (char *)realloc(buf->data, new_cap);
        if (!new_data) return false;
        buf->data = new_data;
        buf->cap = new_cap;
    }
    return true;
}

void json_buf_append(json_buf_t *buf, const char *s) {
    if (!buf || !s) return;
    size_t slen = strlen(s);
    if (!json_buf_ensure(buf, slen)) return;
    memcpy(buf->data + buf->len, s, slen);
    buf->len += slen;
    buf->data[buf->len] = '\0';
}

void json_buf_append_escaped(json_buf_t *buf, const char *s) {
    if (!buf) return;
    if (!s) {
        json_buf_append(buf, "\"\"");
        return;
    }
    json_buf_append(buf, "\"");
    for (const char *p = s; *p; ++p) {
        switch (*p) {
            case '\"': json_buf_append(buf, "\\\""); break;
            case '\\': json_buf_append(buf, "\\\\"); break;
            case '\b': json_buf_append(buf, "\\b"); break;
            case '\f': json_buf_append(buf, "\\f"); break;
            case '\n': json_buf_append(buf, "\\n"); break;
            case '\r': json_buf_append(buf, "\\r"); break;
            case '\t': json_buf_append(buf, "\\t"); break;
            default:
                if ((unsigned char)*p < 0x20) {
                    char hex[8];
                    snprintf(hex, sizeof(hex), "\\u%04x", (unsigned char)*p);
                    json_buf_append(buf, hex);
                } else {
                    char ch[2] = { *p, '\0' };
                    json_buf_append(buf, ch);
                }
                break;
        }
    }
    json_buf_append(buf, "\"");
}

void json_buf_printf(json_buf_t *buf, const char *fmt, ...) {
    if (!buf || !fmt) return;
    va_list args;
    va_start(args, fmt);
    va_list args_copy;
    va_copy(args_copy, args);
    int needed = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (needed > 0 && json_buf_ensure(buf, (size_t)needed)) {
        vsnprintf(buf->data + buf->len, needed + 1, fmt, args_copy);
        buf->len += (size_t)needed;
    }
    va_end(args_copy);
}

/* -------------------------------------------------------------
 * JSON Parser
 * ------------------------------------------------------------- */

static void skip_whitespace(const char **p) {
    while (**p && (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n')) {
        (*p)++;
    }
}

static json_value_t *json_val_alloc(json_type_t type) {
    json_value_t *val = (json_value_t *)calloc(1, sizeof(json_value_t));
    if (val) {
        val->type = type;
    }
    return val;
}

void json_free(json_value_t *val) {
    if (!val) return;
    switch (val->type) {
        case JSON_TYPE_STRING:
            if (val->u.str_val) free(val->u.str_val);
            break;
        case JSON_TYPE_ARRAY:
            for (size_t i = 0; i < val->u.array.count; ++i) {
                json_free(val->u.array.items[i]);
            }
            if (val->u.array.items) free(val->u.array.items);
            break;
        case JSON_TYPE_OBJECT:
            for (size_t i = 0; i < val->u.object.count; ++i) {
                if (val->u.object.keys[i]) free(val->u.object.keys[i]);
                json_free(val->u.object.values[i]);
            }
            if (val->u.object.keys) free(val->u.object.keys);
            if (val->u.object.values) free(val->u.object.values);
            break;
        default:
            break;
    }
    free(val);
}

static json_value_t *parse_value(const char **p, char *err_buf, size_t err_len);

static char *parse_string_raw(const char **p, char *err_buf, size_t err_len) {
    if (**p != '\"') {
        if (err_buf) snprintf(err_buf, err_len, "Expected '\"'");
        return NULL;
    }
    (*p)++; /* skip initial quote */

    size_t cap = 32;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;

    while (**p) {
        char c = **p;
        if (c == '\"') {
            (*p)++; /* consume closing quote */
            buf[len] = '\0';
            return buf;
        }
        if (c == '\\') {
            (*p)++;
            c = **p;
            switch (c) {
                case '\"': c = '\"'; break;
                case '\\': c = '\\'; break;
                case '/':  c = '/'; break;
                case 'b':  c = '\b'; break;
                case 'f':  c = '\f'; break;
                case 'n':  c = '\n'; break;
                case 'r':  c = '\r'; break;
                case 't':  c = '\t'; break;
                case 'u': {
                    /* Basic 4-hex Unicode escape */
                    (*p)++;
                    char hex[5] = {0};
                    for (int h = 0; h < 4 && **p; ++h) {
                        hex[h] = **p;
                        (*p)++;
                    }
                    (*p)--; /* align pointer for loop increment */
                    unsigned int cp = 0;
                    sscanf(hex, "%x", &cp);
                    if (cp < 0x80) {
                        c = (char)cp;
                    } else {
                        c = '?'; /* fallback for non-ASCII basic parser */
                    }
                    break;
                }
                default: break;
            }
        }
        if (len + 2 > cap) {
            cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        buf[len++] = c;
        (*p)++;
    }

    if (err_buf) snprintf(err_buf, err_len, "Unterminated string");
    free(buf);
    return NULL;
}

static json_value_t *parse_string(const char **p, char *err_buf, size_t err_len) {
    char *s = parse_string_raw(p, err_buf, err_len);
    if (!s) return NULL;
    json_value_t *val = json_val_alloc(JSON_TYPE_STRING);
    if (!val) { free(s); return NULL; }
    val->u.str_val = s;
    return val;
}

static json_value_t *parse_number(const char **p) {
    char *endptr = NULL;
    double num = strtod(*p, &endptr);
    if (endptr == *p) return NULL;
    *p = endptr;
    json_value_t *val = json_val_alloc(JSON_TYPE_NUMBER);
    if (val) val->u.num_val = num;
    return val;
}

static json_value_t *parse_array(const char **p, char *err_buf, size_t err_len) {
    if (**p != '[') return NULL;
    (*p)++; /* skip '[' */
    skip_whitespace(p);

    json_value_t *arr = json_val_alloc(JSON_TYPE_ARRAY);
    if (!arr) return NULL;

    if (**p == ']') {
        (*p)++;
        return arr;
    }

    while (**p) {
        json_value_t *elem = parse_value(p, err_buf, err_len);
        if (!elem) {
            json_free(arr);
            return NULL;
        }
        if (arr->u.array.count + 1 > arr->u.array.cap) {
            size_t new_cap = arr->u.array.cap ? arr->u.array.cap * 2 : 8;
            json_value_t **new_items = (json_value_t **)realloc(arr->u.array.items, new_cap * sizeof(json_value_t *));
            if (!new_items) {
                json_free(elem);
                json_free(arr);
                return NULL;
            }
            arr->u.array.items = new_items;
            arr->u.array.cap = new_cap;
        }
        arr->u.array.items[arr->u.array.count++] = elem;

        skip_whitespace(p);
        if (**p == ',') {
            (*p)++;
            skip_whitespace(p);
        } else if (**p == ']') {
            (*p)++;
            return arr;
        } else {
            if (err_buf) snprintf(err_buf, err_len, "Expected ',' or ']' in array");
            json_free(arr);
            return NULL;
        }
    }

    if (err_buf) snprintf(err_buf, err_len, "Unterminated array");
    json_free(arr);
    return NULL;
}

static json_value_t *parse_object(const char **p, char *err_buf, size_t err_len) {
    if (**p != '{') return NULL;
    (*p)++; /* skip '{' */
    skip_whitespace(p);

    json_value_t *obj = json_val_alloc(JSON_TYPE_OBJECT);
    if (!obj) return NULL;

    if (**p == '}') {
        (*p)++;
        return obj;
    }

    while (**p) {
        if (**p != '\"') {
            if (err_buf) snprintf(err_buf, err_len, "Expected string key in object");
            json_free(obj);
            return NULL;
        }
        char *key = parse_string_raw(p, err_buf, err_len);
        if (!key) {
            json_free(obj);
            return NULL;
        }
        skip_whitespace(p);
        if (**p != ':') {
            if (err_buf) snprintf(err_buf, err_len, "Expected ':' after object key");
            free(key);
            json_free(obj);
            return NULL;
        }
        (*p)++; /* skip ':' */
        skip_whitespace(p);

        json_value_t *val = parse_value(p, err_buf, err_len);
        if (!val) {
            free(key);
            json_free(obj);
            return NULL;
        }

        if (obj->u.object.count + 1 > obj->u.object.cap) {
            size_t new_cap = obj->u.object.cap ? obj->u.object.cap * 2 : 8;
            char **new_keys = (char **)realloc(obj->u.object.keys, new_cap * sizeof(char *));
            json_value_t **new_vals = (json_value_t **)realloc(obj->u.object.values, new_cap * sizeof(json_value_t *));
            if (!new_keys || !new_vals) {
                free(key);
                json_free(val);
                json_free(obj);
                return NULL;
            }
            obj->u.object.keys = new_keys;
            obj->u.object.values = new_vals;
            obj->u.object.cap = new_cap;
        }
        obj->u.object.keys[obj->u.object.count] = key;
        obj->u.object.values[obj->u.object.count] = val;
        obj->u.object.count++;

        skip_whitespace(p);
        if (**p == ',') {
            (*p)++;
            skip_whitespace(p);
        } else if (**p == '}') {
            (*p)++;
            return obj;
        } else {
            if (err_buf) snprintf(err_buf, err_len, "Expected ',' or '}' in object");
            json_free(obj);
            return NULL;
        }
    }

    if (err_buf) snprintf(err_buf, err_len, "Unterminated object");
    json_free(obj);
    return NULL;
}

static json_value_t *parse_value(const char **p, char *err_buf, size_t err_len) {
    skip_whitespace(p);
    if (!**p) {
        if (err_buf) snprintf(err_buf, err_len, "Unexpected end of input");
        return NULL;
    }

    switch (**p) {
        case '{': return parse_object(p, err_buf, err_len);
        case '[': return parse_array(p, err_buf, err_len);
        case '\"': return parse_string(p, err_buf, err_len);
        case 't':
            if (strncmp(*p, "true", 4) == 0) {
                *p += 4;
                json_value_t *v = json_val_alloc(JSON_TYPE_BOOL);
                if (v) v->u.bool_val = true;
                return v;
            }
            break;
        case 'f':
            if (strncmp(*p, "false", 5) == 0) {
                *p += 5;
                json_value_t *v = json_val_alloc(JSON_TYPE_BOOL);
                if (v) v->u.bool_val = false;
                return v;
            }
            break;
        case 'n':
            if (strncmp(*p, "null", 4) == 0) {
                *p += 4;
                return json_val_alloc(JSON_TYPE_NULL);
            }
            break;
        default:
            if (**p == '-' || (**p >= '0' && **p <= '9')) {
                return parse_number(p);
            }
            break;
    }

    if (err_buf) snprintf(err_buf, err_len, "Unexpected character '%c'", **p);
    return NULL;
}

json_value_t *json_parse(const char *text, char *err_buf, size_t err_len) {
    if (!text) {
        if (err_buf) snprintf(err_buf, err_len, "Null input");
        return NULL;
    }
    const char *p = text;
    json_value_t *val = parse_value(&p, err_buf, err_len);
    if (!val) return NULL;
    skip_whitespace(&p);
    return val;
}

/* -------------------------------------------------------------
 * Accessors
 * ------------------------------------------------------------- */

const json_value_t *json_obj_get(const json_value_t *val, const char *key) {
    if (!val || val->type != JSON_TYPE_OBJECT || !key) return NULL;
    for (size_t i = 0; i < val->u.object.count; ++i) {
        if (strcmp(val->u.object.keys[i], key) == 0) {
            return val->u.object.values[i];
        }
    }
    return NULL;
}

const char *json_obj_get_str(const json_value_t *val, const char *key, const char *def) {
    const json_value_t *v = json_obj_get(val, key);
    if (!v || v->type != JSON_TYPE_STRING) return def;
    return v->u.str_val;
}

int64_t json_obj_get_int(const json_value_t *val, const char *key, int64_t def) {
    const json_value_t *v = json_obj_get(val, key);
    if (!v) return def;
    if (v->type == JSON_TYPE_NUMBER) return (int64_t)v->u.num_val;
    if (v->type == JSON_TYPE_BOOL) return v->u.bool_val ? 1 : 0;
    return def;
}

double json_obj_get_num(const json_value_t *val, const char *key, double def) {
    const json_value_t *v = json_obj_get(val, key);
    if (!v || v->type != JSON_TYPE_NUMBER) return def;
    return v->u.num_val;
}

bool json_obj_get_bool(const json_value_t *val, const char *key, bool def) {
    const json_value_t *v = json_obj_get(val, key);
    if (!v) return def;
    if (v->type == JSON_TYPE_BOOL) return v->u.bool_val;
    if (v->type == JSON_TYPE_NUMBER) return (v->u.num_val != 0.0);
    return def;
}

size_t json_arr_len(const json_value_t *val) {
    if (!val || val->type != JSON_TYPE_ARRAY) return 0;
    return val->u.array.count;
}

const json_value_t *json_arr_get(const json_value_t *val, size_t index) {
    if (!val || val->type != JSON_TYPE_ARRAY || index >= val->u.array.count) return NULL;
    return val->u.array.items[index];
}

/* -------------------------------------------------------------
 * Rule Serialization and Deserialization
 * ------------------------------------------------------------- */

static int parse_ip_field(const char *str, ip4_t *out_ip, ip4_t *out_mask, ip4_t *out_end) {
    if (!str || !*str || strcmp(str, "any") == 0) {
        *out_ip = 0;
        *out_mask = 0xFFFFFFFF;
        *out_end = 0;
        return 0;
    }
    const char *slash = strchr(str, '/');
    if (slash) {
        char ip_part[32];
        size_t len = (size_t)(slash - str);
        if (len >= sizeof(ip_part)) return -1;
        memcpy(ip_part, str, len);
        ip_part[len] = '\0';
        if (str_to_ip(ip_part, out_ip) != 0) return -1;
        int cidr = atoi(slash + 1);
        if (cidr < 0 || cidr > 32) return -1;
        *out_mask = cidr_to_mask((uint8_t)cidr);
        *out_end = *out_ip;
        return 0;
    }
    const char *dash = strchr(str, '-');
    if (dash) {
        char start_ip[32];
        size_t len = (size_t)(dash - str);
        if (len >= sizeof(start_ip)) return -1;
        memcpy(start_ip, str, len);
        start_ip[len] = '\0';
        if (str_to_ip(start_ip, out_ip) != 0) return -1;
        if (str_to_ip(dash + 1, out_end) != 0) return -1;
        *out_mask = 0xFFFFFFFF;
        return 0;
    }
    /* Single IP */
    if (str_to_ip(str, out_ip) != 0) return -1;
    *out_mask = 0xFFFFFFFF;
    *out_end = *out_ip;
    return 0;
}

static int parse_port_field(const json_value_t *val, uint16_t *out_port, uint16_t *out_port_end) {
    if (!val || val->type == JSON_TYPE_NULL) {
        *out_port = 0;
        *out_port_end = 0;
        return 0;
    }
    if (val->type == JSON_TYPE_NUMBER) {
        int p = (int)val->u.num_val;
        if (p < 0 || p > 65535) return -1;
        *out_port = (uint16_t)p;
        *out_port_end = (uint16_t)p;
        return 0;
    }
    if (val->type == JSON_TYPE_STRING) {
        const char *s = val->u.str_val;
        if (!s || !*s || strcmp(s, "any") == 0) {
            *out_port = 0;
            *out_port_end = 0;
            return 0;
        }
        const char *dash = strchr(s, '-');
        if (!dash) dash = strstr(s, "..");
        if (dash) {
            char p1[16];
            size_t len = (size_t)(dash - s);
            if (len >= sizeof(p1)) return -1;
            memcpy(p1, s, len);
            p1[len] = '\0';
            const char *p2 = (dash[0] == '.') ? (dash + 2) : (dash + 1);
            int sp = atoi(p1);
            int ep = atoi(p2);
            if (sp < 0 || sp > 65535 || ep < 0 || ep > 65535) return -1;
            *out_port = (uint16_t)sp;
            *out_port_end = (uint16_t)ep;
            return 0;
        }
        int p = atoi(s);
        if (p < 0 || p > 65535) return -1;
        *out_port = (uint16_t)p;
        *out_port_end = (uint16_t)p;
        return 0;
    }
    return -1;
}

int json_parse_rule(const json_value_t *val, rule_t *rule) {
    if (!val || val->type != JSON_TYPE_OBJECT || !rule) return -1;
    memset(rule, 0, sizeof(*rule));

    /* id */
    int64_t id = json_obj_get_int(val, "id", 0);
    if (id < 1 || id > 65535) return -1;
    rule->id = (rule_id_t)id;

    /* active */
    rule->active = json_obj_get_bool(val, "active", true) ? 1 : 0;

    /* log */
    rule->log = json_obj_get_bool(val, "log", false) ? 1 : 0;

    /* in_iface / in */
    const json_value_t *in_v = json_obj_get(val, "in_iface");
    if (!in_v) in_v = json_obj_get(val, "in");
    if (in_v) {
        if (in_v->type == JSON_TYPE_NUMBER) {
            rule->in_iface = (int8_t)in_v->u.num_val;
        } else if (in_v->type == JSON_TYPE_STRING) {
            if (strcmp(in_v->u.str_val, "any") == 0 || in_v->u.str_val[0] == '\0') {
                rule->in_iface = -1;
            } else {
                int8_t idx = io_get_iface_index_by_name(in_v->u.str_val);
                if (idx >= 0) {
                    rule->in_iface = idx;
                } else if (in_v->u.str_val[0] >= '0' && in_v->u.str_val[0] <= '9') {
                    rule->in_iface = (int8_t)atoi(in_v->u.str_val);
                } else {
                    return -1;
                }
            }
        } else {
            rule->in_iface = -1;
        }
    } else {
        rule->in_iface = -1;
    }

    /* smac */
    const char *smac_str = json_obj_get_str(val, "smac", NULL);
    if (smac_str && *smac_str && strcmp(smac_str, "any") != 0) {
        if (str_to_mac(smac_str, &rule->smac) != 0) return -1;
    } else {
        rule->smac = 0;
    }

    /* dmac */
    const char *dmac_str = json_obj_get_str(val, "dmac", NULL);
    if (dmac_str && *dmac_str && strcmp(dmac_str, "any") != 0) {
        if (str_to_mac(dmac_str, &rule->dmac) != 0) return -1;
    } else {
        rule->dmac = 0;
    }

    /* src */
    const char *src_str = json_obj_get_str(val, "src", NULL);
    if (parse_ip_field(src_str, &rule->src, &rule->src_mask, &rule->src_end) != 0) return -1;

    /* dst */
    const char *dst_str = json_obj_get_str(val, "dst", NULL);
    if (parse_ip_field(dst_str, &rule->dst, &rule->dst_mask, &rule->dst_end) != 0) return -1;

    /* proto */
    const json_value_t *pv = json_obj_get(val, "proto");
    if (!pv || pv->type == JSON_TYPE_NULL) {
        rule->proto = 0;
    } else if (pv->type == JSON_TYPE_NUMBER) {
        rule->proto = (uint8_t)pv->u.num_val;
    } else if (pv->type == JSON_TYPE_STRING) {
        if (strcasecmp(pv->u.str_val, "tcp") == 0) rule->proto = 6;
        else if (strcasecmp(pv->u.str_val, "udp") == 0) rule->proto = 17;
        else if (strcasecmp(pv->u.str_val, "icmp") == 0) rule->proto = 1;
        else rule->proto = 0;
    }

    /* eth_proto */
    const char *eth_proto_str = json_obj_get_str(val, "eth_proto", "any");
    if (strcasecmp(eth_proto_str, "arp") == 0) {
        rule->eth_proto = ETH_PROTO_ARP;
    } else if (strcasecmp(eth_proto_str, "other") == 0) {
        rule->eth_proto = ETH_PROTO_OTHER;
    } else {
        rule->eth_proto = ETH_PROTO_ANY;
    }

    /* sport */
    if (parse_port_field(json_obj_get(val, "sport"), &rule->sport, &rule->sport_end) != 0) return -1;

    /* dport */
    if (parse_port_field(json_obj_get(val, "dport"), &rule->dport, &rule->dport_end) != 0) return -1;

    /* icmp_type & icmp_code */
    rule->icmp_type = (uint8_t)json_obj_get_int(val, "icmp_type", 255);
    rule->icmp_code = (uint8_t)json_obj_get_int(val, "icmp_code", 255);

    /* action */
    const char *action_str = json_obj_get_str(val, "action", "drop");
    if (strcasecmp(action_str, "accept") == 0) {
        rule->action = ACTION_ACCEPT;
    } else if (strcasecmp(action_str, "goto") == 0) {
        rule->action = ACTION_GOTO;
    } else {
        rule->action = ACTION_DROP;
    }

    /* out_ifaces / out */
    for (int i = 0; i < MAX_INTERFACES; ++i) rule->out_ifaces[i] = -1;
    const json_value_t *out_arr = json_obj_get(val, "out_ifaces");
    if (!out_arr) out_arr = json_obj_get(val, "out");
    if (out_arr && out_arr->type == JSON_TYPE_ARRAY) {
        size_t n = json_arr_len(out_arr);
        size_t written = 0;
        for (size_t i = 0; i < n && written < MAX_INTERFACES; ++i) {
            const json_value_t *if_v = json_arr_get(out_arr, i);
            if (!if_v) continue;
            if (if_v->type == JSON_TYPE_NUMBER) {
                rule->out_ifaces[written++] = (int8_t)if_v->u.num_val;
            } else if (if_v->type == JSON_TYPE_STRING) {
                int8_t idx = io_get_iface_index_by_name(if_v->u.str_val);
                if (idx >= 0) {
                    rule->out_ifaces[written++] = idx;
                } else if (if_v->u.str_val[0] >= '0' && if_v->u.str_val[0] <= '9') {
                    rule->out_ifaces[written++] = (int8_t)atoi(if_v->u.str_val);
                } else {
                    return -1;
                }
            }
        }
    }

    /* to_rule */
    rule->to_rule = (rule_id_t)json_obj_get_int(val, "to_rule", 0);

    /* conntrack (поддержка "conntrack": true или "state": "on" по validation.json) */
    bool ct_enabled = json_obj_get_bool(val, "conntrack", false);
    const char *state_str = json_obj_get_str(val, "state", NULL);
    if (state_str && (strcasecmp(state_str, "on") == 0 || strcmp(state_str, "1") == 0 || strcasecmp(state_str, "true") == 0)) {
        ct_enabled = true;
    }
    rule->conntrack = ct_enabled ? 1 : 0;

    /* comment */
    const char *comment = json_obj_get_str(val, "comment", "");
    strncpy(rule->comment, comment, MAX_COMMENT_LEN - 1);
    rule->comment[MAX_COMMENT_LEN - 1] = '\0';

    /* hits */
    rule->hits = (uint64_t)json_obj_get_int(val, "hits", 0);

    return 0;
}

static void format_ip_field(ip4_t ip, ip4_t mask, ip4_t end, char *buf, size_t buf_len) {
    if (ip == 0 && end == 0) {
        snprintf(buf, buf_len, "null");
        return;
    }
    if (mask != 0xFFFFFFFF && mask != 0) {
        int cidr = mask_to_cidr(mask);
        char ip_str[16];
        ip_to_str(ip, ip_str, sizeof(ip_str));
        snprintf(buf, buf_len, "\"%s/%d\"", ip_str, cidr);
    } else if (end != 0 && end != ip) {
        char s_str[16], e_str[16];
        ip_to_str(ip, s_str, sizeof(s_str));
        ip_to_str(end, e_str, sizeof(e_str));
        snprintf(buf, buf_len, "\"%s-%s\"", s_str, e_str);
    } else {
        char ip_str[16];
        ip_to_str(ip, ip_str, sizeof(ip_str));
        snprintf(buf, buf_len, "\"%s\"", ip_str);
    }
}

static void format_port_field(uint16_t sport, uint16_t sport_end, char *buf, size_t buf_len) {
    if (sport == 0 && sport_end == 0) {
        snprintf(buf, buf_len, "null");
    } else if (sport_end > sport) {
        snprintf(buf, buf_len, "\"%u-%u\"", sport, sport_end);
    } else {
        snprintf(buf, buf_len, "%u", sport);
    }
}

void json_serialize_rule(json_buf_t *buf, const rule_t *rule) {
    if (!buf || !rule) return;

    char smac_buf[32], dmac_buf[32];
    if (rule->smac != 0) {
        char mac_str[24];
        mac_to_str(rule->smac, mac_str, sizeof(mac_str));
        snprintf(smac_buf, sizeof(smac_buf), "\"%s\"", mac_str);
    } else {
        snprintf(smac_buf, sizeof(smac_buf), "null");
    }

    if (rule->dmac != 0) {
        char mac_str[24];
        mac_to_str(rule->dmac, mac_str, sizeof(mac_str));
        snprintf(dmac_buf, sizeof(dmac_buf), "\"%s\"", mac_str);
    } else {
        snprintf(dmac_buf, sizeof(dmac_buf), "null");
    }

    char src_buf[64], dst_buf[64];
    format_ip_field(rule->src, rule->src_mask, rule->src_end, src_buf, sizeof(src_buf));
    format_ip_field(rule->dst, rule->dst_mask, rule->dst_end, dst_buf, sizeof(dst_buf));

    char sport_buf[32], dport_buf[32];
    format_port_field(rule->sport, rule->sport_end, sport_buf, sizeof(sport_buf));
    format_port_field(rule->dport, rule->dport_end, dport_buf, sizeof(dport_buf));

    const char *action_str = (rule->action == ACTION_ACCEPT) ? "accept" :
                             (rule->action == ACTION_GOTO) ? "goto" : "drop";
    const char *eth_proto_str = (rule->eth_proto == ETH_PROTO_ARP) ? "arp" :
                                (rule->eth_proto == ETH_PROTO_OTHER) ? "other" : "any";

    json_buf_printf(buf,
        "{\"id\":%u,\"active\":%s,\"log\":%s,\"in_iface\":%d,"
        "\"smac\":%s,\"dmac\":%s,\"src\":%s,\"dst\":%s,"
        "\"proto\":%u,\"eth_proto\":\"%s\",\"sport\":%s,\"dport\":%s,",
        rule->id,
        rule->active ? "true" : "false",
        rule->log ? "true" : "false",
        rule->in_iface,
        smac_buf, dmac_buf, src_buf, dst_buf,
        rule->proto, eth_proto_str, sport_buf, dport_buf);

    if (rule->icmp_type != 255) json_buf_printf(buf, "\"icmp_type\":%u,", rule->icmp_type);
    else json_buf_append(buf, "\"icmp_type\":null,");

    if (rule->icmp_code != 255) json_buf_printf(buf, "\"icmp_code\":%u,", rule->icmp_code);
    else json_buf_append(buf, "\"icmp_code\":null,");

    json_buf_printf(buf, "\"action\":\"%s\",\"out_ifaces\":[", action_str);
    bool first_out = true;
    for (int i = 0; i < MAX_INTERFACES && rule->out_ifaces[i] >= 0; ++i) {
        if (!first_out) json_buf_append(buf, ",");
        first_out = false;
        json_buf_printf(buf, "%d", rule->out_ifaces[i]);
    }
    json_buf_append(buf, "],");

    if (rule->action == ACTION_GOTO) {
        json_buf_printf(buf, "\"to_rule\":%u,", rule->to_rule);
    } else {
        json_buf_append(buf, "\"to_rule\":null,");
    }

    json_buf_printf(buf, "\"conntrack\":%s,\"comment\":", rule->conntrack ? "true" : "false");
    json_buf_append_escaped(buf, rule->comment);
    json_buf_printf(buf, ",\"hits\":%llu}", (unsigned long long)rule->hits);
}
