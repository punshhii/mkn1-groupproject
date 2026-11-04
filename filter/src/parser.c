/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      parser
 * Назначение:  разбор заголовков Ethernet, ARP, IPv4, TCP, UDP, ICMP
 * Методы:
 *   - parse_frame — разобрать сетевой кадр и проверить корректность заголовков
 *   - parser_ip_checksum — вычислить/проверить контрольную сумму IPv4 (RFC 791)
 */
#include "parser.h"
#include "net_utils.h"

#include <string.h>

#define ETH_HLEN 14
#define ETH_P_IP_VAL  0x0800
#define ETH_P_ARP_VAL 0x0806
#define ETH_P_IPV6_VAL 0x86DD

uint16_t parser_ip_checksum(const void *ip_hdr, size_t ihl_bytes)
{
    const uint8_t *data = (const uint8_t *)ip_hdr;
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < ihl_bytes; i += 2) {
        uint16_t word = ((uint16_t)data[i] << 8) | (uint16_t)data[i + 1];
        sum += word;
    }

    if (ihl_bytes & 1) {
        uint16_t word = ((uint16_t)data[ihl_bytes - 1] << 8);
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum & 0xFFFF);
}

parse_result_t parse_frame(const unsigned char *buf, unsigned len, int8_t in_iface, parsed_packet_t *out_pkt)
{
    if (!buf || !out_pkt) {
        return PARSE_DROP_MALFORMED;
    }

    memset(out_pkt, 0, sizeof(*out_pkt));
    out_pkt->in_iface = in_iface;
    out_pkt->raw_frame = buf;
    out_pkt->raw_len = len;

    /* 1. L2: Заголовок Ethernet (минимум 14 байт) */
    if (len < ETH_HLEN) {
        return PARSE_DROP_MALFORMED;
    }

    out_pkt->dmac = mac_to_u64(&buf[0]);
    out_pkt->smac = mac_to_u64(&buf[6]);
    out_pkt->eth_type = ((uint16_t)buf[12] << 8) | (uint16_t)buf[13];
    out_pkt->l3_offset = ETH_HLEN;

    /* Классификация Ethernet-протокола */
    if (out_pkt->eth_type == ETH_P_ARP_VAL) {
        out_pkt->eth_proto = ETH_PROTO_ARP;
        /* Минимальный размер кадра ARP для IPv4/Ethernet: 14 + 28 = 42 байта */
        if (len < ETH_HLEN + 28) {
            return PARSE_DROP_MALFORMED;
        }
        return PARSE_ARP;
    }

    if (out_pkt->eth_type != ETH_P_IP_VAL) {
        /* Все прочие протоколы (включая IPv6) классифицируются как ETH_PROTO_OTHER (FR-11) */
        out_pkt->eth_proto = ETH_PROTO_OTHER;
        return PARSE_OTHER_ETH;
    }

    /* 2. L3: Заголовок IPv4 */
    out_pkt->eth_proto = ETH_PROTO_ANY;
    size_t ip_avail = len - ETH_HLEN;
    if (ip_avail < 20) {
        return PARSE_DROP_MALFORMED;
    }

    const uint8_t *ip = &buf[ETH_HLEN];
    uint8_t ver_ihl = ip[0];
    uint8_t version = ver_ihl >> 4;
    uint8_t ihl = ver_ihl & 0x0F;

    /* FR-12: версия должна быть строго 4 */
    if (version != 4) {
        return PARSE_DROP_MALFORMED;
    }

    /* FR-12: длина заголовка IHL должна быть не менее 5 (20 байт) */
    if (ihl < 5) {
        return PARSE_DROP_MALFORMED;
    }

    size_t ihl_bytes = (size_t)ihl * 4;
    if (ihl_bytes > ip_avail) {
        return PARSE_DROP_MALFORMED;
    }

    /* FR-12: проверка полной длины пакета (tot_len) */
    uint16_t tot_len = ((uint16_t)ip[2] << 8) | (uint16_t)ip[3];
    if (tot_len < ihl_bytes || tot_len > ip_avail) {
        return PARSE_DROP_MALFORMED;
    }

    /* FR-12: проверка контрольной суммы заголовка IPv4 */
    if (parser_ip_checksum(ip, ihl_bytes) != 0) {
        return PARSE_DROP_MALFORMED;
    }

    out_pkt->ip_tos = ip[1];
    out_pkt->ip_ttl = ip[8];
    out_pkt->ip_proto = ip[9];
    out_pkt->src_ip = ((ip4_t)ip[12] << 24) | ((ip4_t)ip[13] << 16) |
                      ((ip4_t)ip[14] << 8)  | (ip4_t)ip[15];
    out_pkt->dst_ip = ((ip4_t)ip[16] << 24) | ((ip4_t)ip[17] << 16) |
                      ((ip4_t)ip[18] << 8)  | (ip4_t)ip[19];

    out_pkt->l4_offset = ETH_HLEN + ihl_bytes;
    size_t l4_avail = tot_len - ihl_bytes;

    /* Проверка флагов фрагментации: смещение фрагмента */
    uint16_t frag_field = ((uint16_t)ip[6] << 8) | (uint16_t)ip[7];
    uint16_t frag_offset = frag_field & 0x1FFF;
    if (frag_offset != 0) {
        /* Не первый фрагмент: заголовки L4 отсутствуют */
        out_pkt->payload_offset = out_pkt->l4_offset;
        out_pkt->payload_len = l4_avail;
        return PARSE_OK;
    }

    /* 3. L4: Разбор транспортного уровня */
    const uint8_t *l4 = &buf[out_pkt->l4_offset];

    if (out_pkt->ip_proto == 6) {
        /* TCP */
        if (l4_avail < 20) {
            return PARSE_DROP_MALFORMED;
        }

        out_pkt->sport = ((uint16_t)l4[0] << 8) | (uint16_t)l4[1];
        out_pkt->dport = ((uint16_t)l4[2] << 8) | (uint16_t)l4[3];

        uint8_t data_offset = l4[12] >> 4;
        if (data_offset < 5) {
            return PARSE_DROP_MALFORMED;
        }

        size_t tcp_hdr_len = (size_t)data_offset * 4;
        if (tcp_hdr_len > l4_avail) {
            return PARSE_DROP_MALFORMED;
        }

        out_pkt->tcp_flags = l4[13] & 0x3F;
        out_pkt->payload_offset = out_pkt->l4_offset + tcp_hdr_len;
        out_pkt->payload_len = l4_avail - tcp_hdr_len;

    } else if (out_pkt->ip_proto == 17) {
        /* UDP */
        if (l4_avail < 8) {
            return PARSE_DROP_MALFORMED;
        }

        out_pkt->sport = ((uint16_t)l4[0] << 8) | (uint16_t)l4[1];
        out_pkt->dport = ((uint16_t)l4[2] << 8) | (uint16_t)l4[3];

        uint16_t udp_len = ((uint16_t)l4[4] << 8) | (uint16_t)l4[5];
        if (udp_len < 8 || udp_len > l4_avail) {
            return PARSE_DROP_MALFORMED;
        }

        out_pkt->payload_offset = out_pkt->l4_offset + 8;
        out_pkt->payload_len = udp_len - 8;

    } else if (out_pkt->ip_proto == 1) {
        /* ICMPv4 */
        if (l4_avail < 4) {
            return PARSE_DROP_MALFORMED;
        }

        out_pkt->icmp_type = l4[0];
        out_pkt->icmp_code = l4[1];

        if (out_pkt->icmp_type == 8 || out_pkt->icmp_type == 0) {
            /* Echo Request или Echo Reply */
            if (l4_avail < 8) {
                return PARSE_DROP_MALFORMED;
            }
            out_pkt->icmp_id = ((uint16_t)l4[4] << 8) | (uint16_t)l4[5];
            out_pkt->icmp_seq = ((uint16_t)l4[6] << 8) | (uint16_t)l4[7];
            out_pkt->payload_offset = out_pkt->l4_offset + 8;
            out_pkt->payload_len = l4_avail - 8;
        } else {
            out_pkt->payload_offset = out_pkt->l4_offset + 4;
            out_pkt->payload_len = l4_avail - 4;
        }

    } else {
        /* Прочие протоколы IP */
        out_pkt->payload_offset = out_pkt->l4_offset;
        out_pkt->payload_len = l4_avail;
    }

    return PARSE_OK;
}
