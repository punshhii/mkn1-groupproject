/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      parser
 * Назначение:  разбор заголовков Ethernet, ARP, IPv4, TCP, UDP, ICMP
 * Методы:
 *   - parse_frame — разобрать сетевой кадр и проверить корректность заголовков
 *   - parser_ip_checksum — вычислить/проверить контрольную сумму IPv4 (RFC 791)
 */
#ifndef FW_PARSER_H
#define FW_PARSER_H

#include <stddef.h>
#include <stdint.h>
#include "types.h"

/* Результаты разбора сетевого кадра */
typedef enum {
    PARSE_OK = 0,               /* Успешно разобран IPv4-пакет */
    PARSE_ARP = 1,              /* Разобран ARP-кадр */
    PARSE_OTHER_ETH = 2,        /* Другой протокол Ethernet (включая IPv6) */
    PARSE_DROP_MALFORMED = -1   /* Некорректный или усечённый заголовок (FR-12) */
} parse_result_t;

/* Флаги заголовка TCP */
#define FW_TCP_FIN  0x01
#define FW_TCP_SYN  0x02
#define FW_TCP_RST  0x04
#define FW_TCP_PSH  0x08
#define FW_TCP_ACK  0x10
#define FW_TCP_URG  0x20

/* Структура разобранного сетевого пакета */
typedef struct {
    int8_t      in_iface;       /* Индекс входного интерфейса (0..MAX_INTERFACES-1) */
    mac_t       smac;           /* MAC-адрес источника (uint64_t, 48 бит) */
    mac_t       dmac;           /* MAC-адрес назначения */
    uint16_t    eth_type;       /* EtherType кадра */
    eth_proto_t eth_proto;      /* ETH_PROTO_ANY / ETH_PROTO_ARP / ETH_PROTO_OTHER */

    /* Поля IPv4 */
    ip4_t       src_ip;         /* IPv4 источника (host byte order) */
    ip4_t       dst_ip;         /* IPv4 назначения (host byte order) */
    uint8_t     ip_proto;       /* 6 = TCP, 17 = UDP, 1 = ICMP, иначе номер протокола */
    uint8_t     ip_tos;         /* Type of service */
    uint8_t     ip_ttl;         /* Time to live */

    /* Поля L4 (TCP / UDP) */
    uint16_t    sport;          /* Порт источника (host byte order) */
    uint16_t    dport;          /* Порт назначения (host byte order) */
    uint8_t     tcp_flags;      /* Маска флагов TCP (SYN, ACK, FIN, RST...) */

    /* Поля ICMPv4 */
    uint8_t     icmp_type;      /* Тип ICMP (0..255) */
    uint8_t     icmp_code;      /* Код ICMP (0..255) */
    uint16_t    icmp_id;        /* Echo Identifier (host byte order) */
    uint16_t    icmp_seq;       /* Echo Sequence number (host byte order) */

    /* Смещения и указатели на сырые данные */
    const uint8_t *raw_frame;   /* Указатель на начало кадра */
    size_t         raw_len;     /* Полная длина кадра в байтах */
    size_t         l3_offset;   /* Смещение заголовка L3 (для Ethernet = 14) */
    size_t         l4_offset;   /* Смещение заголовка L4 */
    size_t         payload_offset; /* Смещение данных полезной нагрузки */
    size_t         payload_len;    /* Длина полезной нагрузки в байтах */
} parsed_packet_t;

/**
 * Разобрать сетевой кадр и проверить корректность заголовков (FR-11, FR-12).
 *
 * @param buf       Указатель на сырой сетевой кадр
 * @param len       Длина сетевого кадра в байтах
 * @param in_iface  Индекс входного интерфейса (или -1, если не задан)
 * @param out_pkt   Выходная структура с разобранными полями
 * @return parse_result_t Результат разбора
 */
parse_result_t parse_frame(const unsigned char *buf, unsigned len, int8_t in_iface, parsed_packet_t *out_pkt);

/**
 * Вычислить или проверить 16-битную контрольную сумму IPv4 заголовка (RFC 791).
 *
 * @param ip_hdr    Указатель на заголовок IPv4
 * @param ihl_bytes Длина заголовка в байтах (IHL * 4)
 * @return uint16_t Результат (0, если контрольная сумма в заголовке корректна)
 */
uint16_t parser_ip_checksum(const void *ip_hdr, size_t ihl_bytes);

#endif /* FW_PARSER_H */
