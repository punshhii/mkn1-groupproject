/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      test_parser
 * Назначение:  модульные тесты разбора сетевых заголовков (parser, net_utils)
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "parser.h"
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

static void helper_calc_ip_csum(uint8_t *ip_hdr, size_t ihl_bytes)
{
    ip_hdr[10] = 0;
    ip_hdr[11] = 0;
    uint16_t csum = parser_ip_checksum(ip_hdr, ihl_bytes);
    ip_hdr[10] = (uint8_t)(csum >> 8);
    ip_hdr[11] = (uint8_t)(csum & 0xFF);
}

static void test_net_utils(void)
{
    /* MAC */
    uint8_t mac_bytes[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    mac_t m = mac_to_u64(mac_bytes);
    uint8_t out_mac[6];
    u64_to_mac(m, out_mac);
    TEST_ASSERT(memcmp(mac_bytes, out_mac, 6) == 0);

    char mac_buf[32];
    TEST_ASSERT(mac_to_str(m, mac_buf, sizeof(mac_buf)) == 0);
    TEST_ASSERT(strcmp(mac_buf, "00:1A:2B:3C:4D:5E") == 0);

    mac_t parsed_mac = 0;
    TEST_ASSERT(str_to_mac("00:1a:2b:3c:4d:5e", &parsed_mac) == 0);
    TEST_ASSERT(parsed_mac == m);

    /* IP */
    ip4_t ip = 0;
    TEST_ASSERT(str_to_ip("192.168.1.100", &ip) == 0);
    TEST_ASSERT(ip == 0xC0A80164U);

    char ip_buf[32];
    TEST_ASSERT(ip_to_str(ip, ip_buf, sizeof(ip_buf)) == 0);
    TEST_ASSERT(strcmp(ip_buf, "192.168.1.100") == 0);

    /* CIDR */
    TEST_ASSERT(cidr_to_mask(24) == 0xFFFFFF00U);
    TEST_ASSERT(cidr_to_mask(0) == 0x00000000U);
    TEST_ASSERT(cidr_to_mask(32) == 0xFFFFFFFFU);
    TEST_ASSERT(mask_to_cidr(0xFFFFFF00U) == 24);
    TEST_ASSERT(mask_to_cidr(0xFFFFFFFFU) == 32);
    TEST_ASSERT(mask_to_cidr(0x00000000U) == 0);
}

static void test_valid_tcp(void)
{
    /* Ethernet (14) + IPv4 (20) + TCP (20) = 54 байта */
    uint8_t pkt[54];
    memset(pkt, 0, sizeof(pkt));

    /* Ethernet */
    uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    memcpy(&pkt[0], dst_mac, 6);
    memcpy(&pkt[6], src_mac, 6);
    pkt[12] = 0x08; pkt[13] = 0x00; /* IPv4 */

    /* IPv4 */
    pkt[14] = 0x45; /* Version 4, IHL 5 */
    pkt[15] = 0x00; /* TOS */
    pkt[16] = 0x00; pkt[17] = 40; /* Total length: 20 IP + 20 TCP = 40 */
    pkt[18] = 0x12; pkt[19] = 0x34; /* ID */
    pkt[20] = 0x40; pkt[21] = 0x00; /* DF */
    pkt[22] = 64;   /* TTL */
    pkt[23] = 6;    /* Protocol TCP */
    /* 10.0.0.1 -> 192.168.1.1 */
    pkt[26] = 10; pkt[27] = 0; pkt[28] = 0; pkt[29] = 1;
    pkt[30] = 192; pkt[31] = 168; pkt[32] = 1; pkt[33] = 1;
    helper_calc_ip_csum(&pkt[14], 20);

    /* TCP */
    /* sport = 54321 (0xD431), dport = 80 (0x0050) */
    pkt[34] = 0xD4; pkt[35] = 0x31;
    pkt[36] = 0x00; pkt[37] = 0x50;
    /* Seq num */
    pkt[38] = 0x01; pkt[39] = 0x02; pkt[40] = 0x03; pkt[41] = 0x04;
    /* Ack num */
    pkt[42] = 0x00; pkt[43] = 0x00; pkt[44] = 0x00; pkt[45] = 0x00;
    /* Data offset: 5 (20 bytes), flags: SYN (0x02) */
    pkt[46] = 0x50;
    pkt[47] = FW_TCP_SYN;
    pkt[48] = 0x72; pkt[49] = 0x10; /* Window */

    parsed_packet_t p;
    parse_result_t res = parse_frame(pkt, sizeof(pkt), 0, &p);

    TEST_ASSERT(res == PARSE_OK);
    TEST_ASSERT(p.in_iface == 0);
    TEST_ASSERT(p.smac == mac_to_u64(src_mac));
    TEST_ASSERT(p.dmac == mac_to_u64(dst_mac));
    TEST_ASSERT(p.eth_type == 0x0800);
    TEST_ASSERT(p.eth_proto == ETH_PROTO_ANY);
    TEST_ASSERT(p.src_ip == 0x0A000001U);
    TEST_ASSERT(p.dst_ip == 0xC0A80101U);
    TEST_ASSERT(p.ip_proto == 6);
    TEST_ASSERT(p.sport == 54321);
    TEST_ASSERT(p.dport == 80);
    TEST_ASSERT(p.tcp_flags == FW_TCP_SYN);
    TEST_ASSERT(p.payload_len == 0);
}

static void test_valid_udp(void)
{
    /* Ethernet (14) + IPv4 (20) + UDP (8) + payload (4) = 46 байт */
    uint8_t pkt[46];
    memset(pkt, 0, sizeof(pkt));

    pkt[12] = 0x08; pkt[13] = 0x00; /* IPv4 */
    pkt[14] = 0x45;
    pkt[16] = 0x00; pkt[17] = 32; /* Total length: 20 + 8 + 4 = 32 */
    pkt[22] = 64;
    pkt[23] = 17;   /* Protocol UDP */
    pkt[26] = 172; pkt[27] = 16; pkt[28] = 0; pkt[29] = 5;
    pkt[30] = 8; pkt[31] = 8; pkt[32] = 8; pkt[33] = 8;
    helper_calc_ip_csum(&pkt[14], 20);

    /* UDP */
    pkt[34] = 0x04; pkt[35] = 0xD2; /* sport = 1234 */
    pkt[36] = 0x00; pkt[37] = 0x35; /* dport = 53 */
    pkt[38] = 0x00; pkt[39] = 12;   /* UDP len = 12 (8 hdr + 4 data) */
    pkt[40] = 0x00; pkt[41] = 0x00; /* Checksum */
    memcpy(&pkt[42], "PING", 4);

    parsed_packet_t p;
    parse_result_t res = parse_frame(pkt, sizeof(pkt), 1, &p);

    TEST_ASSERT(res == PARSE_OK);
    TEST_ASSERT(p.in_iface == 1);
    TEST_ASSERT(p.ip_proto == 17);
    TEST_ASSERT(p.sport == 1234);
    TEST_ASSERT(p.dport == 53);
    TEST_ASSERT(p.payload_len == 4);
    TEST_ASSERT(memcmp(&pkt[p.payload_offset], "PING", 4) == 0);
}

static void test_valid_icmp_echo(void)
{
    /* Ethernet (14) + IPv4 (20) + ICMP (8) = 42 байта */
    uint8_t pkt[42];
    memset(pkt, 0, sizeof(pkt));

    pkt[12] = 0x08; pkt[13] = 0x00;
    pkt[14] = 0x45;
    pkt[16] = 0x00; pkt[17] = 28; /* Total length: 20 + 8 = 28 */
    pkt[22] = 64;
    pkt[23] = 1; /* ICMP */
    pkt[26] = 192; pkt[27] = 168; pkt[28] = 1; pkt[29] = 10;
    pkt[30] = 192; pkt[31] = 168; pkt[32] = 1; pkt[33] = 20;
    helper_calc_ip_csum(&pkt[14], 20);

    /* ICMP Echo Request */
    pkt[34] = 8; /* Type 8 = Echo Request */
    pkt[35] = 0; /* Code 0 */
    pkt[36] = 0; pkt[37] = 0; /* Checksum */
    pkt[38] = 0x12; pkt[39] = 0x34; /* ID = 0x1234 */
    pkt[40] = 0x00; pkt[41] = 0x01; /* Seq = 1 */

    parsed_packet_t p;
    parse_result_t res = parse_frame(pkt, sizeof(pkt), 2, &p);

    TEST_ASSERT(res == PARSE_OK);
    TEST_ASSERT(p.ip_proto == 1);
    TEST_ASSERT(p.icmp_type == 8);
    TEST_ASSERT(p.icmp_code == 0);
    TEST_ASSERT(p.icmp_id == 0x1234);
    TEST_ASSERT(p.icmp_seq == 1);

    /* Echo Reply */
    pkt[34] = 0; /* Type 0 = Echo Reply */
    res = parse_frame(pkt, sizeof(pkt), 2, &p);
    TEST_ASSERT(res == PARSE_OK);
    TEST_ASSERT(p.icmp_type == 0);
    TEST_ASSERT(p.icmp_id == 0x1234);
}

static void test_arp_and_other_eth(void)
{
    uint8_t arp_pkt[42];
    memset(arp_pkt, 0, sizeof(arp_pkt));
    arp_pkt[12] = 0x08; arp_pkt[13] = 0x06; /* ARP */

    parsed_packet_t p;
    parse_result_t res = parse_frame(arp_pkt, sizeof(arp_pkt), 0, &p);
    TEST_ASSERT(res == PARSE_ARP);
    TEST_ASSERT(p.eth_proto == ETH_PROTO_ARP);

    /* IPv6 */
    uint8_t ipv6_pkt[54];
    memset(ipv6_pkt, 0, sizeof(ipv6_pkt));
    ipv6_pkt[12] = 0x86; ipv6_pkt[13] = 0xDD;

    res = parse_frame(ipv6_pkt, sizeof(ipv6_pkt), 0, &p);
    TEST_ASSERT(res == PARSE_OTHER_ETH);
    TEST_ASSERT(p.eth_proto == ETH_PROTO_OTHER);

    /* Неизвестный EtherType (например, LLDP 0x88CC) */
    uint8_t lldp_pkt[30];
    memset(lldp_pkt, 0, sizeof(lldp_pkt));
    lldp_pkt[12] = 0x88; lldp_pkt[13] = 0xCC;

    res = parse_frame(lldp_pkt, sizeof(lldp_pkt), 0, &p);
    TEST_ASSERT(res == PARSE_OTHER_ETH);
    TEST_ASSERT(p.eth_proto == ETH_PROTO_OTHER);
}

static void test_malformed_frames(void)
{
    parsed_packet_t p;

    /* 1. Усечённый Ethernet (< 14 байт) */
    uint8_t short_eth[13];
    memset(short_eth, 0, sizeof(short_eth));
    TEST_ASSERT(parse_frame(short_eth, sizeof(short_eth), 0, &p) == PARSE_DROP_MALFORMED);

    /* 2. Усечённый ARP (< 42 байт) */
    uint8_t short_arp[30];
    memset(short_arp, 0, sizeof(short_arp));
    short_arp[12] = 0x08; short_arp[13] = 0x06;
    TEST_ASSERT(parse_frame(short_arp, sizeof(short_arp), 0, &p) == PARSE_DROP_MALFORMED);

    /* 3. Базовый валидный пакет для проверок повреждений */
    uint8_t base[54];
    memset(base, 0, sizeof(base));
    base[12] = 0x08; base[13] = 0x00;
    base[14] = 0x45; /* Version 4, IHL 5 */
    base[16] = 0x00; base[17] = 40; /* Total length 40 */
    base[22] = 64;
    base[23] = 6; /* TCP */
    helper_calc_ip_csum(&base[14], 20);
    base[46] = 0x50; /* TCP offset 5 */

    /* Валидный базовый пакет должен проходить */
    TEST_ASSERT(parse_frame(base, sizeof(base), 0, &p) == PARSE_OK);

    /* 4. FR-12: Версия IP != 4 (например версия 6 в IPv4 пакете) */
    uint8_t bad_ver[54];
    memcpy(bad_ver, base, sizeof(base));
    bad_ver[14] = 0x65; /* Version 6 */
    helper_calc_ip_csum(&bad_ver[14], 20);
    TEST_ASSERT(parse_frame(bad_ver, sizeof(bad_ver), 0, &p) == PARSE_DROP_MALFORMED);

    /* Версия 0 */
    bad_ver[14] = 0x05;
    helper_calc_ip_csum(&bad_ver[14], 20);
    TEST_ASSERT(parse_frame(bad_ver, sizeof(bad_ver), 0, &p) == PARSE_DROP_MALFORMED);

    /* 5. FR-12: IHL < 5 (например 4 или 0) */
    uint8_t bad_ihl[54];
    memcpy(bad_ihl, base, sizeof(base));
    bad_ihl[14] = 0x44; /* Version 4, IHL 4 (16 байт) */
    helper_calc_ip_csum(&bad_ihl[14], 16);
    TEST_ASSERT(parse_frame(bad_ihl, sizeof(bad_ihl), 0, &p) == PARSE_DROP_MALFORMED);

    bad_ihl[14] = 0x40; /* Version 4, IHL 0 */
    TEST_ASSERT(parse_frame(bad_ihl, sizeof(bad_ihl), 0, &p) == PARSE_DROP_MALFORMED);

    /* 6. FR-12: Неверная контрольная сумма IPv4 */
    uint8_t bad_csum[54];
    memcpy(bad_csum, base, sizeof(base));
    bad_csum[24] ^= 0xFF; /* Испортить контрольную сумму */
    TEST_ASSERT(parse_frame(bad_csum, sizeof(bad_csum), 0, &p) == PARSE_DROP_MALFORMED);

    /* 7. FR-12: Усечённый пакет (tot_len > размера буфера) */
    uint8_t trunc_ip[54];
    memcpy(trunc_ip, base, sizeof(base));
    trunc_ip[16] = 0x01; trunc_ip[17] = 0x00; /* tot_len = 256 байт > 40 доступных */
    helper_calc_ip_csum(&trunc_ip[14], 20);
    TEST_ASSERT(parse_frame(trunc_ip, sizeof(trunc_ip), 0, &p) == PARSE_DROP_MALFORMED);

    /* 8. FR-12: tot_len < ihl_bytes */
    memcpy(trunc_ip, base, sizeof(base));
    trunc_ip[16] = 0x00; trunc_ip[17] = 16; /* tot_len = 16 < 20 */
    helper_calc_ip_csum(&trunc_ip[14], 20);
    TEST_ASSERT(parse_frame(trunc_ip, sizeof(trunc_ip), 0, &p) == PARSE_DROP_MALFORMED);

    /* 9. Усечённый TCP заголовок (< 20 байт) */
    uint8_t short_tcp[40]; /* 14 Eth + 20 IP + 6 TCP байт */
    memcpy(short_tcp, base, 40);
    short_tcp[16] = 0x00; short_tcp[17] = 26; /* tot_len = 26 (20 IP + 6 TCP) */
    helper_calc_ip_csum(&short_tcp[14], 20);
    TEST_ASSERT(parse_frame(short_tcp, sizeof(short_tcp), 0, &p) == PARSE_DROP_MALFORMED);

    /* 10. Неверный TCP data offset (< 5) */
    uint8_t bad_tcp_off[54];
    memcpy(bad_tcp_off, base, sizeof(base));
    bad_tcp_off[46] = 0x40; /* offset 4 < 5 */
    TEST_ASSERT(parse_frame(bad_tcp_off, sizeof(bad_tcp_off), 0, &p) == PARSE_DROP_MALFORMED);

    /* 11. Усечённый UDP заголовок (< 8 байт) */
    uint8_t short_udp[38]; /* 14 Eth + 20 IP + 4 UDP */
    memcpy(short_udp, base, 38);
    short_udp[23] = 17; /* UDP */
    short_udp[16] = 0x00; short_udp[17] = 24; /* tot_len = 24 (20 IP + 4 UDP) */
    helper_calc_ip_csum(&short_udp[14], 20);
    TEST_ASSERT(parse_frame(short_udp, sizeof(short_udp), 0, &p) == PARSE_DROP_MALFORMED);

    /* 12. Неверная длина UDP в заголовке */
    uint8_t bad_udp_len[46];
    memcpy(bad_udp_len, base, 34);
    bad_udp_len[23] = 17; /* UDP */
    bad_udp_len[16] = 0x00; bad_udp_len[17] = 32;
    helper_calc_ip_csum(&bad_udp_len[14], 20);
    bad_udp_len[38] = 0x00; bad_udp_len[39] = 50; /* UDP len 50 > l4_avail 12 */
    TEST_ASSERT(parse_frame(bad_udp_len, sizeof(bad_udp_len), 0, &p) == PARSE_DROP_MALFORMED);

    /* 13. Усечённый ICMP Echo (< 8 байт) */
    uint8_t short_icmp[40]; /* 14 Eth + 20 IP + 6 ICMP */
    memcpy(short_icmp, base, 40);
    short_icmp[23] = 1; /* ICMP */
    short_icmp[16] = 0x00; short_icmp[17] = 26;
    helper_calc_ip_csum(&short_icmp[14], 20);
    short_icmp[34] = 8; /* Echo request */
    TEST_ASSERT(parse_frame(short_icmp, sizeof(short_icmp), 0, &p) == PARSE_DROP_MALFORMED);
}

int main(void)
{
    printf("Running parser and net_utils tests...\n");

    test_net_utils();
    test_valid_tcp();
    test_valid_udp();
    test_valid_icmp_echo();
    test_arp_and_other_eth();
    test_malformed_frames();

    printf("ALL TESTS PASSED (%d/%d checks passed)\n", tests_passed, tests_run);
    return 0;
}
