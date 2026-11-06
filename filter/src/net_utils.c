/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      net_utils
 * Назначение:  вспомогательные функции для работы с сетевыми адресами
 * Методы:
 *   - mac_to_u64 — преобразовать массив 6 байт в mac_t
 *   - u64_to_mac — преобразовать mac_t в массив 6 байт
 *   - mac_to_str — форматировать mac_t в строку XX:XX:XX:XX:XX:XX
 *   - str_to_mac — разобрать строку XX:XX:XX:XX:XX:XX в mac_t
 *   - ip_to_str — форматировать ip4_t в строку a.b.c.d
 *   - str_to_ip — разобрать строку a.b.c.d в ip4_t
 *   - cidr_to_mask — преобразовать длину префикса 0..32 в маску ip4_t
 *   - mask_to_cidr — преобразовать маску ip4_t в длину префикса 0..32
 */
#include "net_utils.h"

#include <stdio.h>
#include <string.h>

mac_t mac_to_u64(const uint8_t mac[6])
{
    mac_t res = 0;
    for (int i = 0; i < 6; i++) {
        res = (res << 8) | (mac_t)mac[i];
    }
    return res;
}

void u64_to_mac(mac_t val, uint8_t mac[6])
{
    for (int i = 5; i >= 0; i--) {
        mac[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

int mac_to_str(mac_t val, char *buf, size_t buf_len)
{
    uint8_t m[6];
    u64_to_mac(val, m);
    int written = snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
                           m[0], m[1], m[2], m[3], m[4], m[5]);
    if (written < 0 || (size_t)written >= buf_len) {
        return -1;
    }
    return 0;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int str_to_mac(const char *str, mac_t *val)
{
    if (!str || !val) return -1;
    uint8_t bytes[6];
    const char *p = str;

    for (int i = 0; i < 6; i++) {
        int h1 = hex_digit(*p++);
        if (h1 < 0) return -1;
        int h2 = hex_digit(*p++);
        if (h2 < 0) return -1;
        bytes[i] = (uint8_t)((h1 << 4) | h2);
        if (i < 5) {
            if (*p != ':' && *p != '-') return -1;
            p++;
        }
    }
    if (*p != '\0') return -1;

    *val = mac_to_u64(bytes);
    return 0;
}

int ip_to_str(ip4_t ip, char *buf, size_t buf_len)
{
    uint8_t b3 = (uint8_t)((ip >> 24) & 0xFF);
    uint8_t b2 = (uint8_t)((ip >> 16) & 0xFF);
    uint8_t b1 = (uint8_t)((ip >> 8) & 0xFF);
    uint8_t b0 = (uint8_t)(ip & 0xFF);

    int written = snprintf(buf, buf_len, "%u.%u.%u.%u", b3, b2, b1, b0);
    if (written < 0 || (size_t)written >= buf_len) {
        return -1;
    }
    return 0;
}

int str_to_ip(const char *str, ip4_t *ip)
{
    if (!str || !ip) return -1;
    unsigned int b[4];
    char tail[2];
    int parsed = sscanf(str, "%u.%u.%u.%u%1s", &b[0], &b[1], &b[2], &b[3], tail);
    if (parsed != 4) {
        return -1;
    }
    for (int i = 0; i < 4; i++) {
        if (b[i] > 255) return -1;
    }
    *ip = ((ip4_t)b[0] << 24) |
          ((ip4_t)b[1] << 16) |
          ((ip4_t)b[2] << 8)  |
          (ip4_t)b[3];
    return 0;
}

ip4_t cidr_to_mask(uint8_t cidr)
{
    if (cidr == 0) return 0;
    if (cidr >= 32) return 0xFFFFFFFFU;
    return (0xFFFFFFFFU << (32 - cidr)) & 0xFFFFFFFFU;
}

int mask_to_cidr(ip4_t mask)
{
    int count = 0;
    for (int i = 31; i >= 0; i--) {
        if (mask & ((ip4_t)1 << i)) {
            count++;
        } else {
            /* Check if there are any remaining 1s, which would mean non-contiguous mask */
            for (int j = i - 1; j >= 0; j--) {
                if (mask & ((ip4_t)1 << j)) {
                    return -1; /* Non-contiguous netmask */
                }
            }
            break;
        }
    }
    return count;
}
