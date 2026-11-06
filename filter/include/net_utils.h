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
#ifndef FW_NET_UTILS_H
#define FW_NET_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include "types.h"

mac_t mac_to_u64(const uint8_t mac[6]);
void u64_to_mac(mac_t val, uint8_t mac[6]);
int mac_to_str(mac_t val, char *buf, size_t buf_len);
int str_to_mac(const char *str, mac_t *val);

int ip_to_str(ip4_t ip, char *buf, size_t buf_len);
int str_to_ip(const char *str, ip4_t *ip);

ip4_t cidr_to_mask(uint8_t cidr);
int mask_to_cidr(ip4_t mask);

#endif /* FW_NET_UTILS_H */
