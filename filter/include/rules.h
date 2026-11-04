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
#ifndef FW_RULES_H
#define FW_RULES_H

#include <stdbool.h>
#include <stdint.h>
#include "parser.h"
#include "rule.h"
#include "types.h"

/* Результат проверки пакета по правилам */
typedef enum {
    RULE_MATCH_ACCEPT = 0,       /* Пакет разрешён сработавшим правилом */
    RULE_MATCH_DROP = 1,         /* Пакет сброшен сработавшим правилом */
    RULE_MATCH_DEFAULT_DROP = 2, /* Ни одно правило не совпало (правило 0, FR-08) */
    RULE_MATCH_ARP_FORWARD = 3   /* Пересылка ARP на прочие интерфейсы (FR-11) */
} rule_verdict_t;

/* Структура решения по пакету */
typedef struct {
    rule_verdict_t verdict;                     /* Решение по пакету */
    rule_id_t      rule_id;                     /* Номер сработавшего правила (или 0) */
    uint8_t        log;                         /* Флаг логирования (0 или 1) */
    uint8_t        conntrack;                   /* Флаг контроля состояния (0 или 1) */
    int8_t         out_ifaces[MAX_INTERFACES];  /* Выходные интерфейсы (-1 = терминатор) */
    uint8_t        out_count;                   /* Количество выходных интерфейсов */
} rule_decision_t;

/* Список номеров правил (для передачи изменённых/удалённых правил в conntrack по FR-23) */
typedef struct {
    rule_id_t ids[MAX_RULES];
    uint32_t  count;
} rule_id_list_t;

/**
 * Инициализировать движок правил (пустая таблица, все IPv4 удаляются по FR-08).
 *
 * @return 0 при успехе, отрицательное значение при ошибке
 */
int rules_init(void);

/**
 * Освободить ресурсы движка правил.
 */
void rules_cleanup(void);

/**
 * Установить режим пересылки ARP при отсутствии подходящего правила.
 *
 * @param enabled true = пересылать ARP, false = сбрасывать
 */
void rules_set_arp_forwarding(bool enabled);

/**
 * Получить текущий режим пересылки ARP.
 */
bool rules_get_arp_forwarding(void);

/**
 * Сопоставить разобранный пакет с активной таблицей правил.
 *
 * @param pkt      Указатель на разобранный сетевой пакет
 * @param out_dec  Выходная структура с принятым решением
 */
void rules_match(const parsed_packet_t *pkt, rule_decision_t *out_dec);

/**
 * Валидировать набор правил согласно Таблице 2 и FR-13.
 *
 * @param rules    Массив правил
 * @param count    Число правил в массиве
 * @param err_code Выходной код ошибки ("M06", "M07", "M11" или NULL)
 * @return 0 если правила корректны, -1 при ошибке
 */
int rules_validate(const rule_t *rules, uint32_t count, const char **err_code);

/**
 * Атомарно заменить активную таблицу правил (FR-10).
 * Сохраняет счётчики hits для неизменённых правил.
 * Формирует список ID изменённых/удалённых/деактивированных правил (FR-23).
 *
 * @param new_rules          Массив новых правил
 * @param count              Число новых правил
 * @param out_modified_rules Выходной список ID изменённых правил (может быть NULL)
 * @return 0 при успехе, -1 при ошибке валидации
 */
int rules_replace(const rule_t *new_rules, uint32_t count, rule_id_list_t *out_modified_rules);

/**
 * Получить копию активной таблицы правил со счётчиками hits.
 *
 * @param out_rules Массив для записи правил
 * @param max_count Максимальное число правил для записи
 * @return Фактическое число правил в таблице
 */
uint32_t rules_get_active(rule_t *out_rules, uint32_t max_count);

/**
 * Получить общее количество правил в активной таблице.
 */
uint32_t rules_get_count(void);

#endif /* FW_RULES_H */
