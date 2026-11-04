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
#ifndef FW_CONNTRACK_H
#define FW_CONNTRACK_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include "parser.h"
#include "rules.h"
#include "types.h"

#define CT_DEFAULT_TABLE_SIZE 65536

/* Состояния протоколов */
typedef enum {
    CT_STATE_NONE = 0,
    /* TCP */
    CT_TCP_SYN_SENT = 1,       /* Клиент отправил SYN */
    CT_TCP_SYN_RECV = 2,       /* Сервер ответил SYN-ACK */
    CT_TCP_ESTABLISHED = 3,    /* 3-way handshake завершён, соединение установлено */
    CT_TCP_FIN_WAIT = 4,       /* Получен FIN (финализация) */
    /* UDP */
    CT_UDP_UNREPLIED = 5,      /* Первый UDP пакет */
    CT_UDP_REPLIED = 6,        /* Получен обратный ответ */
    /* ICMP */
    CT_ICMP_REQUEST = 7        /* Отправлен Echo Request */
} ct_state_t;

/* Направление пакета относительно первого пакета соединения */
typedef enum {
    CT_DIR_ORIGINAL = 0,       /* Прямое направление (клиент -> сервер) */
    CT_DIR_REPLY = 1           /* Обратное направление (сервер -> клиент) */
} ct_dir_t;

/* Результат обработки пакета в conntrack */
typedef enum {
    CT_RES_FORWARD = 0,              /* Пакет принадлежит соединению и разрешён */
    CT_RES_PASS_TO_RULES = 1,        /* Соединение не найдено, передать пакет в модуль правил */
    CT_RES_DROP_OUT_OF_CONTEXT = 2   /* Пакет нарушает состояние или интерфейс (FR-15, FR-16, FR-22) */
} ct_result_t;

/* Структура действия для передачи пакета */
typedef struct {
    ct_result_t result;
    rule_id_t   rule_id;                     /* ID создавшего правила (для лога при drop) */
    uint32_t    conn_id;                     /* ID записи conntrack */
    uint8_t     rule_log;                    /* Флаг log правила (FR-22) */
    int8_t      out_ifaces[MAX_INTERFACES];  /* Куда пересылать пакет */
    uint8_t     out_count;                   /* Количество выходных портов */
} ct_action_t;

/* Конфигурация conntrack */
typedef struct {
    uint32_t tcp_syn_timeout_sec;   /* По умолчанию 5 с */
    uint32_t tcp_est_timeout_sec;   /* По умолчанию 3600 с */
    uint32_t tcp_fin_timeout_sec;   /* По умолчанию 30 с */
    uint32_t udp_timeout_no_reply;  /* По умолчанию 15 с */
    uint32_t udp_timeout_reply;     /* По умолчанию 60 с */
    uint32_t icmp_timeout_sec;      /* По умолчанию 5 с */
    uint32_t state_table_size;      /* 1024..1048576 (по умолчанию 65536) */
    bool     conntrack_enabled;     /* Вкл / Выкл */
} conntrack_config_t;

/* Структура для выгрузки информации о сессии (для команды state.list) */
typedef struct {
    uint32_t   conn_id;
    uint8_t    proto;
    ip4_t      client_ip;
    ip4_t      server_ip;
    uint16_t   client_port;
    uint16_t   server_port;
    ip4_t      src_ip;              /* Алиас client_ip */
    ip4_t      dst_ip;              /* Алиас server_ip */
    uint16_t   sport;               /* Алиас client_port */
    uint16_t   dport;               /* Алиас server_port */
    uint64_t   client_packets;
    uint64_t   client_bytes;
    uint64_t   server_packets;
    uint64_t   server_bytes;
    int8_t     in_iface;
    int8_t     out_ifaces[MAX_INTERFACES];
    rule_id_t  rule_id;
    ct_state_t state;
    uint32_t   expires_in_sec;
} ct_entry_info_t;

/**
 * Инициализировать таблицу состояний с конфигурацией по умолчанию.
 *
 * @return 0 при успехе, -1 при ошибке памяти
 */
int ct_init(void);

/**
 * Инициализировать таблицу состояний с заданной конфигурацией.
 *
 * @param cfg Конфигурация (если NULL, используются значения по умолчанию)
 * @return 0 при успехе, -1 при ошибке памяти
 */
int ct_init_config(const conntrack_config_t *cfg);

/**
 * Освободить ресурсы таблицы состояний.
 */
void ct_cleanup(void);

/**
 * Включить механизм контроля состояний (FR-20).
 */
void ct_enable(void);

/**
 * Отключить механизм контроля состояний и очистить таблицу (FR-20).
 */
void ct_disable(void);

/**
 * Проверить, активен ли контроль состояний.
 */
bool ct_is_enabled(void);

/**
 * Сопоставить пакет с существующими сессиями и выполнить валидацию состояния.
 *
 * @param pkt      Разобранный сетевой пакет
 * @param out_act  Выходная структура с вердиктом и выходными интерфейсами
 * @return ct_result_t Результат сопоставления
 */
ct_result_t ct_process_packet(const parsed_packet_t *pkt, ct_action_t *out_act);

/**
 * Создать новую запись таблицы состояний для первого пакета соединения (FR-14).
 *
 * @param pkt Разобранный первый пакет
 * @param dec Решение модуля правил (содержащее out_ifaces, rule_id, rule_log)
 * @return 0 при успехе, -1 если пакет не может открыть сессию или при переполнении таблицы
 */
int ct_create_entry(const parsed_packet_t *pkt, const rule_decision_t *dec);

/**
 * Очистить истёкшие записи таблицы состояний по времени (FR-19).
 *
 * @param now Текущее время Unix epoch (если 0, берётся системное)
 * @return Число удалённых записей
 */
uint32_t ct_expire_entries(time_t now);

/**
 * Удалить запись таблицы состояний по ID (FR-21).
 *
 * @param conn_id Идентификатор записи
 * @return 0 если удалено, -1 если запись не найдена
 */
int ct_delete_entry(uint32_t conn_id);

/**
 * Принудительно очистить всю таблицу состояний (FR-20, FR-21, FR-23).
 */
void ct_delete_all(void);

/**
 * Удалить записи conntrack, созданные указанными номерами правил (FR-23).
 *
 * @param rule_ids Массив номеров правил
 * @param count    Число номеров правил
 * @return Число удалённых записей
 */
uint32_t ct_purge_by_rule_ids(const rule_id_t *rule_ids, uint32_t count);

/**
 * Получить копию текущей конфигурации conntrack.
 */
void ct_get_config(conntrack_config_t *out_cfg);

/**
 * Обновить параметры таймаутов conntrack.
 */
void ct_set_config(const conntrack_config_t *new_cfg);

/**
 * Получить текущее количество активных соединений в таблице.
 */
uint32_t ct_get_entries_count(void);

/**
 * Выгрузить копию активных сессий (для команды state.list).
 *
 * @param out_entries Массив для записи сессий
 * @param max_count   Максимальное число сессий для записи
 * @return Фактическое число выгруженных сессий
 */
uint32_t ct_dump_entries(ct_entry_info_t *out_entries, uint32_t max_count);

#endif /* FW_CONNTRACK_H */
