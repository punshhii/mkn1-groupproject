/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      json_utils
 * Назначение:  легковесный разбор и форматирование JSON для протокола управления
 * Методы:
 *   - json_parse — разбор строки в AST JSON
 *   - json_free — освобождение AST JSON
 *   - json_obj_get / json_obj_get_str / ... — функции выборки полей
 *   - json_arr_len / json_arr_get — функции работы с массивами
 *   - json_buf_init / json_buf_free / json_buf_append — буфер сериализации
 *   - json_parse_rule — десериализация rule_t из JSON-объекта
 *   - json_serialize_rule — сериализация rule_t в JSON
 */
#ifndef FW_JSON_UTILS_H
#define FW_JSON_UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "rule.h"

typedef enum {
    JSON_TYPE_NULL = 0,
    JSON_TYPE_BOOL,
    JSON_TYPE_NUMBER,
    JSON_TYPE_STRING,
    JSON_TYPE_ARRAY,
    JSON_TYPE_OBJECT
} json_type_t;

typedef struct json_value_s json_value_t;

struct json_value_s {
    json_type_t type;
    union {
        bool bool_val;
        double num_val;
        char *str_val;
        struct {
            json_value_t **items;
            size_t count;
            size_t cap;
        } array;
        struct {
            char **keys;
            json_value_t **values;
            size_t count;
            size_t cap;
        } object;
    } u;
};

/* Динамический буфер для сборки JSON */
typedef struct {
    char   *data;
    size_t  len;
    size_t  cap;
} json_buf_t;

/* Разбор и освобождение */
json_value_t *json_parse(const char *text, char *err_buf, size_t err_len);
void json_free(json_value_t *val);

/* Выборка значений */
const json_value_t *json_obj_get(const json_value_t *val, const char *key);
const char *json_obj_get_str(const json_value_t *val, const char *key, const char *def);
int64_t json_obj_get_int(const json_value_t *val, const char *key, int64_t def);
double json_obj_get_num(const json_value_t *val, const char *key, double def);
bool json_obj_get_bool(const json_value_t *val, const char *key, bool def);

size_t json_arr_len(const json_value_t *val);
const json_value_t *json_arr_get(const json_value_t *val, size_t index);

/* Буфер сериализации */
void json_buf_init(json_buf_t *buf);
void json_buf_free(json_buf_t *buf);
void json_buf_append(json_buf_t *buf, const char *s);
void json_buf_append_escaped(json_buf_t *buf, const char *s);
void json_buf_printf(json_buf_t *buf, const char *fmt, ...);

/* Сериализация и десериализация правил */
int json_parse_rule(const json_value_t *val, rule_t *rule);
void json_serialize_rule(json_buf_t *buf, const rule_t *rule);

#endif /* FW_JSON_UTILS_H */
