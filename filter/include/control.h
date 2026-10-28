/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      control
 * Назначение:  сервер управления и диспетчер IPC-команд (/run/fw/filter.sock)
 * Методы:
 *   - control_init — запуск сервера IPC и инициализация очередей
 *   - control_cleanup — остановка сервера и освобождение ресурсов
 *   - control_get_fd — получение дескриптора сокета сервера (для epoll/poll)
 *   - control_process — неблокирующая обработка подключений и команд
 *   - control_is_emergency_blocked — опрос флага аварийного режима (traffic.block)
 *   - control_set_emergency_blocked — установка флага аварийного режима
 *   - control_inc_stat_rx / tx / drop — инкремент счётчиков сетевых пакетов
 *   - control_get_stats — получение статистики пакетов
 *   - control_flush_logd_events — отправка буферизованных событий E14/E15 в logd
 */
#ifndef FW_CONTROL_H
#define FW_CONTROL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define CONTROL_DEFAULT_SOCKET_PATH       "/run/fw/filter.sock"
#define CONTROL_DEFAULT_LOGD_SOCKET_PATH  "/run/fw/logd.sock"

/**
 * Инициализировать сервер управления и IPC.
 *
 * @param sock_path      Путь к сокету сервера (или NULL для CONTROL_DEFAULT_SOCKET_PATH)
 * @param logd_sock_path Путь к сокету logd (или NULL для CONTROL_DEFAULT_LOGD_SOCKET_PATH)
 * @return 0 при успехе, -1 при ошибке
 */
int control_init(const char *sock_path, const char *logd_sock_path);

/**
 * Освободить ресурсы сервера управления (закрыть сокеты, удалить сокет-файл).
 */
void control_cleanup(void);

/**
 * Получить дескриптор серверного сокета управления (для epoll/poll).
 *
 * @return файловый дескриптор или -1
 */
int control_get_fd(void);

/**
 * Получить дескрипторы серверного сокета и всех подключенных клиентов (для poll).
 *
 * @param fds     выходной массив дескрипторов
 * @param max_fds вместимость массива
 * @return число записанных дескрипторов
 */
int control_get_poll_fds(int *fds, int max_fds);

/**
 * Обработать входящие подключения и команды на сокете управления.
 * Вызывается из основного цикла при событии на дескрипторе control_get_fd()
 * или периодически.
 *
 * @return число обработанных сообщений или отрицательное значение при ошибке
 */
int control_process(void);

/**
 * Проверить, активен ли режим аварийной блокировки трафика (traffic.block, FR-48).
 *
 * @return true если транзитный трафик заблокирован, false иначе
 */
bool control_is_emergency_blocked(void);

/**
 * Установить режим аварийной блокировки (для программного вызова или тестов).
 */
void control_set_emergency_blocked(bool blocked);

/**
 * Счётчики сетевых пакетов для stats.get.
 */
void control_inc_stat_rx(void);
void control_inc_stat_tx(void);
void control_inc_stat_drop(void);

/**
 * Получить статистику сетевых пакетов.
 */
void control_get_stats(uint64_t *rx, uint64_t *tx, uint64_t *drop);

/**
 * Сбросить очередь событий в logd (например, перед остановкой или в тестах).
 *
 * @return число успешно отправленных событий
 */
int control_flush_logd_events(void);

#endif /* FW_CONTROL_H */
