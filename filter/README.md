# ПС-1 Фильтрация (`fw-filter`)

Подсистема фильтрации пакетов прозрачного межсетевого экрана (L2 bridge). Работает в пространстве пользователя, выполняет классификацию кадров, фильтрацию по критериям L2/L3/L4, отслеживание состояний сетевых соединений (Stateful Inspection) и передачу журнала в подсистему ПС-2.

- **Язык:** C (C11)
- **Пользователь ОС:** `fw-filter` (+`CAP_NET_RAW` на Linux)
- **Сокет управления:** `/run/fw/filter.sock` (`0600`)
- **Сокет логирования:** `/run/fw/logd-packets.sock` (`0600`)
- **Требования ТЗ:** FR-01, FR-05 – FR-23, FR-26, FR-48

---

## Архитектура модулей

| Модуль | Исходный код | Назначение |
|---|---|---|
| **io** | [`src/io.c`](src/io.c) | Приём и передача кадров: на Linux через `AF_PACKET (SOCK_RAW)`, на macOS — встроенный mock-бэкенд (`socketpair`). |
| **parser** | [`src/parser.c`](src/parser.c) | Разбор Ethernet, ARP, IPv4, TCP, UDP, ICMP; проверка контрольных сумм и отсечение битых кадров (RFC 791, FR-12). |
| **rules** | [`src/rules.c`](src/rules.c) | Движок правил: порядок first-match, действия `accept` / `goto` / `drop`, default drop (правило 0), валидация (FR-13). |
| **conntrack** | [`src/conntrack.c`](src/conntrack.c) | Таблица состояний соединений (5-tuple хэш): стейт-машины TCP, UDP, ICMP Echo, таймауты и отсечение TCP без SYN (FR-14–FR-22). |
| **pktlog_client** | [`src/pktlog_client.c`](src/pktlog_client.c) | Неблокирующая передача записей пакетов (55 байт) в сокет ПС-2 (FR-26). |
| **control** | [`src/control.c`](src/control.c) | IPC-сервер управления по Unix-сокету, дедупликация сообщений по `msg_id`, буфер событий E14/E15. |
| **main** | [`src/main.c`](src/main.c) | Точка входа, загрузка конфигурации, цикл событий `poll()` для сети и сокета управления. |

---

## Сборка и запуск

### 1. Сборка
```bash
make -C filter clean
make -C filter
```
Исполняемый файл: `filter/fw-filter`.

### 2. Параметры запуска
```bash
./filter/fw-filter [--config <path>] [--policy <path>] [--sock <path>] [--logd <path>]
```

| Параметр | По умолчанию | Описание |
|---|---|---|
| `--config` | `/etc/fw/config.json` | Путь к конфигурации интерфейсов и conntrack (fallback: `/etc/default/config.json`) |
| `--policy` | `/etc/fw/policy.json` | Путь к начальной политике правил (fallback: `/etc/default/policy.json`) |
| `--sock` | `/run/fw/filter.sock` | Путь к сокету IPC для команд управления от CLI / Web / Integrity |
| `--logd` | `/run/fw/logd.sock` | Путь к сокету событий журнала ПС-2 |

*Пример запуска для локальной отладки:*
```bash
./filter/fw-filter --sock /tmp/filter.sock
```

---

## Справочник команд IPC

Все команды передаются в сокет управления в формате JSON, разделённые переводом строки `\n` ([`common/PROTOCOL.md`](../common/PROTOCOL.md)):

```json
{"msg_id": 1, "type": "request", "src": "cli", "dst": "filter", "cmd": "<имя_команды>", "payload": {}}
```

### 1. `rule.replace` — атомарная замена таблицы правил
Заменяет всю таблицу правил на новую. При изменении правил автоматически сбрасываются сессии conntrack, привязанные к удалённым/изменённым правилам (FR-10, FR-23).

* **Payload:**
  ```json
  {
    "rules": [
      {
        "id": 10,
        "active": true,
        "action": "accept",
        "in_iface": 0,
        "out_ifaces": [1],
        "proto": "tcp",
        "dport": 80,
        "log": true,
        "comment": "Allow HTTP"
      },
      {
        "id": 20,
        "active": true,
        "action": "drop",
        "in_iface": 0
      }
    ]
  }
  ```
* **Ответ при успехе:**
  ```json
  {"status": "ok", "payload": {"rule_count": 2, "purged_sessions": 0}}
  ```
* **Ответ при ошибке валидации:**
  ```json
  {"status": "error", "error_code": "M06", "error_message": "Ошибка валидации..."}
  ```

---

### 2. `rule.get` — выгрузка активных правил со счётчиками
Возвращает текущую активную таблицу правил с актуальными счётчиками совпадений (`hits`).

* **Payload:** `{}`
* **Ответ:**
  ```json
  {
    "status": "ok",
    "payload": {
      "rules": [
        {
          "id": 10,
          "active": true,
          "hits": 42,
          "action": "accept",
          "in_iface": 0,
          "out_ifaces": [1],
          "proto": "tcp",
          "dport": 80
        }
      ]
    }
  }
  ```

---

### 3. `state.status` — опрос настроек и состояния conntrack
Возвращает текущий статус механизма состояний, таймауты и флаг аварийного режима.

* **Payload:** `{}`
* **Ответ:**
  ```json
  {
    "status": "ok",
    "payload": {
      "enabled": true,
      "active_sessions": 0,
      "max_sessions": 65536,
      "arp_forwarding": false,
      "emergency_mode": false,
      "tcp_syn_timeout_sec": 5,
      "tcp_est_timeout_sec": 3600,
      "tcp_fin_timeout_sec": 30,
      "udp_timeout_no_reply": 15,
      "udp_timeout_reply": 60,
      "icmp_timeout_sec": 5
    }
  }
  ```

---

### 4. `state.list` — просмотр таблицы активных сессий
Возвращает список всех сессий, отслеживаемых в данный момент.

* **Payload:** `{}`
* **Ответ:**
  ```json
  {
    "status": "ok",
    "payload": {
      "entries": [
        {
          "conn_id": 1,
          "proto": "tcp",
          "client_ip": "192.168.1.10",
          "client_port": 54321,
          "server_ip": "192.168.1.20",
          "server_port": 80,
          "client_packets": 12,
          "client_bytes": 1420,
          "server_packets": 10,
          "server_bytes": 4530,
          "state": "ESTABLISHED",
          "in_iface": 0,
          "out_ifaces": [1],
          "rule_id": 10,
          "expires_in_sec": 3599
        }
      ]
    }
  }
  ```

---

### 5. `state.enable` / `state.disable` — переключение conntrack
Включает или выключает механизм отслеживания состояний. Генерирует системные события `E14` (включение) и `E15` (отключение) для журнала аудита.

* **Payload:** `{}`
* **Ответ:** `{"status": "ok", "payload": {"enabled": true}}` (или `false`)

---

### 6. `state.delete` — удаление одной сессии администратором
Удаляет запись соединения по её идентификатору `conn_id`.

* **Payload:** `{"conn_id": 1}`
* **Ответ:** `{"status": "ok", "payload": {"deleted": true, "conn_id": 1}}`
* **Ошибка (если сессия не найдена):** `{"status": "error", "error_code": "M13", "error_message": "Записи не найдены"}`

---

### 7. `state.delete_all` / `state.clear` — сброс всех сессий
Полная очистка таблицы сессий conntrack.
* **Payload:** `{}`
* **Ответ:** `{"status": "ok", "payload": {"cleared": true, "deleted": 5}}`

---

### 8. `traffic.block` / `traffic.unblock` — аварийный режим (FR-48)
Вызывается подсистемой контроля целостности (ПС-6). При блокировке сбрасываются все текущие сессии, а весь входящий транзитный трафик дропается на входе.
* **Payload:** `{}`
* **Ответ `traffic.block`:** `{"status": "ok", "payload": {"blocked": true, "purged_sessions": 3}}`
* **Ответ `traffic.unblock`:** `{"status": "ok", "payload": {"blocked": false}}`

---

### 9. `stats.get` — счётчики сетевых пакетов
Возвращает общую статистику с момента запуска.
* **Payload:** `{}`
* **Ответ:**
  ```json
  {
    "status": "ok",
    "payload": {
      "stat_rx": 1500,
      "stat_tx": 1200,
      "stat_drop": 300,
      "log_sent": 1200,
      "log_dropped": 0
    }
  }
  ```

---

## Формат описания правила фильтрации

Правило передаётся объектом JSON со следующими полями:

| Поле | Тип | Обязательное | Описание |
|---|---|---|---|
| `id` | int | Да | Уникальный номер правила (1..65535) |
| `active` | bool | Нет (default: true) | Флаг активности правила |
| `action` | string | Да | `"accept"` \| `"drop"` \| `"goto"` |
| `in_iface` | int | Нет (default: -1) | Индекс входного интерфейса (-1 = any, 0..5) |
| `out_ifaces` | array[int] | Для `accept` | Список интерфейсов отправки (запрещено указывать `in_iface`) |
| `to_rule` | int | Для `goto` | Номер правила перехода (должен быть строго больше `id`, без циклов) |
| `proto` | string / int | Нет (default: any) | `"tcp"` (6), `"udp"` (17), `"icmp"` (1) |
| `src` / `dst` | string | Нет (default: any) | IP (`"192.168.1.5"`), CIDR (`"10.0.0.0/24"`) или диапазон (`"10.0.0.1-10.0.0.50"`) |
| `sport` / `dport` | int / string | Нет (default: any) | Порт (`80`) или диапазон портов (`"8000-8080"`) |
| `smac` / `dmac` | string | Нет (default: any) | MAC-адрес в формате `"00:11:22:33:44:55"` |
| `icmp_type` | int | Нет (default: any) | Тип ICMP (0..255) |
| `icmp_code` | int | Нет (default: any) | Код ICMP (0..255) |
| `log` | bool | Нет (default: false)| Флаг записи в журнал пакетов (ПС-2) |
| `comment` | string | Нет | Текстовый комментарий (до 256 символов) |

---

## Как тестировать модуль

### Вариант 1: Быстрый запуск набора модульных тестов
В модуле реализованы самодостаточные C-тесты для каждого компонента:

```bash
make -C filter test
```

Тестовые исполняемые файлы:
- `filter/tests/test_parser` — тестирование разбора заголовков и поврежденных кадров (RFC 791).
- `filter/tests/test_rules` — тестирование движка правил, first-match, goto, валидации (FR-13).
- `filter/tests/test_conntrack` — тестирование автоматов состояний TCP, UDP, ICMP и таймаутов.
- `filter/tests/test_pipeline` — сквозной конвейер: генерация сырых L2/L3 кадров, сопоставление и проверка выхода.
- `filter/tests/test_control` — тестирование сервера IPC и обработки JSON-команд.
- `filter/tests/test_pktlog` — тестирование бинарной очереди журнала (55 байт).

---

### Вариант 2: Запуск программы испытаний (ПМИ стенда)
Проверяет все 22 требования ТЗ (FR-01, FR-05–FR-23, FR-48):

```bash
python3 tests/stand/test_filter_stand.py
```

---

### Вариант 3: Ручное интерактивное тестирование на macOS

Поскольку в macOS нет Linux raw-сокетов `AF_PACKET`, демон автоматически включает mock-бэкенд на сокетах Unix.

1. **Запустите демон в первом терминале:**
   ```bash
   ./filter/fw-filter --sock /tmp/filter.sock
   ```

2. **Во втором терминале запустите Python и отправляйте команды:**
   ```python
   import sys, json
   sys.path.insert(0, "common")
   from fwcommon import protocol

   SOCK = "/tmp/filter.sock"

   def send(cmd, payload=None):
       res = protocol.request(SOCK, "cli", "filter", cmd, payload or {})
       print(json.dumps(res, indent=2, ensure_ascii=False))

   # Проверка статуса
   send("state.status")

   # Загрузка правил
   send("rule.replace", {
       "rules": [
           {"id": 10, "active": True, "action": "accept", "in_iface": 0, "out_ifaces": [1], "proto": "tcp", "dport": 80},
           {"id": 20, "active": True, "action": "drop", "in_iface": 0}
       ]
   })

   # Просмотр правил со счётчиками
   send("rule.get")

   # Проверка аварийного режима
   send("traffic.block")
   send("traffic.unblock")
   ```

3. **Отправка через Netcat (bash):**
   ```bash
   echo '{"msg_id": 1, "type": "request", "src": "cli", "dst": "filter", "cmd": "state.status", "payload": {}}' | nc -U /tmp/filter.sock
   ```

---

### Вариант 4: Автоматизированный стенд на Linux (`stand.sh`)

Скрипт [`stand.sh`](../stand.sh) автоматизирует поднятие стенда: создаёт пространства имён `client` и `server`, связывает их через L2-мост интерфейсов `fw-in` и `fw-out`, запускает демон `fw-filter` и сразу передаёт управление:

```bash
# Поднять стенд и запустить демон в фоне:
sudo ./stand.sh

# Или запустить на переднем плане в терминале (foreground):
sudo ./stand.sh -f

# Остановить стенд и удалить пространства имён:
sudo ./stand.sh down
```

После запуска стенда вы можете свободно работать в терминале:
* Проверить пинг: `sudo ip netns exec client ping 192.168.1.20`
* Открыть шелл клиента: `sudo ip netns exec client bash`
* Открыть шелл сервера: `sudo ip netns exec server bash`
* Смотреть логи демона: `tail -f /tmp/fw-filter.log`
* Отправлять команды в сокет `/tmp/filter.sock` через скрипты или CLI подсистемы ПС-3.
