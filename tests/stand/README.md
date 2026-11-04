# Стенд

VM Debian 12 с 6 интерфейсами и ≥ 3 узла на разных портах. Проверки при 1, 3 и 6 портах; пропускная способность — один поток 1 Гбит/с на порт, 1 и 100 правил без флага регистрации.

## Заглушки подсистем для ПС-3 / ПС-4

`mock_core.py` поднимает заглушки ПС-5 authd, ПС-2 logd, ПС-6 integrityd и ПС-1 filter на кодеке `common/fwcommon/protocol.py`. Клиент CLI или web работает с ними так же, как с настоящими подсистемами; меняется только каталог сокетов.

```bash
# все заглушки в /tmp/fw (на стенде — /run/fw)
python3 tests/stand/mock_core.py /tmp/fw

# без filter — рядом запущен настоящий fw-filter из ветки filtration
python3 tests/stand/mock_core.py /tmp/fw --only authd,logd,integrityd

# медленные подсистемы: проверка тайм-аута 5 с, повторов и M16
python3 tests/stand/mock_core.py /tmp/fw --delay 16

# демонстрация клиентского сценария и интеграционные тесты
python3 tests/stand/demo_codec.py /tmp/fw
python3 tests/stand/test_stand_codec.py

# PHP-клиент ПС-4 против заглушек (нужен php; путь — в переменной PHP)
PHP=/usr/bin/php python3 tests/stand/test_php_client.py

# приёмник ПС-4 (web/src/listener.php): emergency.* и session.terminate на web.sock
PHP=/usr/bin/php python3 tests/stand/test_php_listener.py

# аварийный режим вручную: нарушить целостность / восстановить
kill -USR1 <pid mock_core>      # emergency.enter в cli.sock и web.sock
kill -USR2 <pid mock_core>      # emergency.exit
```

Учётные записи заглушки: `admin` / `admin123` (rw), `viewer` / `viewer123` (ro).

| Подсистема | Команды | Источник контракта |
|---|---|---|
| authd | `auth.login/logout/ping/check`, `user.list/add/edit/delete`, `session.list/kill` | `authd/README.md` (ветка `authd/stubs`) |
| filter | `rule.replace` (путь к `policy.json`), `rule.get`, `state.*`, `stats.get` | `filter/src/control.c` (ветка `filtration`), ТЗ от 21.10 |
| logd | `log.write.event`, `log.query.events/packets`, `log.packets.clear`, `log.flush` | `logd/fw_logd/query.py` |
| integrityd | `integrity.status/check/restore/update_baseline` | `integrityd/README.md` |

Поведение по ТЗ:
- блокировка входа после 5 неудач подряд для каждого идентификатора, на 60 с (FR-31);
- понижение второго rw-сеанса до ro с M04 (FR-34);
- завершение сеанса после 15 мин бездействия с M15 (FR-35);
- защита `admin` (M05, FR-33) и проверка учётных записей (M06, FR-36);
- `rule.replace` читает файл по пути, проверяет правила (M06, M07, FR-13), сохраняет счётчики неизменённых правил и удаляет записи состояний изменённых и отключённых правил (FR-23);
- пустая выборка журнала возвращает `items: []`, сообщение M13 выводит клиент;
- ПС-6 при нарушении целостности и после восстановления отправляет `emergency.enter` (с M08) и `emergency.exit` на `cli.sock` и `web.sock`, всегда обоим (`integrityd/README.md`);
- ПС-5 при сбросе сеанса, удалении учётной записи и истечении 15 минут бездействия отправляет `session.terminate {"session_id", "reason"}` на сокет интерфейса сеанса (`cli.sock` или `web.sock`).

Отправленные уведомления видны в тестах через `mock_core.notified("emergency.enter")`. Нет получателя (CLI или приёмник web не запущен) — уведомление теряется, клиент узнаёт режим через `integrity.status`.

События, которые порождают заглушки (E01–E07, E14, E15, E32, E40–E42, E50), и события, присланные клиентом через `log.write.event`, попадают в общий журнал заглушки и видны в `log.query.events`. В тестах они доступны через `mock_core.events("E50")`.
