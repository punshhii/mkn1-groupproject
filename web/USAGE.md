# ПС-4 WEB: реализация, запуск, тесты

Дополняет [README.md](README.md): там — что модуль принимает и отправляет по спецификации, здесь — как это сделано в коде.

## Модули

| Модуль | Назначение | Состояние |
|---|---|---|
| protocol | клиент Unix-сокета подсистем: JSON-конверт, тайм-аут 5 с, 2 повтора с тем же msg_id, M01–M16, M16 (как `common/fwcommon/protocol.py`) | готов |
| inbox | входящие команды и режим: `FwInbox::handle`, файл состояния `web.state.json`, `FwInbox::emergency` (уведомление или `integrity.status`, M16 → аварийный), `terminatedReason`, `forget`, `takeNotice` | готов |
| listener | постоянный процесс: приём `emergency.enter` / `emergency.exit` (ПС-6) и `session.terminate` (ПС-5) на `web.sock` | готов |
| server, auth, pages, api | точка входа, сеанс и CSRF, разделы меню, вызовы подсистем | заготовки |

## Входящие команды и режим работы

- Запросы PHP живут недолго и не могут держать сокет, поэтому `web.sock` (0600) слушает отдельный постоянный процесс `web/src/listener.php`. Он записывает состояние в `web.state.json` рядом с сокетами (0600, атомарная запись под блокировкой `web.state.lock`).
- `emergency.enter` / `emergency.exit` принимаются только от `integrityd`, `session.terminate` — только от `authd`; от других отправителей — M14. Повторные команды состояния не меняют; повтор с тем же `(src, msg_id)` получает прежний ответ.
- Каждый web-запрос перед действием вызывает `FwInbox::emergency($runDir)`: принятое `emergency.enter` действует сразу, иначе — `integrity.status` ПС-6; ПС-6 не отвечает — аварийный режим, недоступные запросы отклоняются с M10.
- `FwInbox::terminatedReason($runDir, $sid)` — если ПС-5 завершила сеанс, страница показывает M15 с причиной, сбрасывает PHP-сессию и вызывает `FwInbox::forget`.

## Запуск

```bash
php web/src/listener.php /run/fw          # на стенде: php web/src/listener.php /tmp/fw
```

## Тесты

```bash
php web/tests/test_protocol.php                         # клиент протокола без подсистем
php web/tests/test_inbox.php                            # входящие команды без подсистем
PHP=/путь/к/php python3 tests/stand/test_php_client.py    # клиент против заглушек mock_core
PHP=/путь/к/php python3 tests/stand/test_php_listener.py  # приёмник против заглушек mock_core
```

Пример вызова:

```php
require 'src/protocol.php';
try {
    $r = FwProtocol::request('/run/fw/authd.sock', 'web', 'authd', 'auth.login',
                             ['id' => $id, 'password' => $pwd, 'source' => 'web']);
    $sid = $r['payload']['session_id'];
} catch (FwProtocolError $e) {
    // $e->fwCode: M02, M12, M16 ...; $e->fwMessage — текст для области сообщений
}
```
