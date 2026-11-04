<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      index
 * Назначение:  единая точка входа web-интерфейса (корень сайта nginx или php -S)
 * Методы:
 *   - (маршрутизация) — выбор страницы по ?page=, см. web/src/server.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/server.php';

fw_server_handle();
