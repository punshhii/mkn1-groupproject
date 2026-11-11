<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      listener
 * Назначение:  постоянный процесс ПС-4: принимает входящие команды на
 *              /run/fw/web.sock (0600) — emergency.enter / emergency.exit от ПС-6,
 *              session.terminate от ПС-5 — и записывает состояние в
 *              web.state.json (FwInbox). Повтор запроса с тем же (src, msg_id)
 *              получает прежний ответ (PROTOCOL.md). Некорректная строка
 *              игнорируется, исключения не завершают процесс.
 * Методы:
 *   - fw_listener_busy — сокет уже слушает другой процесс
 *   - fw_listener_reply — ответ на одну строку запроса (с учётом кэша повторов)
 *   - fw_listener_run — цикл приёма соединений
 * Запуск:      php web/src/listener.php [/run/fw]     (на стенде: /tmp/fw)
 */

declare(strict_types=1);

require_once __DIR__ . '/inbox.php';

const FW_LISTENER_CACHE = 1024;  // ответов в кэше повторов

function fw_listener_busy(string $path): bool
{
    $s = @stream_socket_client('unix://' . $path, $errno, $errstr, 1.0);
    if ($s === false) {
        return false;
    }
    fclose($s);
    return true;
}

/** Ответ (строка JSON) на строку запроса или null, если отвечать не нужно. */
function fw_listener_reply(string $runDir, string $line, array &$cache): ?string
{
    $msg = json_decode($line, true);
    try {
        FwProtocol::validateEnvelope($msg);
    } catch (InvalidArgumentException $e) {
        return null;  // некорректный конверт — строка игнорируется
    }
    if ($msg['type'] !== 'request') {
        return null;  // события и ответы приёмнику не адресуются
    }
    $key = $msg['src'] . ':' . $msg['msg_id'];
    if (isset($cache[$key])) {
        return $cache[$key];  // повтор: прежний ответ, состояние не меняется
    }
    try {
        [$st, $payload, $ec, $em] = FwInbox::update($runDir, fn(array $s) => FwInbox::handle($msg, $s));
    } catch (Throwable $e) {
        [$st, $payload, $ec, $em] = ['error', [], 'M16', 'внутренняя ошибка ПС-4: ' . $e->getMessage()];
    }
    $resp = FwProtocol::encodeLine(FwProtocol::makeMsg('response', 'web', $msg['src'], $msg['cmd'],
        $payload, $msg['msg_id'], null,
        ['status' => $st, 'error_code' => $ec, 'error_message' => $em]));
    $cache[$key] = $resp;
    if (count($cache) > FW_LISTENER_CACHE) {
        array_shift($cache);
    }
    return $resp;
}

function fw_listener_run(string $runDir): int
{
    $path = rtrim($runDir, '/') . '/web.sock';
    if (fw_listener_busy($path)) {
        fwrite(STDERR, "fw-web-listener: $path уже слушает другой процесс\n");
        return 1;
    }
    if (file_exists($path)) {
        unlink($path);  // оставлен завершившимся процессом
    }
    $old = umask(0077);
    $srv = @stream_socket_server('unix://' . $path, $errno, $errstr);
    umask($old);
    if ($srv === false) {
        fwrite(STDERR, "fw-web-listener: $path: $errstr\n");
        return 1;
    }
    chmod($path, 0600);
    if (!is_file(FwInbox::statePath($runDir))) {
        FwInbox::save($runDir, FwInbox::initial());
    }
    $stop = false;
    if (function_exists('pcntl_async_signals')) {
        pcntl_async_signals(true);
        $h = function () use (&$stop) { $stop = true; };
        pcntl_signal(SIGTERM, $h);
        pcntl_signal(SIGINT, $h);
    }
    fwrite(STDERR, "fw-web-listener: $path\n");
    $cache = [];
    while (!$stop) {
        $c = @stream_socket_accept($srv, 1.0);
        if ($c === false) {
            continue;
        }
        stream_set_timeout($c, (int)FwProtocol::TIMEOUT_SEC);
        $buf = '';
        while (!feof($c) && strlen($buf) <= FwProtocol::MAX_LINE) {
            $chunk = fgets($c, FwProtocol::MAX_LINE);
            if ($chunk === false) {
                break;  // тайм-аут или соединение закрыто
            }
            $buf .= $chunk;
            if (substr($buf, -1) !== "\n") {
                continue;
            }
            $resp = fw_listener_reply($runDir, $buf, $cache);
            $buf = '';
            if ($resp !== null) {
                @fwrite($c, $resp);
            }
        }
        fclose($c);
    }
    fclose($srv);
    @unlink($path);
    return 0;
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    exit(fw_listener_run($argv[1] ?? '/run/fw'));
}
