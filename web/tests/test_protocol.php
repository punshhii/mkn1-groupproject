<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      test_protocol
 * Назначение:  тесты PHP-клиента протокола (web/src/protocol.php): конверт и его
 *              проверка, метка времени, msg_id, кодирование; с каталогом сокетов
 *              заглушек — запросы к authd, ошибки M02/M14, M16 после повторов,
 *              отправка события в logd
 * Запуск:      php web/tests/test_protocol.php                 (без подсистем)
 *              php web/tests/test_protocol.php /tmp/fw /tmp/fw-slow
 *              (каталоги сокетов mock_core: обычный и с задержкой ответа;
 *               так запускает tests/stand/test_php_client.py)
 */

declare(strict_types=1);

require __DIR__ . '/../src/protocol.php';

$failures = 0;
$checks = 0;

function check(bool $cond, string $what): void
{
    global $failures, $checks;
    $checks++;
    if (!$cond) {
        $failures++;
        fwrite(STDERR, "FAIL: $what\n");
    }
}

function expectError(callable $fn, string $code, string $what): ?FwProtocolError
{
    try {
        $fn();
    } catch (FwProtocolError $e) {
        check($e->fwCode === $code, "$what: ожидался $code, получен {$e->fwCode}");
        return $e;
    }
    check(false, "$what: ожидалась ошибка $code");
    return null;
}

function expectInvalid(array $msg, string $what): void
{
    try {
        FwProtocol::validateEnvelope($msg);
        check(false, "$what: конверт должен быть отклонён");
    } catch (InvalidArgumentException $e) {
        check(true, $what);
    }
}

// --- без подсистем ----------------------------------------------------------

check((bool)preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/', FwProtocol::nowIso()), 'nowIso');

$a = FwProtocol::newId();
$b = FwProtocol::newId();
check($b === $a + 1, 'newId монотонный');
check($a >= 0 && $a < 2 ** 52, 'newId в пределах 2^52');

$msg = FwProtocol::makeMsg('request', 'web', 'authd', 'auth.ping');
check(FwProtocol::validateEnvelope($msg) === $msg, 'корректный конверт');
$line = FwProtocol::encodeLine($msg);
check(str_ends_with($line, "\n") && substr_count($line, "\n") === 1, 'одна строка с \n');
check(str_contains($line, '"payload":{}'), 'пустой payload кодируется как {}');
$u = FwProtocol::encodeLine(FwProtocol::makeMsg('request', 'web', 'authd', 'auth.login',
                                                ['id' => 'админ']));
check(str_contains($u, 'админ'), 'UTF-8 без \u-экранирования');

expectInvalid(array_merge($msg, ['type' => 'x']), 'неверный type');
expectInvalid(array_merge($msg, ['src' => 'php']), 'неверный src');
expectInvalid(array_merge($msg, ['cmd' => 'AUTH.PING']), 'неверный cmd');
expectInvalid(array_merge($msg, ['cmd' => null]), 'cmd обязателен для request');
expectInvalid(array_merge($msg, ['ts' => '2026-10-28 10:00:00']), 'неверный ts');
expectInvalid(array_merge($msg, ['payload' => [1, 2]]), 'payload-список');
expectInvalid(array_merge($msg, ['msg_id' => '5']), 'msg_id строкой');
$resp = FwProtocol::makeMsg('response', 'authd', 'web', 'auth.ping', [], null);
expectInvalid($resp, 'response без reply_to');
expectInvalid(array_merge($resp, ['reply_to' => 1, 'status' => 'error']), 'error без error_code');

check(str_contains(FwProtocol::messageText('M16', ['name' => 'authd']), '«authd»'), 'текст M16');

expectError(fn() => FwProtocol::request('/nonexistent/authd.sock', 'web', 'authd', 'auth.ping',
                                        [], 0.2, 2), 'M16', 'нет сокета');

// --- против заглушек mock_core ------------------------------------------------

$dir = $argv[1] ?? null;
$slow = $argv[2] ?? null;
if ($dir !== null) {
    $authd = "$dir/authd.sock";
    $r = FwProtocol::request($authd, 'web', 'authd', 'auth.login',
                             ['id' => 'admin', 'password' => 'admin123', 'source' => 'web']);
    check($r['status'] === 'ok' && $r['src'] === 'authd' && $r['dst'] === 'web', 'auth.login ok');
    $sid = $r['payload']['session_id'] ?? '';
    check(strlen($sid) === 32, 'session_id');
    check(($r['payload']['role'] ?? null) === 'rw', 'роль rw');

    $p = FwProtocol::request($authd, 'web', 'authd', 'auth.ping', ['session_id' => $sid]);
    check(($p['payload']['status'] ?? null) === 'pong', 'auth.ping');

    $e = expectError(fn() => FwProtocol::request($authd, 'web', 'authd', 'auth.login',
                     ['id' => 'admin', 'password' => 'wrong-password']), 'M02', 'неверный пароль');
    check($e !== null && str_contains($e->fwMessage, 'неверный идентификатор'), 'текст M02');
    expectError(fn() => FwProtocol::request($authd, 'web', 'authd', 'rule.dropall'), 'M14',
                'неизвестная команда');

    $rules = FwProtocol::request("$dir/filter.sock", 'web', 'filter', 'rule.get');
    check(count($rules['payload']['rules'] ?? []) === 2, 'rule.get');

    FwProtocol::sendEvent("$dir/logd.sock", 'web', 'logd', 'log.write.event',
                          ['code' => 'E50', 'actor' => 'viewer', 'cmd' => 'rule add', 'source' => 'web']);
    check(true, 'sendEvent');
}
if ($slow !== null) {
    // ответ через 1 с, окно попыток 0.2 с * 3 = 0.6 с -> M16 после двух повторов
    $t0 = FwProtocol::monotonic();
    expectError(fn() => FwProtocol::request("$slow/authd.sock", 'web', 'authd', 'auth.ping',
                                            [], 0.2, 2), 'M16', 'медленная подсистема');
    $dt = FwProtocol::monotonic() - $t0;
    check($dt >= 0.55 && $dt < 2.0, sprintf('три попытки по 0.2 с (%.2f с)', $dt));
}

if ($failures > 0) {
    fwrite(STDERR, "FAILED: $failures из $checks\n");
    exit(1);
}
echo "OK $checks\n";
