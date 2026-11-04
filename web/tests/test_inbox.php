<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      test_inbox
 * Назначение:  тесты входящих команд ПС-4 (web/src/inbox.php, web/src/listener.php)
 *              без подсистем: emergency.enter / exit (идемпотентность, M08),
 *              session.terminate (M06, причина M15), проверка отправителя (M14),
 *              файл состояния (0600, атомарная запись), кэш повторов по
 *              (src, msg_id), некорректные строки; разделы в аварийном режиме (M10),
 *              M15 и сброс PHP-сессии; общие сценарии tests/shared (шаги notify, mode)
 * Запуск:      php web/tests/test_inbox.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/listener.php';
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/pages.php';

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

function req(string $cmd, string $src, array $payload = []): array
{
    return FwProtocol::makeMsg('request', $src, 'web', $cmd, $payload);
}

// --- FwInbox::handle --------------------------------------------------------
$s = FwInbox::initial();
[$s, $r] = FwInbox::handle(req('emergency.enter', 'integrityd', ['error_message' => 'M08 text']), $s);
check($r[0] === 'ok' && $r[1] === ['mode' => 'emergency'], 'emergency.enter -> ok, emergency');
check($s['emergency'] === true && $s['notice'] === 'M08 text', 'режим и текст M08 сохранены');
$s['notice'] = null;
[$s2, $r] = FwInbox::handle(req('emergency.enter', 'integrityd'), $s);
check($r[0] === 'ok' && $s2 === $s, 'повторный emergency.enter не меняет состояния');
[$s, $r] = FwInbox::handle(req('emergency.exit', 'integrityd'), $s);
check($r[1] === ['mode' => 'normal'] && $s['emergency'] === false, 'emergency.exit -> normal');
[$s2, $r] = FwInbox::handle(req('emergency.exit', 'integrityd'), $s);
check($r[0] === 'ok' && $s2 === $s, 'повторный emergency.exit — ok без изменений');
[$s2, $r] = FwInbox::handle(req('emergency.enter', 'integrityd'), FwInbox::initial());
check($s2['notice'] === FwProtocol::messageText('M08'), 'без error_message — текст M08 из messages.json');

foreach ([['emergency.enter', 'authd'], ['session.terminate', 'integrityd'], ['rule.replace', 'integrityd']] as [$c, $src]) {
    [$s2, $r] = FwInbox::handle(req($c, $src), FwInbox::initial());
    check($r[2] === 'M14' && $s2 === FwInbox::initial(), "$c от $src отклоняется с M14");
}

[$s, $r] = FwInbox::handle(req('session.terminate', 'authd'), FwInbox::initial());
check($r[2] === 'M06', 'session.terminate без session_id -> M06');
[$s, $r] = FwInbox::handle(req('session.terminate', 'authd', ['session_id' => 'abc', 'reason' => 'сброшен']), $s);
check($r[0] === 'ok' && $s['terminated'] === ['abc' => 'сброшен'], 'session.terminate запомнен с причиной');
[$s, $r] = FwInbox::handle(req('session.terminate', 'authd', ['session_id' => 'def']), $s);
check(is_string($s['terminated']['def']) && $s['terminated']['def'] !== '', 'причина по умолчанию');

// --- файл состояния ---------------------------------------------------------
$dir = sys_get_temp_dir() . '/fw-inbox-' . getmypid();
@mkdir($dir, 0700);
check(FwInbox::load($dir) === FwInbox::initial(), 'нет файла — исходное состояние');
FwInbox::save($dir, $s);
check((fileperms(FwInbox::statePath($dir)) & 0777) === 0600, 'файл состояния 0600');
check(FwInbox::terminatedReason($dir, 'abc') === 'сброшен', 'terminatedReason читает файл');
check(FwInbox::terminatedReason($dir, 'zzz') === null, 'чужой сеанс — null');
FwInbox::forget($dir, 'abc');
check(FwInbox::terminatedReason($dir, 'abc') === null, 'forget убирает сеанс');
file_put_contents(FwInbox::statePath($dir), '{испорчен');
check(FwInbox::load($dir) === FwInbox::initial(), 'испорченный файл — исходное состояние');

// --- обработка строк приёмником ------------------------------------------------
$cache = [];
$line = FwProtocol::encodeLine(req('emergency.enter', 'integrityd', ['error_message' => 'x']));
$a = fw_listener_reply($dir, $line, $cache);
$resp = json_decode((string)$a, true);
check(is_array($resp) && $resp['type'] === 'response' && $resp['status'] === 'ok'
      && $resp['src'] === 'web' && $resp['dst'] === 'integrityd', 'ответ — response от web');
check($resp['reply_to'] === json_decode($line, true)['msg_id'], 'reply_to = msg_id запроса');
FwProtocol::validateEnvelope($resp);
check(FwInbox::load($dir)['emergency'] === true, 'состояние записано в файл');
check(FwInbox::takeNotice($dir) === 'x' && FwInbox::takeNotice($dir) === null, 'M08 показывается один раз');
FwInbox::save($dir, FwInbox::initial());
check(fw_listener_reply($dir, $line, $cache) === $a, 'повтор (src, msg_id) — прежний ответ');
check(FwInbox::load($dir)['emergency'] === null, 'повтор не выполняется заново');
check(fw_listener_reply($dir, "{мусор\n", $cache) === null, 'мусор игнорируется');
check(fw_listener_reply($dir, FwProtocol::encodeLine(FwProtocol::makeMsg('event', 'integrityd', 'web',
      'emergency.enter')), $cache) === null, 'на событие ответа нет');
$bad = json_decode((string)fw_listener_reply($dir, FwProtocol::encodeLine(req('emergency.enter', 'authd')),
                                             $cache), true);
check($bad['status'] === 'error' && $bad['error_code'] === 'M14', 'чужой отправитель — error M14');

// --- разделы в аварийном режиме (FR-49) ------------------------------------------
foreach (array_keys(FW_SECTIONS) as $sec) {
    check(fw_page_denied($sec, true, false) === null, "штатный режим: $sec доступен");
}
foreach (['status', 'logs', 'system'] as $sec) {
    check(fw_page_denied($sec, false, true) === null && fw_page_denied($sec, true, true) === null,
          "аварийный режим: $sec доступен");
}
check(fw_page_denied('config', false, true) === null, 'аварийный режим: просмотр конфигурации');
check(fw_page_denied('config', true, true) === 'M10', 'аварийный режим: изменение конфигурации -> M10');
foreach (['policy', 'conntrack', 'admins', 'network', 'нет_такого'] as $sec) {
    check(fw_page_denied($sec, false, true) === 'M10', "аварийный режим: $sec -> M10");
}

// --- session.terminate: M15 и сброс PHP-сессии -------------------------------------
FwInbox::save($dir, FwInbox::initial());
[$st] = FwInbox::handle(req('session.terminate', 'authd', ['session_id' => 's1', 'reason' => 'сброшен']),
                        FwInbox::initial());
FwInbox::save($dir, $st);
check(fw_auth_terminated($dir, [FW_SESSION_KEY => 's2']) === null, 'другой сеанс не завершён');
check(fw_auth_terminated($dir, []) === null, 'нет входа — нечего завершать');
$_SESSION = [FW_SESSION_KEY => 's1', 'role' => 'rw'];
check(fw_auth_enforce_terminate($dir) === FwProtocol::messageText('M15', ['reason' => 'сброшен']),
      'M15 с причиной');
check($_SESSION === [], 'PHP-сессия сброшена');
check(FwInbox::terminatedReason($dir, 's1') === null, 'завершённый сеанс убран из файла');

// --- общие сценарии tests/shared: шаги notify и mode ---------------------------------
$total = 0;
foreach (glob(__DIR__ . '/../../tests/shared/*.json') as $path) {
    $sc = json_decode((string)file_get_contents($path), true);
    $s = FwInbox::initial();
    foreach ($sc['steps'] as $i => $step) {
        $what = basename($path) . " шаг $i ({$step['do']})";
        if ($step['do'] === 'notify') {
            $total++;
            $payload = array_map(fn($v) => $v === '$session' ? 'sid-shared' : $v, $step['payload'] ?? []);
            [$s, $r] = FwInbox::handle(req($step['cmd'], $step['src'], $payload), $s);
            $got = ['status' => $r[0]];
            if (array_key_exists('mode', $step['expect'])) {
                $got['mode'] = $r[1]['mode'] ?? null;
            }
            if ($r[2] !== null) {
                $got['error_code'] = $r[2];
            }
            check($got == $step['expect'], "$what: " . json_encode($got, JSON_UNESCAPED_UNICODE));
        } elseif ($step['do'] === 'mode') {
            $total++;
            // ПС-6 в сценарии отвечает штатным режимом: режим задаёт уведомление
            check(($s['emergency'] === true ? 'emergency' : 'normal') === $step['expect'], $what);
        }
    }
}
check($total > 0, 'в tests/shared есть шаги notify / mode');

array_map('unlink', glob($dir . '/*'));
rmdir($dir);

if ($failures) {
    echo "FAILED $failures из $checks\n";
    exit(1);
}
echo "OK $checks проверок\n";
