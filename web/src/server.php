<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      server
 * Назначение:  обработка web-запроса (точка входа web/public/index.php; на МЭ —
 *              за nginx по HTTPS на 8443, на стенде — php -S). Порядок для каждого
 *              запроса: session.terminate от ПС-5 (M15) -> вход через ПС-5, если
 *              сеанса нет -> режим по integrity.status ПС-6 (баннер M08, M16 —
 *              аварийный) -> auth.check на страницу -> для действия: CSRF, M10 в
 *              аварийном режиме, auth.check на действие -> страница раздела.
 *              Разделы: «Состояние», «Контроль состояний», «Администраторы», «Сеть».
 * Методы:
 *   - FW_PAGE_CMD — команда таблицы 7, по которой ПС-5 проверяет право на просмотр раздела
 *   - FW_ACTIONS — действия: раздел, команда для auth.check, подтверждение
 *   - fw_server_handle — обработать текущий запрос и вывести страницу
 *   - fw_do_action — выполнить действие раздела -> [вид сообщения, текст]
 *   - fw_section_body — рабочая область раздела
 */

declare(strict_types=1);

require_once __DIR__ . '/protocol.php';
require_once __DIR__ . '/inbox.php';
require_once __DIR__ . '/api.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/pages.php';

const FW_PAGE_CMD = [
    'status' => 'sys info',
    'conntrack' => 'state table',
    'admins' => 'session list',
    'network' => 'if list',
];

const FW_ACTIONS = [
    'session_kill' => ['admins', 'session kill', null],
    'state_enable' => ['conntrack', 'state enable', null],
    'state_disable' => ['conntrack', 'state disable', null],
    'state_delete' => ['conntrack', 'state delete', null],
    'state_delete_all' => ['conntrack', 'state delete all', 'Удалить все записи таблицы состояний?'],
    'if_ip' => ['network', 'if ip', null],
    'route_add' => ['network', 'route add', null],
    'route_del' => ['network', 'route del', null],
];

const FW_RW_ACTIONS = ['session_kill', 'state_enable', 'state_disable', 'state_delete',
                       'state_delete_all', 'if_ip', 'route_add', 'route_del'];

function fw_server_handle(): void
{
    $api = FwApi::fromEnv();
    session_name('fwweb');
    session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict',
                               'secure' => !empty($_SERVER['HTTPS'])]);
    session_start();
    header('Content-Type: text/html; charset=utf-8');
    header('X-Frame-Options: DENY');
    $page = is_string($_GET['page'] ?? null) ? $_GET['page'] : 'status';
    $post = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';

    $m15 = fw_auth_enforce_terminate($api->runDir);  // session.terminate от ПС-5
    if ($m15 !== null) {
        session_start();
        echo fw_login_page($m15, fw_auth_csrf());
        return;
    }
    if ($page === 'login' && $post) {
        if (!fw_auth_csrf_ok($_POST['csrf'] ?? null)) {
            echo fw_login_page('Ошибка: форма устарела, повторите вход', fw_auth_csrf());
            return;
        }
        try {
            fw_auth_login($api, (string)($_POST['id'] ?? ''), (string)($_POST['password'] ?? ''),
                          (string)($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'));
        } catch (FwProtocolError $e) {
            echo fw_login_page($e->fwMessage, fw_auth_csrf());  // M02, M12, M16
            return;
        }
        header('Location: ?page=status', true, 303);
        return;
    }
    $s = fw_auth_session();
    if ($s === null) {
        echo fw_login_page(null, fw_auth_csrf());
        return;
    }
    if ($page === 'logout' && $post && fw_auth_csrf_ok($_POST['csrf'] ?? null)) {
        fw_auth_logout($api);
        echo fw_login_page(null, fw_auth_csrf());
        return;
    }
    if (!in_array($page, FW_READY_SECTIONS, true)) {
        $page = 'status';
    }

    $mode = FwInbox::modeInfo($api->runDir);  // integrity.status на каждом запросе
    $notice = FwInbox::takeNotice($api->runDir);
    if ($notice !== null && $mode['emergency']) {
        $mode['banner'] = $notice;
    }
    $csrf = fw_auth_csrf();
    $messages = [];

    // право на просмотр раздела — ПС-5; аварийный режим — M10
    $denied = fw_page_denied($page, false, $mode['emergency']);
    if ($denied === null) {
        try {
            $api->check($s['session_id'], FW_PAGE_CMD[$page]);
        } catch (FwProtocolError $e) {
            if ($e->fwCode === 'M15') {
                fw_auth_reset();
                echo fw_login_page($e->fwMessage, fw_auth_csrf());
                return;
            }
            $denied = $e->fwCode;
            $messages[] = ['error', $e->fwMessage];  // M16 — ПС-5 не отвечает, M03
        }
    } else {
        $messages[] = ['error', FwProtocol::messageText($denied)];
    }

    if ($denied === null && $post) {
        $action = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';
        if (!fw_auth_csrf_ok($_POST['csrf'] ?? null)) {
            $messages[] = ['error', 'Ошибка: форма устарела, повторите действие'];
        } elseif (!isset(FW_ACTIONS[$action]) || FW_ACTIONS[$action][0] !== $page) {
            $messages[] = ['error', FwProtocol::messageText('M14')];
        } elseif ($code = fw_page_denied($page, true, $mode['emergency'])) {
            $messages[] = ['error', FwProtocol::messageText($code)];  // M10
        } else {
            try {
                $api->check($s['session_id'], FW_ACTIONS[$action][1]);  // M03 (E50 — ПС-5)
                $messages[] = fw_do_action($api, $s, $action, $_POST);
            } catch (FwProtocolError $e) {
                if ($e->fwCode === 'M15') {
                    fw_auth_reset();
                    echo fw_login_page($e->fwMessage, fw_auth_csrf());
                    return;
                }
                if ($e->fwCode !== 'M03' && in_array($action, FW_RW_ACTIONS, true)) {
                    $api->event('E43', $s, FW_ACTIONS[$action][1], 'fail',
                                ['reason' => $e->fwCode . ': ' . $e->fwMessage]);
                }
                $messages[] = ['error', $e->fwMessage];
            }
        }
    }

    $body = $denied === null ? fw_section_body($api, $page, $s, $mode, $csrf) : '';
    echo fw_layout($page, $s, $mode, $messages, $body, $csrf);
}

function fw_m06(string $field, string $allowed): FwProtocolError
{
    return new FwProtocolError('M06', FwProtocol::messageText('M06', ['field' => $field, 'allowed' => $allowed]));
}

function fw_check_cidr(string $v, string $field): string
{
    if (!preg_match('~^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$~', $v, $m)
        || ip2long($m[1]) === false || (int)$m[2] > 32) {
        throw fw_m06($field, 'адрес/маска, например 192.168.1.10/24');
    }
    return $v;
}

/** Выполнить действие (право уже проверено ПС-5) -> ['ok', M09] или FwProtocolError. */
function fw_do_action(FwApi $api, array $s, string $action, array $in): array
{
    $cmd = FW_ACTIONS[$action][1];
    switch ($action) {
        case 'session_kill':
            $api->call('authd', 'session.kill', ['session_id' => $s['session_id'],
                                                  'target_session_id' => (string)($in['target'] ?? '')]);
            break;  // E05 регистрирует ПС-5
        case 'state_enable':
        case 'state_disable':
            $api->call('filter', $action === 'state_enable' ? 'state.enable' : 'state.disable');
            break;  // E14 / E15 — ПС-1
        case 'state_delete':
            $id = (string)($in['conn_id'] ?? '');
            if (!ctype_digit($id)) {
                throw fw_m06('ID', 'номер записи таблицы состояний');
            }
            $api->call('filter', 'state.delete', ['conn_id' => (int)$id]);
            $api->event('E35', $s, $cmd, 'ok', ['conn_id' => (int)$id]);
            break;
        case 'state_delete_all':
            $api->call('filter', 'state.delete_all');
            $api->event('E35', $s, $cmd, 'ok', ['all' => true]);
            break;
        case 'if_ip':
            $name = (string)($in['name'] ?? '');
            if (!in_array($name, $api->mgmt(), true)) {  // IP только у управляющего интерфейса
                throw fw_m06('ИМЯ', 'только управляющий интерфейс: ' . (implode(', ', $api->mgmt()) ?: 'не задан'));
            }
            $addr = fw_check_cidr(trim((string)($in['addr'] ?? '')), 'адрес/маска');
            $api->setAddr($name, $addr);
            $api->event('E33', $s, $cmd, 'ok', ['iface' => $name, 'addr' => $addr]);
            break;
        case 'route_add':
            $net = fw_check_cidr(trim((string)($in['net'] ?? '')), 'сеть/маска');
            $gw = trim((string)($in['gw'] ?? ''));
            $dev = null;
            $nets = [];
            foreach ($api->links() as $l) {
                if (in_array($l['name'] ?? null, $api->mgmt(), true) && !empty($l['addr'])) {
                    $nets[] = $l['name'] . ' (' . $l['addr'] . ')';
                    if ($dev === null && fw_in_subnet($gw, $l['addr'])) {
                        $dev = $l['name'];
                    }
                }
            }
            if ($dev === null) {  // маршрут только через управляющий интерфейс
                throw fw_m06('шлюз', 'адрес в сети управляющего интерфейса: ' . (implode(', ', $nets) ?: 'не задан'));
            }
            $api->addRoute($net, $gw, $dev);
            $api->event('E33', $s, $cmd, 'ok', ['dst' => $net, 'gw' => $gw, 'dev' => $dev]);
            break;
        case 'route_del':
            $net = trim((string)($in['net'] ?? ''));
            $found = array_values(array_filter($api->routes(), fn($r) => ($r['dst'] ?? null) === $net));
            if ($found === []) {
                throw new FwProtocolError('M13', FwProtocol::messageText('M13'));
            }
            foreach ($found as $r) {
                if (!in_array($r['dev'] ?? null, $api->mgmt(), true)) {
                    throw fw_m06('сеть/маска', 'только управляющий интерфейс: ' . implode(', ', $api->mgmt()));
                }
            }
            $api->delRoute($net);
            $api->event('E33', $s, $cmd, 'ok', ['dst' => $net]);
            break;
    }
    return ['ok', FwProtocol::messageText('M09')];
}

/** Данные подсистемы для раздела: ошибка показывается в рабочей области, страница не падает. */
function fw_try(callable $fn, &$err)
{
    try {
        return $fn();
    } catch (FwProtocolError $e) {
        $err[] = $e->fwMessage;
        return null;
    }
}

function fw_section_body(FwApi $api, string $page, array $s, array $mode, string $csrf): string
{
    $err = [];
    $rw = $s['role'] === 'rw';  // кнопки изменения для ro не показываются (право всё равно решает ПС-5)
    $actions = $rw && !$mode['emergency'];
    $html = '';
    $ifaceName = function ($i) use ($api) {
        $names = $api->ifaces();
        return is_int($i) && isset($names[$i]) ? $names[$i] : $i;
    };

    if ($page === 'status') {
        $integrity = fw_try(fn() => $api->call('integrityd', 'integrity.status'), $err);
        $st = fw_try(fn() => $api->call('filter', 'state.status'), $err);
        $rules = fw_try(fn() => $api->call('filter', 'rule.get'), $err);
        $links = fw_try(fn() => $api->links(), $err);
        $html .= fw_table(['k' => 'Параметр', 'v' => 'Значение'], [
            ['k' => 'Режим работы', 'v' => $mode['emergency'] ? 'Аварийная поддержка' : 'Штатный'],
            ['k' => 'Последняя проверка целостности', 'v' => $integrity['last_check_ts'] ?? null],
            ['k' => 'Контроль состояний', 'v' => $st['enabled'] ?? null],
            ['k' => 'Записей в таблице состояний', 'v' => $st['active_sessions'] ?? null],
            ['k' => 'Правил политики доступа', 'v' => isset($rules['rules']) ? count($rules['rules']) : null],
            ['k' => 'Права сеанса', 'v' => $rw ? 'чтение/запись' : 'только чтение'],
        ]);
        $html .= '<h2>Интерфейсы</h2>' . fw_table(['name' => 'Интерфейс', 'state' => 'Состояние'],
                                                   array_values(array_filter($links ?? [], fn($l) =>
                                                       in_array($l['name'] ?? null, array_merge($api->ifaces(), $api->mgmt()), true))));
        if (!empty($integrity['files'])) {
            $html .= '<h2>Контролируемые файлы</h2>'
                   . fw_table(['path' => 'Файл', 'status' => 'Статус'],
                              array_map(fn($k, $v) => is_array($v) ? $v : ['path' => $k, 'status' => $v],
                                        array_keys($integrity['files']), $integrity['files']));
        }
    } elseif ($page === 'admins') {
        $users = fw_try(fn() => $api->call('authd', 'user.list', ['session_id' => $s['session_id']]), $err);
        $sessions = fw_try(fn() => $api->call('authd', 'session.list', ['session_id' => $s['session_id']]), $err);
        $html .= '<h2>Учётные записи</h2>' . fw_table(['id' => 'Идентификатор', 'role' => 'Роль'], $users['users'] ?? []);
        $rows = array_map(fn($r) => array_merge($r, ['ip' => $r['ip'] ?? 'локальная консоль']), $sessions['sessions'] ?? []);
        $html .= '<h2>Активные сеансы</h2>' . fw_table(
            ['username' => 'Администратор', 'role' => 'Роль', 'source' => 'Интерфейс', 'ip' => 'IP-адрес',
             'idle_sec' => 'Бездействие, с', 'downgraded' => 'Понижен', 'session_id' => 'ID сеанса'],
            $rows,
            $actions ? fn($r) => ($r['session_id'] ?? '') === $s['session_id'] ? 'текущий'
                : fw_form('admins', 'session_kill', ['target' => $r['session_id'] ?? ''], 'Сбросить', $csrf)
                : null);
    } elseif ($page === 'conntrack') {
        $st = fw_try(fn() => $api->call('filter', 'state.status'), $err);
        $list = fw_try(fn() => $api->call('filter', 'state.list'), $err);
        $labels = ['enabled' => 'Контроль состояний', 'active_sessions' => 'Записей в таблице',
                   'max_sessions' => 'Размер таблицы', 'tcp_syn_timeout_sec' => 'Таймаут TCP SYN, с',
                   'tcp_est_timeout_sec' => 'Таймаут TCP ESTABLISHED, с', 'tcp_fin_timeout_sec' => 'Таймаут TCP FIN, с',
                   'udp_timeout_no_reply' => 'Таймаут UDP без ответа, с', 'udp_timeout_reply' => 'Таймаут UDP с ответом, с',
                   'icmp_timeout_sec' => 'Таймаут ICMP, с'];
        $html .= fw_table(['k' => 'Параметр', 'v' => 'Значение'],
                          array_map(fn($k) => ['k' => $labels[$k], 'v' => $st[$k] ?? null],
                                    array_keys(array_filter($labels, fn($k) => array_key_exists($k, $st ?? []), ARRAY_FILTER_USE_KEY))));
        if ($actions && $st !== null) {
            $html .= '<div class="box">' . (!empty($st['enabled'])
                ? fw_form('conntrack', 'state_disable', [], 'Отключить механизм', $csrf)
                : fw_form('conntrack', 'state_enable', [], 'Включить механизм', $csrf))
                . ' ' . fw_form('conntrack', 'state_delete_all', [], 'Удалить все записи', $csrf, '',
                                FW_ACTIONS['state_delete_all'][2]) . '</div>';
        }
        $rows = [];
        foreach ($list['entries'] ?? [] as $e) {
            $rows[] = ['conn_id' => $e['conn_id'] ?? null, 'proto' => $e['proto'] ?? null,
                       'client' => ($e['src_ip'] ?? '?') . ':' . ($e['sport'] ?? '?'),
                       'server' => ($e['dst_ip'] ?? '?') . ':' . ($e['dport'] ?? '?'),
                       'state' => $e['state'] ?? null, 'ttl' => $e['expires_in_sec'] ?? null,
                       'in' => $ifaceName($e['in_iface'] ?? null),
                       'out' => implode(', ', array_map($ifaceName, $e['out_ifaces'] ?? [])),
                       'rule' => $e['rule_id'] ?? null];
        }
        // соединение двунаправленное: стороны — клиент (инициатор) и сервер
        $html .= '<h2>Таблица состояний</h2>' . fw_table(
            ['conn_id' => 'ID', 'proto' => 'Протокол', 'client' => 'Клиент (IP:порт)',
             'server' => 'Сервер (IP:порт)', 'state' => 'Состояние', 'ttl' => 'Осталось, с',
             'in' => 'Вход', 'out' => 'Выход', 'rule' => 'Правило'],
            $rows,
            $actions ? fn($r) => fw_form('conntrack', 'state_delete', ['conn_id' => $r['conn_id']], 'Удалить', $csrf) : null);
    } elseif ($page === 'network') {
        $mgmt = $api->mgmt();
        $known = array_merge($api->ifaces(), $mgmt);
        $links = array_values(array_filter(fw_try(fn() => $api->links(), $err) ?? [],
                                           fn($l) => in_array($l['name'] ?? null, $known, true)));
        $rows = array_map(fn($l) => array_merge($l, [
            'kind' => in_array($l['name'], $mgmt, true) ? 'управляющий' : 'фильтрующий',
            // IP-адрес есть только у управляющего интерфейса
            'addr' => in_array($l['name'], $mgmt, true) ? ($l['addr'] ?? '-') : '—']), $links);
        $html .= '<h2>Интерфейсы</h2>' . fw_table(
            ['name' => 'Интерфейс', 'kind' => 'Управляющий / фильтрующий', 'state' => 'Состояние',
             'addr' => 'IP-адрес', 'mac' => 'MAC', 'rx_bytes' => 'Принято, байт', 'tx_bytes' => 'Передано, байт'],
            $rows,
            $actions ? fn($r) => $r['kind'] === 'управляющий'
                ? fw_form('network', 'if_ip', ['name' => $r['name']], 'Задать IP', $csrf,
                          '<input name="addr" placeholder="адрес/маска" size="18" required> ')
                : '' : null);
        $routes = fw_try(fn() => $api->routes(), $err) ?? [];
        $html .= '<h2>Маршруты</h2>' . fw_table(
            ['dst' => 'Сеть', 'gw' => 'Шлюз', 'dev' => 'Интерфейс'],
            $routes,
            $actions ? fn($r) => in_array($r['dev'] ?? null, $mgmt, true)
                ? fw_form('network', 'route_del', ['net' => $r['dst']], 'Удалить', $csrf) : '' : null);
        if ($actions) {
            $html .= '<div class="box">' . fw_form('network', 'route_add', [], 'Добавить маршрут', $csrf,
                '<input name="net" placeholder="сеть/маска" size="18" required> '
                . '<input name="gw" placeholder="шлюз в сети управляющего интерфейса" size="30" required> ') . '</div>';
        }
    }
    foreach ($err as $e) {
        $html = '<div class="msg error">' . fw_h($e) . '</div>' . $html;
    }
    return $html;
}
