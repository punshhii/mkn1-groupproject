<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      pages
 * Назначение:  разделы меню (таблица 7, столбец Web) и разметка страниц: шапка
 *              (идентификатор, роль, IP-адрес, режим, «Выход»), левое меню,
 *              область сообщений (ошибки — красным, M09 — зелёным), баннеры M04
 *              и M08, рабочая область. В режиме аварийной поддержки доступны
 *              только «Состояние», «Журналы», «Конфигурация» (просмотр) и
 *              «Система»; остальные запросы отклоняются с M10 (FR-49).
 * Методы:
 *   - FW_SECTIONS — разделы меню: идентификатор -> название (ТЗ, «Web-интерфейс»)
 *   - FW_READY_SECTIONS — разделы, страницы которых уже реализованы
 *   - FW_EMERGENCY_SECTIONS — разделы аварийного режима: true — с изменениями, false — просмотр
 *   - fw_page_denied — код отказа для раздела: null или M10
 *   - fw_h — экранирование HTML
 *   - fw_table — таблица данных
 *   - fw_form — форма действия с CSRF-токеном (и подтверждением, если нужно)
 *   - fw_layout — страница целиком
 *   - fw_login_page — форма входа
 */

declare(strict_types=1);

require_once __DIR__ . '/protocol.php';

const FW_SECTIONS = [
    'status' => 'Состояние',
    'policy' => 'Политика доступа',
    'conntrack' => 'Контроль состояний',
    'logs' => 'Журналы',
    'config' => 'Конфигурация',
    'admins' => 'Администраторы',
    'network' => 'Сеть',
    'system' => 'Система',
];

const FW_READY_SECTIONS = ['status', 'conntrack', 'admins', 'network'];

const FW_EMERGENCY_SECTIONS = [
    'status' => true,
    'logs' => true,
    'config' => false,  // только просмотр
    'system' => true,
];

/**
 * Можно ли открыть раздел section; modify — запрос изменяет данные (POST),
 * emergency — режим аварийной поддержки. null — можно, M10 — нет.
 */
function fw_page_denied(string $section, bool $modify, bool $emergency): ?string
{
    if (!$emergency) {
        return null;
    }
    if (!array_key_exists($section, FW_EMERGENCY_SECTIONS)) {
        return 'M10';
    }
    return ($modify && !FW_EMERGENCY_SECTIONS[$section]) ? 'M10' : null;
}

function fw_h($v): string
{
    return htmlspecialchars($v === null ? '-' : (is_bool($v) ? ($v ? 'yes' : 'no') : (string)$v),
                            ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Таблица: columns — [ключ => заголовок], rows — список ассоциативных массивов. */
function fw_table(array $columns, array $rows, ?callable $actions = null): string
{
    if ($rows === []) {
        return '<p class="empty">' . fw_h(FwProtocol::messageText('M13')) . '</p>';
    }
    $html = '<table><tr>';
    foreach ($columns as $title) {
        $html .= '<th>' . fw_h($title) . '</th>';
    }
    if ($actions) {
        $html .= '<th></th>';
    }
    $html .= '</tr>';
    foreach ($rows as $r) {
        $html .= '<tr>';
        foreach (array_keys($columns) as $k) {
            $html .= '<td>' . fw_h($r[$k] ?? null) . '</td>';
        }
        if ($actions) {
            $html .= '<td>' . $actions($r) . '</td>';
        }
        $html .= '</tr>';
    }
    return $html . '</table>';
}

/**
 * Форма действия: скрытые поля, CSRF-токен; confirm — текст подтверждения
 * (действия, требующие подтверждения в CLI, требуют его и в web).
 */
function fw_form(string $section, string $action, array $hidden, string $button, string $csrf,
                 string $fields = '', ?string $confirm = null): string
{
    $html = '<form method="post" action="?page=' . fw_h($section) . '"'
          . ($confirm ? ' onsubmit="return confirm(' . fw_h(json_encode($confirm, JSON_UNESCAPED_UNICODE)) . ')"' : '')
          . '><input type="hidden" name="action" value="' . fw_h($action) . '">'
          . '<input type="hidden" name="csrf" value="' . fw_h($csrf) . '">';
    foreach ($hidden as $k => $v) {
        $html .= '<input type="hidden" name="' . fw_h($k) . '" value="' . fw_h($v) . '">';
    }
    return $html . $fields . '<button>' . fw_h($button) . '</button></form>';
}

const FW_CSS = <<<'CSS'
body{font-family:sans-serif;margin:0;color:#222;background:#fafafa}
header{display:flex;gap:1.5em;align-items:center;padding:.6em 1em;background:#2d3e50;color:#fff;flex-wrap:wrap}
header .mode{padding:.1em .6em;border-radius:3px;background:#2e7d32}
header .mode.emergency{background:#c62828}
header form{margin-left:auto}
nav{float:left;width:13em;padding:1em}
nav a,nav span{display:block;padding:.3em .5em;color:#2d3e50;text-decoration:none}
nav a.current{font-weight:bold;background:#e3e8ee}
nav span{color:#aaa}
main{margin-left:15em;padding:1em;max-width:70em}
.banner{padding:.6em 1em;background:#fdecea;color:#b71c1c;border-bottom:1px solid #f5c6cb}
.banner.warn{background:#fff8e1;color:#7a5c00;border-color:#ffe08a}
.msg{padding:.5em .8em;margin:.5em 0;border-radius:3px}
.msg.error{background:#fdecea;color:#b71c1c}
.msg.ok{background:#e8f5e9;color:#1b5e20}
table{border-collapse:collapse;margin:.5em 0}
th,td{border:1px solid #ccc;padding:.25em .6em;text-align:left;vertical-align:top}
th{background:#eef1f4}
form{display:inline}
.box{margin:1em 0}
.empty{color:#777}
.login{max-width:22em;margin:5em auto;padding:1.5em;background:#fff;border:1px solid #ddd}
.login form{display:block}
.login label{display:block;margin:.6em 0}
.login input{width:100%;box-sizing:border-box}
CSS;

/**
 * Страница целиком. $s — сеанс (username, role, ip), $mode — ['emergency', 'banner'],
 * $messages — [['error'|'ok', текст]], $body — рабочая область.
 */
function fw_layout(string $section, array $s, array $mode, array $messages, string $body,
                   string $csrf): string
{
    $title = FW_SECTIONS[$section] ?? 'ПО МЭ';
    $html = '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
          . '<meta name="viewport" content="width=device-width, initial-scale=1">'
          . '<title>' . fw_h($title) . ' — ПО МЭ</title><style>' . FW_CSS . '</style></head><body>';
    $html .= '<header><strong>ПО МЭ</strong><span>' . fw_h($s['username']) . '</span>'
           . '<span>роль: ' . fw_h($s['role']) . '</span><span>IP: ' . fw_h($s['ip']) . '</span>'
           . '<span class="mode' . ($mode['emergency'] ? ' emergency' : '') . '">'
           . ($mode['emergency'] ? 'Аварийная поддержка' : 'Штатный') . '</span>'
           . fw_form('logout', 'logout', [], 'Выход', $csrf) . '</header>';
    if ($mode['banner'] !== null) {
        $html .= '<div class="banner">' . fw_h($mode['banner']) . '</div>';  // M08 (или M16 от ПС-6)
    }
    if (!empty($s['warning'])) {
        $html .= '<div class="banner warn">' . fw_h($s['warning']) . '</div>';  // M04
    }
    $html .= '<nav>';
    foreach (FW_SECTIONS as $id => $name) {
        $html .= in_array($id, FW_READY_SECTIONS, true)
            ? '<a href="?page=' . $id . '"' . ($id === $section ? ' class="current"' : '') . '>' . fw_h($name) . '</a>'
            : '<span title="раздел пока не реализован">' . fw_h($name) . '</span>';
    }
    $html .= '</nav><main><h1>' . fw_h($title) . '</h1>';
    foreach ($messages as [$kind, $text]) {
        $html .= '<div class="msg ' . ($kind === 'ok' ? 'ok' : 'error') . '">' . fw_h($text) . '</div>';
    }
    return $html . $body . '</main></body></html>';
}

function fw_login_page(?string $message, string $csrf): string
{
    return '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
         . '<meta name="viewport" content="width=device-width, initial-scale=1">'
         . '<title>Вход — ПО МЭ</title><style>' . FW_CSS . '</style></head><body><div class="login">'
         . '<h1>Вход</h1>'
         . ($message !== null ? '<div class="msg error">' . fw_h($message) . '</div>' : '')
         . '<form method="post" action="?page=login"><input type="hidden" name="csrf" value="' . fw_h($csrf) . '">'
         . '<label>Идентификатор <input name="id" autocomplete="username" required></label>'
         . '<label>Пароль <input name="password" type="password" autocomplete="current-password" required></label>'
         . '<button>Войти</button></form></div></body></html>';
}
