<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      auth
 * Назначение:  сеанс web: вход через ПС-5 (auth.login с IP из REMOTE_ADDR), выход
 *              (auth.logout), данные сеанса в PHP-сессии, CSRF-токен; принудительное
 *              завершение: session.terminate от ПС-5 (принят web/src/listener.php)
 *              или M15 на auth.check — показать M15 и сбросить PHP-сессию (FR-35).
 *              Право на страницу и действие проверяет ПС-5 (FwApi::check).
 * Методы:
 *   - FW_SESSION_KEY — ключ PHP-сессии с session_id ПС-5
 *   - fw_auth_login — auth.login: сеанс в PHP-сессии (FwProtocolError M02, M12, M16)
 *   - fw_auth_logout — auth.logout и сброс PHP-сессии
 *   - fw_auth_session — данные текущего сеанса или null
 *   - fw_auth_reset — сбросить PHP-сессию
 *   - fw_auth_csrf / fw_auth_csrf_ok — CSRF-токен формы и его проверка
 *   - fw_auth_terminated — текст M15, если ПС-5 завершила сеанс из данных PHP-сессии
 *   - fw_auth_enforce_terminate — проверка для текущего запроса: M15 и сброс $_SESSION
 */

declare(strict_types=1);

require_once __DIR__ . '/inbox.php';
require_once __DIR__ . '/api.php';

const FW_SESSION_KEY = 'fw_session_id';

function fw_auth_login(FwApi $api, string $id, string $password, string $ip): array
{
    $p = $api->call('authd', 'auth.login', ['id' => $id, 'password' => $password,
                                            'source' => 'web', 'ip' => $ip]);
    $sid = $p['session_id'] ?? null;
    $role = $p['role'] ?? null;
    if (!is_string($sid) || $sid === '' || !in_array($role, ['rw', 'ro'], true)) {
        throw new FwProtocolError('M16', 'некорректный ответ ПС-5 на auth.login');
    }
    session_regenerate_id(true);
    $_SESSION[FW_SESSION_KEY] = $sid;
    $_SESSION['username'] = is_string($p['username'] ?? null) ? $p['username'] : $id;
    $_SESSION['role'] = $role;  // только для показа и скрытия кнопок: право решает ПС-5
    $_SESSION['ip'] = $ip;
    $_SESSION['warning'] = ($p['warning'] ?? null) === 'M04' ? FwProtocol::messageText('M04') : null;
    return fw_auth_session();
}

function fw_auth_session(): ?array
{
    $sid = $_SESSION[FW_SESSION_KEY] ?? null;
    if (!is_string($sid) || $sid === '') {
        return null;
    }
    return ['session_id' => $sid, 'username' => (string)($_SESSION['username'] ?? ''),
            'role' => (string)($_SESSION['role'] ?? 'ro'), 'ip' => (string)($_SESSION['ip'] ?? ''),
            'warning' => $_SESSION['warning'] ?? null];
}

function fw_auth_reset(): void
{
    $_SESSION = [];
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
}

function fw_auth_logout(FwApi $api): void
{
    $s = fw_auth_session();
    if ($s !== null) {
        try {
            $api->call('authd', 'auth.logout', ['session_id' => $s['session_id']]);  // E02 — ПС-5
        } catch (FwProtocolError $e) {
            // сеанс уже завершён или ПС-5 недоступна: PHP-сессия сбрасывается всё равно
        }
    }
    fw_auth_reset();
}

function fw_auth_csrf(): string
{
    if (!is_string($_SESSION['csrf'] ?? null)) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf'];
}

function fw_auth_csrf_ok($token): bool
{
    return is_string($token) && is_string($_SESSION['csrf'] ?? null) && hash_equals($_SESSION['csrf'], $token);
}

/** Текст M15 для сеанса из массива PHP-сессии или null, если сеанс не завершён. */
function fw_auth_terminated(string $runDir, array $session): ?string
{
    $sid = $session[FW_SESSION_KEY] ?? null;
    if (!is_string($sid) || $sid === '') {
        return null;
    }
    $reason = FwInbox::terminatedReason($runDir, $sid);
    return $reason === null ? null : FwProtocol::messageText('M15', ['reason' => $reason]);
}

/**
 * Вызывается в начале каждого web-запроса после session_start(). Если ПС-5
 * завершила сеанс — сбрасывает PHP-сессию и возвращает текст M15 для страницы входа.
 */
function fw_auth_enforce_terminate(string $runDir): ?string
{
    $text = fw_auth_terminated($runDir, $_SESSION ?? []);
    if ($text === null) {
        return null;
    }
    FwInbox::forget($runDir, (string)$_SESSION[FW_SESSION_KEY]);
    $_SESSION = [];
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
    return $text;
}
