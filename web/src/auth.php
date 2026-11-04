<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      auth
 * Назначение:  проверка сеанса, CSRF. Сейчас реализовано принудительное завершение
 *              сеанса: session.terminate от ПС-5 (принят web/src/listener.php) —
 *              показать M15 и сбросить PHP-сессию (FR-35, README ПС-4).
 * Методы:
 *   - FW_SESSION_KEY — ключ PHP-сессии с session_id ПС-5
 *   - fw_auth_terminated — текст M15, если ПС-5 завершила сеанс из данных PHP-сессии
 *   - fw_auth_enforce_terminate — проверка для текущего запроса: M15 и сброс $_SESSION
 */

declare(strict_types=1);

require_once __DIR__ . '/inbox.php';

const FW_SESSION_KEY = 'fw_session_id';

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
