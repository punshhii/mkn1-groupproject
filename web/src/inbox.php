<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      inbox
 * Назначение:  входящие команды ПС-4 (README, «Принимает») и режим работы:
 *              emergency.enter / emergency.exit от ПС-6, session.terminate от ПС-5.
 *              Запросы PHP живут недолго, поэтому команды принимает постоянный
 *              процесс web/src/listener.php и записывает состояние в файл
 *              web.state.json рядом с сокетами; обработчики web-запросов читают
 *              этот файл и перед каждым действием спрашивают integrity.status
 *              (README, «Режим работы»).
 * Методы:
 *   - FwInbox::handle — обработать входящую команду: новое состояние и ответ
 *   - FwInbox::statePath / load / save — файл состояния (запись атомарная, 0600)
 *   - FwInbox::update — изменить состояние под блокировкой файла
 *   - FwInbox::emergency — аварийный режим: принятое emergency.enter или integrity.status,
 *     нет ответа ПС-6 (M16) — аварийный
 *   - FwInbox::modeInfo — режим и баннер для страницы (M08 или M16)
 *   - FwInbox::terminatedReason — причина M15, если ПС-5 завершила сеанс
 *   - FwInbox::forget — убрать завершённый сеанс из файла после вывода M15
 *   - FwInbox::takeNotice — текст M08 для показа один раз
 */

declare(strict_types=1);

require_once __DIR__ . '/protocol.php';

final class FwInbox
{
    /** Кто вправе присылать команду (данным другой подсистемы без проверки не доверяют). */
    public const SENDERS = [
        'emergency.enter' => 'integrityd',
        'emergency.exit' => 'integrityd',
        'session.terminate' => 'authd',
    ];
    public const MAX_TERMINATED = 1000;  // защитный предел списка завершённых сеансов

    public static function initial(): array
    {
        // emergency = null: уведомлений не было, режим — по integrity.status
        return ['emergency' => null, 'notice' => null, 'terminated' => []];
    }

    /**
     * Обработать входящий запрос msg (конверт уже проверен).
     * Возвращает [новое состояние, [status, payload, error_code, error_message]].
     * Повторные emergency.enter / emergency.exit состояния не меняют (идемпотентны).
     */
    public static function handle(array $msg, array $state): array
    {
        $cmd = $msg['cmd'] ?? null;
        $p = is_array($msg['payload'] ?? null) ? $msg['payload'] : [];
        if ((self::SENDERS[$cmd] ?? null) !== ($msg['src'] ?? null)) {
            return [$state, ['error', [], 'M14', FwProtocol::messageText('M14')]];
        }
        if ($cmd === 'session.terminate') {
            $sid = $p['session_id'] ?? null;
            if (!is_string($sid) || $sid === '') {
                return [$state, ['error', [], 'M06', FwProtocol::messageText('M06',
                    ['field' => 'session_id', 'allowed' => 'идентификатор сеанса'])]];
            }
            $reason = $p['reason'] ?? null;
            if (!isset($state['terminated'][$sid])) {
                $state['terminated'][$sid] = is_string($reason) && $reason !== ''
                    ? $reason : 'сеанс завершён подсистемой аутентификации';
                $state['terminated'] = array_slice($state['terminated'], -self::MAX_TERMINATED,
                                                   null, true);
            }
        } else {
            $on = $cmd === 'emergency.enter';
            if ($state['emergency'] !== $on) {
                $text = $p['error_message'] ?? null;
                $state['emergency'] = $on;
                $state['notice'] = $on ? (is_string($text) ? $text : FwProtocol::messageText('M08'))
                                       : null;
            }
        }
        $mode = $state['emergency'] === null ? 'unknown'
                                             : ($state['emergency'] ? 'emergency' : 'normal');
        return [$state, ['ok', ['mode' => $mode], null, null]];
    }

    public static function statePath(string $runDir): string
    {
        return rtrim($runDir, '/') . '/web.state.json';
    }

    public static function load(string $runDir): array
    {
        $raw = @file_get_contents(self::statePath($runDir));
        $s = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($s)) {
            return self::initial();
        }
        $init = self::initial();
        $em = $s['emergency'] ?? null;
        return [
            'emergency' => is_bool($em) ? $em : null,
            'notice' => is_string($s['notice'] ?? null) ? $s['notice'] : null,
            'terminated' => is_array($s['terminated'] ?? null) ? $s['terminated'] : $init['terminated'],
        ];
    }

    /** Записать состояние атомарно: временный файл 0600 и rename. */
    public static function save(string $runDir, array $state): void
    {
        $path = self::statePath($runDir);
        $tmp = $path . '.' . getmypid() . '.tmp';
        $json = json_encode([
            'emergency' => $state['emergency'],
            'notice' => $state['notice'],
            'terminated' => $state['terminated'] === [] ? new stdClass() : $state['terminated'],
        ], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $old = umask(0077);
        try {
            if (file_put_contents($tmp, $json) === false || !rename($tmp, $path)) {
                @unlink($tmp);
                throw new RuntimeException('не удалось записать ' . $path);
            }
        } finally {
            umask($old);
        }
    }

    /**
     * Аварийный режим для текущего web-запроса: принятое emergency.enter действует
     * сразу; иначе — integrity.status ПС-6; ПС-6 не отвечает (M16) — аварийный.
     */
    public static function emergency(string $runDir): bool
    {
        if (self::load($runDir)['emergency'] === true) {
            return true;
        }
        try {
            $r = FwProtocol::request(rtrim($runDir, '/') . '/integrityd.sock', 'web', 'integrityd',
                                     'integrity.status');
            return ($r['payload']['mode'] ?? null) !== 'normal';
        } catch (FwProtocolError $e) {
            return true;
        }
    }

    /**
     * Режим для страницы: ['emergency' => bool, 'banner' => текст или null].
     * Баннер — M08 (аварийный режим по ПС-6 или по emergency.enter) или M16,
     * если ПС-6 не ответила (режим тогда тоже аварийный).
     */
    public static function modeInfo(string $runDir): array
    {
        $notified = self::load($runDir);
        if ($notified['emergency'] === true) {
            return ['emergency' => true, 'banner' => $notified['notice'] ?? FwProtocol::messageText('M08')];
        }
        try {
            $r = FwProtocol::request(rtrim($runDir, '/') . '/integrityd.sock', 'web', 'integrityd',
                                     'integrity.status');
        } catch (FwProtocolError $e) {
            return ['emergency' => true, 'banner' => $e->fwMessage];
        }
        $on = ($r['payload']['mode'] ?? null) !== 'normal';
        return ['emergency' => $on, 'banner' => $on ? FwProtocol::messageText('M08') : null];
    }

    /** Причина для M15, если ПС-5 завершила сеанс sid; иначе null. */
    public static function terminatedReason(string $runDir, string $sid): ?string
    {
        $r = self::load($runDir)['terminated'][$sid] ?? null;
        return is_string($r) ? $r : null;
    }

    /**
     * Прочитать, изменить и записать состояние под блокировкой файла
     * (приёмник и web-запросы меняют его независимо). fn(state) -> [state, result].
     */
    public static function update(string $runDir, callable $fn)
    {
        $old = umask(0077);
        $lock = fopen(rtrim($runDir, '/') . '/web.state.lock', 'c');
        umask($old);
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new RuntimeException('не удалось заблокировать состояние ПС-4');
        }
        try {
            [$state, $result] = $fn(self::load($runDir));
            self::save($runDir, $state);
            return $result;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** Убрать сеанс из списка завершённых (M15 показан, PHP-сессия сброшена). */
    public static function forget(string $runDir, string $sid): void
    {
        self::update($runDir, function (array $s) use ($sid) {
            unset($s['terminated'][$sid]);
            return [$s, null];
        });
    }

    /** Текст M08 из emergency.enter для показа один раз (область сообщений страницы). */
    public static function takeNotice(string $runDir): ?string
    {
        return self::update($runDir, function (array $s) {
            $text = $s['notice'];
            $s['notice'] = null;
            return [$s, $text];
        });
    }
}
