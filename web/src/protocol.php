<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      protocol
 * Назначение:  клиент протокола подсистем по Unix-сокету (AF_UNIX / SOCK_STREAM),
 *              как common/fwcommon/protocol.py: JSON-конверт по common/PROTOCOL.md,
 *              одно сообщение на строку; тайм-аут ответа 5 с, до 2 повторов с тем
 *              же msg_id; status=error -> FwProtocolError с кодом M01..M16;
 *              ответа нет после повторов -> FwProtocolError("M16").
 * Методы:
 *   - FwProtocolError — ошибка ответа подсистемы (code — код из messages.json)
 *   - FwProtocol::nowIso — метка времени ISO 8601 с миллисекундами, суффикс Z
 *   - FwProtocol::newId — новый msg_id (счётчик со случайным началом)
 *   - FwProtocol::makeMsg — собрать конверт сообщения
 *   - FwProtocol::validateEnvelope — проверить конверт (нарушение — InvalidArgumentException)
 *   - FwProtocol::encodeLine — сообщение -> строка JSON с \n
 *   - FwProtocol::exchange — одно соединение: запрос и ожидание ответа по reply_to
 *   - FwProtocol::request — запрос с тайм-аутом и повторами (M16)
 *   - FwProtocol::sendEvent — отправить событие (type=event), ответа не ждать
 *   - FwProtocol::monotonic — монотонное время, секунд (для тайм-аутов)
 *   - FwProtocol::messageText — текст сообщения по коду из common/messages.json
 */

declare(strict_types=1);

final class FwProtocolError extends RuntimeException
{
    /** Код сообщения из common/messages.json, например M16. */
    public string $fwCode;
    public string $fwMessage;

    public function __construct(string $code, string $message = '')
    {
        parent::__construct($code . ': ' . $message);
        $this->fwCode = $code;
        $this->fwMessage = $message;
    }
}

final class FwProtocol
{
    public const TIMEOUT_SEC = 5.0;   // PROTOCOL.md: тайм-аут ответа, секунд
    public const RETRIES = 2;         // PROTOCOL.md: до 2 повторов с тем же msg_id
    public const MSG_TYPES = ['request', 'response', 'event'];
    public const SOURCES = ['cli', 'web', 'filter', 'logd', 'authd', 'integrityd', 'os'];
    public const MAX_STRING = 255;    // строки UTF-8 до 255 символов
    public const MAX_LINE = 65536;    // защитный предел длины строки ответа, байт

    private const TS_RE = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/';
    private const CMD_RE = '/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/';

    private static ?int $nextId = null;
    private static ?array $messages = null;

    /** Путь к common/messages.json (можно переопределить при установке). */
    public static string $messagesPath = __DIR__ . '/../../common/messages.json';

    public static function nowIso(): string
    {
        $t = DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', microtime(true)));
        return $t->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v') . 'Z';
    }

    /**
     * Случайное начало счётчика: msg_id разных процессов (сеансы web, CLI) не
     * совпадают, и сервер не вернёт одному клиенту кэшированный ответ другому.
     */
    public static function newId(): int
    {
        if (self::$nextId === null) {
            self::$nextId = random_int(0, 0xFFFFFFFF) << 20;
        }
        return self::$nextId++;
    }

    /**
     * Собрать конверт. payload — ассоциативный массив; пустой payload
     * передаётся как JSON-объект {}.
     */
    public static function makeMsg(string $type, string $src, string $dst, ?string $cmd = null,
                                   array $payload = [], ?int $replyTo = null,
                                   ?int $msgId = null, array $extra = []): array
    {
        return array_merge([
            'msg_id' => $msgId ?? self::newId(),
            'type' => $type,
            'src' => $src,
            'dst' => $dst,
            'cmd' => $cmd,
            'ts' => self::nowIso(),
            'payload' => $payload,
            'reply_to' => $replyTo,
        ], $extra);
    }

    private static function strLen(string $s): int
    {
        $n = preg_match_all('/./su', $s);
        if ($n === false) {
            throw new InvalidArgumentException('строка не в кодировке UTF-8');
        }
        return $n;
    }

    private static function isObject($v): bool
    {
        return is_array($v) && ($v === [] || !array_is_list($v));
    }

    /** Проверить конверт по PROTOCOL.md; нарушение — InvalidArgumentException с именем поля. */
    public static function validateEnvelope($msg): array
    {
        if (!self::isObject($msg)) {
            throw new InvalidArgumentException('сообщение должно быть объектом');
        }
        $mid = $msg['msg_id'] ?? null;
        if (!is_int($mid) || $mid < 0) {
            throw new InvalidArgumentException('msg_id');
        }
        if (!in_array($msg['type'] ?? null, self::MSG_TYPES, true)) {
            throw new InvalidArgumentException('type');
        }
        foreach (['src', 'dst'] as $f) {
            if (!in_array($msg[$f] ?? null, self::SOURCES, true)) {
                throw new InvalidArgumentException($f);
            }
        }
        $cmd = $msg['cmd'] ?? null;
        if ($cmd === null) {
            if ($msg['type'] !== 'response') {
                throw new InvalidArgumentException('cmd обязателен для ' . $msg['type']);
            }
        } elseif (!is_string($cmd) || self::strLen($cmd) > self::MAX_STRING
                  || !preg_match(self::CMD_RE, $cmd)) {
            throw new InvalidArgumentException('cmd');
        }
        if (!is_string($msg['ts'] ?? null) || !preg_match(self::TS_RE, $msg['ts'])) {
            throw new InvalidArgumentException('ts');
        }
        if (!self::isObject($msg['payload'] ?? null)) {
            throw new InvalidArgumentException('payload');
        }
        $rt = $msg['reply_to'] ?? null;
        if ($rt !== null && !is_int($rt)) {
            throw new InvalidArgumentException('reply_to');
        }
        if ($msg['type'] === 'response') {
            if ($rt === null) {
                throw new InvalidArgumentException('response: reply_to обязателен');
            }
            $st = $msg['status'] ?? null;
            if ($st !== 'ok' && $st !== 'error') {
                throw new InvalidArgumentException('status');
            }
            if ($st === 'error' && (!is_string($msg['error_code'] ?? null)
                                    || !is_string($msg['error_message'] ?? null))) {
                throw new InvalidArgumentException('error_code');
            }
        }
        return $msg;
    }

    /** Сообщение -> строка UTF-8 с \n; пустой payload кодируется как {}. */
    public static function encodeLine(array $msg): string
    {
        if (($msg['payload'] ?? null) === []) {
            $msg['payload'] = new stdClass();
        }
        return json_encode($msg, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
                                 | JSON_THROW_ON_ERROR) . "\n";
    }

    /**
     * Одно соединение: отправить сообщение и дождаться response с reply_to == msg_id
     * за $timeout секунд. События и чужие ответы пропускаются. Нет ответа,
     * закрытое соединение, некорректный ответ — RuntimeException (будет повтор).
     */
    public static function exchange(string $path, array $msg, float $timeout): array
    {
        self::validateEnvelope($msg);
        // монотонные часы: перевод системного времени не влияет на тайм-аут
        $deadline = self::monotonic() + $timeout;
        $errno = 0;
        $errstr = '';
        $s = @stream_socket_client('unix://' . $path, $errno, $errstr, $timeout);
        if ($s === false) {
            throw new RuntimeException("нет соединения с $path: $errstr");
        }
        try {
            $line = self::encodeLine($msg);
            for ($off = 0; $off < strlen($line);) {
                $n = @fwrite($s, substr($line, $off));
                if ($n === false || $n === 0) {
                    throw new RuntimeException('ошибка отправки');
                }
                $off += $n;
            }
            // чтение без блокировки: буфер PHP-потока не скрывает данные от stream_select
            stream_set_blocking($s, false);
            $buf = '';
            while (true) {
                $left = $deadline - self::monotonic();
                if ($left <= 0) {
                    throw new RuntimeException('тайм-аут ответа');
                }
                $r = [$s];
                $w = $e = null;
                $ready = @stream_select($r, $w, $e, (int)$left, (int)(($left - (int)$left) * 1e6));
                if ($ready === false) {
                    throw new RuntimeException('ошибка ожидания ответа');
                }
                if ($ready === 0) {
                    continue;
                }
                $chunk = fread($s, 65536);
                if ($chunk === false || ($chunk === '' && feof($s))) {
                    throw new RuntimeException('соединение закрыто без ответа');
                }
                if ($chunk === '') {
                    continue;
                }
                $buf .= $chunk;
                while (($nl = strpos($buf, "\n")) !== false) {
                    $raw = substr($buf, 0, $nl);
                    $buf = substr($buf, $nl + 1);
                    if (trim($raw) === '') {
                        continue;
                    }
                    $m = json_decode($raw, true, 64, JSON_BIGINT_AS_STRING);
                    if (!is_array($m)) {
                        throw new RuntimeException('некорректная строка ответа');
                    }
                    if (($m['type'] ?? null) === 'event') {
                        continue; // события подтверждения не требуют
                    }
                    try {
                        self::validateEnvelope($m);
                    } catch (InvalidArgumentException $ex) {
                        throw new RuntimeException('некорректный ответ подсистемы: ' . $ex->getMessage());
                    }
                    if ($m['type'] === 'response' && $m['reply_to'] === $msg['msg_id']) {
                        return $m;
                    }
                }
                if (strlen($buf) > self::MAX_LINE) {
                    throw new RuntimeException('строка ответа длиннее ' . self::MAX_LINE . ' байт');
                }
            }
        } finally {
            fclose($s);
        }
    }

    /**
     * Запрос подсистеме. До $retries повторов с тем же msg_id: получатель
     * по (src, msg_id) вернёт прежний ответ и не выполнит команду повторно.
     * status=error -> FwProtocolError(error_code); ответа нет -> FwProtocolError("M16"),
     * вызывающий регистрирует неуспешное событие (FR-28). Успех — конверт ответа.
     */
    public static function request(string $path, string $src, string $dst, string $cmd,
                                   array $payload = [], float $timeout = self::TIMEOUT_SEC,
                                   int $retries = self::RETRIES): array
    {
        $msg = self::makeMsg('request', $src, $dst, $cmd, $payload);
        $last = '';
        for ($i = 0; $i <= $retries; $i++) {
            try {
                $resp = self::exchange($path, $msg, $timeout);
            } catch (RuntimeException | InvalidArgumentException | JsonException $e) {
                $last = $e->getMessage();
                continue;
            }
            if ($resp['status'] === 'error') {
                throw new FwProtocolError($resp['error_code'] ?: 'M14', $resp['error_message'] ?? '');
            }
            return $resp;
        }
        throw new FwProtocolError('M16', self::messageText('M16', ['name' => $dst]) . " ($last)");
    }

    /** Событие (log.write.event); подтверждения нет. Ошибка соединения — RuntimeException. */
    public static function sendEvent(string $path, string $src, string $dst, string $cmd,
                                     array $payload = [], float $timeout = self::TIMEOUT_SEC): array
    {
        $msg = self::validateEnvelope(self::makeMsg('event', $src, $dst, $cmd, $payload));
        $s = @stream_socket_client('unix://' . $path, $errno, $errstr, $timeout);
        if ($s === false) {
            throw new RuntimeException("нет соединения с $path: $errstr");
        }
        try {
            fwrite($s, self::encodeLine($msg));
        } finally {
            fclose($s);
        }
        return $msg;
    }

    /** Монотонное время в секундах (не зависит от перевода системных часов). */
    public static function monotonic(): float
    {
        return hrtime(true) / 1e9;
    }

    /** Текст сообщения по коду; подстановки {name} из $kw. */
    public static function messageText(string $code, array $kw = []): string
    {
        if (self::$messages === null) {
            $raw = @file_get_contents(self::$messagesPath);
            self::$messages = is_string($raw) ? (json_decode($raw, true) ?: []) : [];
        }
        $text = self::$messages[$code] ?? $code;
        foreach ($kw as $k => $v) {
            $text = str_replace('{' . $k . '}', (string)$v, $text);
        }
        return $text;
    }
}
