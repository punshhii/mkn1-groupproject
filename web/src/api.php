<?php
/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-4 WEB
 * Модуль:      api
 * Назначение:  вызовы подсистем от имени web (src = "web"): запросы к ПС-1, ПС-2,
 *              ПС-5, ПС-6, проверка права auth.check, события в ПС-2, интерфейсы
 *              из config.json (is_mgmt) и сеть ОС для раздела «Сеть»: на МЭ —
 *              ip -j и sudo -n с фиксированным списком команд, на стенде —
 *              заглушка «os» (FW_NET=stand), как в ПС-3.
 * Методы:
 *   - FwApi::fromEnv — каталог сокетов FW_RUN_DIR, config.json FW_CONFIG, сеть FW_NET
 *   - FwApi::call — запрос подсистеме -> payload (FwProtocolError M01..M16)
 *   - FwApi::check — auth.check: право сеанса на команду (M03, M15, M16)
 *   - FwApi::event — событие в ПС-2 (log.write.event, без ожидания ответа)
 *   - FwApi::ifaces / mgmt — интерфейсы и управляющие интерфейсы из config.json
 *   - FwApi::links / routes / setAddr / addRoute / delRoute — сеть ОС
 *   - fw_in_subnet — адрес принадлежит сети адрес/маска
 */

declare(strict_types=1);

require_once __DIR__ . '/protocol.php';

function fw_in_subnet(string $addr, string $cidr): bool
{
    [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, '32');
    $a = ip2long($addr);
    $n = ip2long($net);
    if ($a === false || $n === false || !ctype_digit($bits) || (int)$bits > 32) {
        return false;
    }
    $mask = (int)$bits === 0 ? 0 : (~0 << (32 - (int)$bits)) & 0xFFFFFFFF;
    return ($a & $mask) === ($n & $mask);
}

final class FwApi
{
    public const IP = '/usr/sbin/ip';

    public string $runDir;
    private array $config;
    private bool $standNet;

    public function __construct(string $runDir, ?string $configPath = null, bool $standNet = false)
    {
        $this->runDir = rtrim($runDir, '/');
        $raw = @file_get_contents($configPath ?? '/etc/fw/config.json');
        $cfg = is_string($raw) ? json_decode($raw, true) : null;
        $this->config = is_array($cfg) ? $cfg : [];
        $this->standNet = $standNet;
    }

    public static function fromEnv(): self
    {
        $run = getenv('FW_RUN_DIR') ?: '/run/fw';
        $cfg = getenv('FW_CONFIG') ?: (is_file("$run/config.json") ? "$run/config.json" : null);
        return new self($run, $cfg ?: null, getenv('FW_NET') === 'stand');
    }

    public function path(string $name): string
    {
        return "{$this->runDir}/$name.sock";
    }

    public function call(string $dst, string $cmd, array $payload = []): array
    {
        $r = FwProtocol::request($this->path($dst), 'web', $dst, $cmd, $payload);
        return is_array($r['payload'] ?? null) ? $r['payload'] : [];
    }

    /** auth.check {session_id, cmd}: ответ без allowed=true — отказ M03. */
    public function check(string $sid, string $cmdName): void
    {
        $p = $this->call('authd', 'auth.check', ['session_id' => $sid, 'cmd' => $cmdName]);
        if (($p['allowed'] ?? null) !== true) {
            throw new FwProtocolError('M03', FwProtocol::messageText('M03'));
        }
    }

    /** Событие FR-25: код, администратор, IP, результат, имя команды. */
    public function event(string $code, array $s, string $cmdName, string $result = 'ok',
                          array $details = []): void
    {
        $rec = array_merge(['code' => $code, 'actor' => $s['username'], 'source' => 'web',
                            'ip' => $s['ip'], 'result' => $result, 'cmd' => $cmdName], $details);
        try {
            FwProtocol::sendEvent($this->path('logd'), 'web', 'logd', 'log.write.event', $rec);
        } catch (Throwable $e) {
            // ПС-2 недоступна: событие теряется, действие уже выполнено
        }
    }

    /** Имена интерфейсов из config.json (порядок — индексы ПС-1). */
    public function ifaces(): array
    {
        $out = [];
        foreach ($this->config['ifaces'] ?? [] as $i) {
            if (is_array($i) && is_string($i['name'] ?? null)) {
                $out[] = $i['name'];
            }
        }
        return $out;
    }

    /** Управляющие интерфейсы: is_mgmt в config.json (iface_config_t, ТЗ). */
    public function mgmt(): array
    {
        $out = [];
        foreach ($this->config['ifaces'] ?? [] as $i) {
            if (is_array($i) && is_string($i['name'] ?? null) && !empty($i['is_mgmt'])) {
                $out[] = $i['name'];
            }
        }
        return $out;
    }

    private function ip(array $args, bool $sudo): string
    {
        $cmd = ($sudo ? 'sudo -n ' : '') . self::IP . ' ' . implode(' ', array_map('escapeshellarg', $args));
        $out = [];
        $rc = 0;
        exec($cmd . ' 2>&1', $out, $rc);
        if ($rc !== 0) {
            throw new FwProtocolError('M16', FwProtocol::messageText('M16', ['name' => 'ОС'])
                                     . ' (' . implode(' ', $out) . ')');
        }
        return implode("\n", $out);
    }

    private function os(string $cmd, array $payload = []): array
    {
        try {
            return $this->call('os', $cmd, $payload);
        } catch (FwProtocolError $e) {
            throw new FwProtocolError('M16', FwProtocol::messageText('M16', ['name' => 'ОС'])
                                     . ' (' . $e->fwMessage . ')');
        }
    }

    /** [{name, state, addr, mac, rx_bytes, tx_bytes}] — addr: a.b.c.d/nn или null. */
    public function links(): array
    {
        if ($this->standNet) {
            return $this->os('if.list')['ifaces'] ?? [];
        }
        $out = [];
        foreach (json_decode($this->ip(['-j', '-s', 'addr', 'show'], false), true) ?: [] as $i) {
            $v4 = array_values(array_filter($i['addr_info'] ?? [], fn($a) => ($a['family'] ?? '') === 'inet'));
            $st = $i['stats64'] ?? $i['stats'] ?? [];
            $out[] = ['name' => $i['ifname'] ?? null,
                      'state' => in_array('UP', $i['flags'] ?? [], true) ? 'up' : 'down',
                      'addr' => $v4 ? $v4[0]['local'] . '/' . $v4[0]['prefixlen'] : null,
                      'mac' => $i['address'] ?? null,
                      'rx_bytes' => $st['rx']['bytes'] ?? null, 'tx_bytes' => $st['tx']['bytes'] ?? null];
        }
        return $out;
    }

    /** [{dst, gw, dev}]. */
    public function routes(): array
    {
        if ($this->standNet) {
            return $this->os('route.list')['routes'] ?? [];
        }
        return array_map(fn($r) => ['dst' => $r['dst'] ?? null, 'gw' => $r['gateway'] ?? null,
                                    'dev' => $r['dev'] ?? null],
                         json_decode($this->ip(['-j', 'route', 'show'], false), true) ?: []);
    }

    public function setAddr(string $name, string $cidr): void
    {
        if ($this->standNet) {
            $this->os('if.ip', ['name' => $name, 'addr' => $cidr]);
            return;
        }
        $this->ip(['addr', 'flush', 'dev', $name], true);
        $this->ip(['addr', 'add', $cidr, 'dev', $name], true);
    }

    public function addRoute(string $net, string $gw, string $dev): void
    {
        if ($this->standNet) {
            $this->os('route.add', ['dst' => $net, 'gw' => $gw, 'dev' => $dev]);
            return;
        }
        $this->ip(['route', 'add', $net, 'via', $gw, 'dev', $dev], true);
    }

    public function delRoute(string $net): void
    {
        if ($this->standNet) {
            $this->os('route.del', ['dst' => $net]);
            return;
        }
        $this->ip(['route', 'del', $net], true);
    }
}
