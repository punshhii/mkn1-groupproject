#!/bin/bash
# Подготовка и запуск стенда для демо 12.11: настоящие authd, logd, integrityd, filter + web.
# Запуск: sudo tests/stand/demo_stand.sh   (root нужен только для filter)
# Сценарии в другом терминале: python3 tests/stand/demo_scenarios.py
# Пароль admin: Admin_12345
set -e
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
RUN=/tmp/fw
pkill -f run_stand.sh 2>/dev/null || true
rm -rf "$RUN"; mkdir -p "$RUN"
cp etc/default/policy.json "$RUN/policy.json"

# Конфиг стенда: tests/stand/stand_config.json + контролируемый файл для integrityd, проверка раз в 10 с
python3 - <<'EOF'
import json
c = json.load(open('tests/stand/stand_config.json'))
c['integrityd']['files'] = ['/tmp/fw/policy.json']
c['integrityd']['check_period_sec'] = 10
json.dump(c, open('/tmp/fw/config.json', 'w'), ensure_ascii=False, indent=1)
EOF

echo 'Admin_12345' > "$RUN/admin.pw"
PYTHONPATH=common:authd python3 -m fw_authd.mkaccounts --output "$RUN/accounts.json" --password-file "$RUN/admin.pw"
PYTHONPATH=common:integrityd python3 -m fw_integrityd baseline --config "$RUN/config.json"

# logd первой: остальные пишут в неё события при старте
exec tests/stand/run_stand.sh --real logd,authd,integrityd,filter \
    --config "$RUN/config.json" --filter-config tests/stand/stand_config.json --web 8080
