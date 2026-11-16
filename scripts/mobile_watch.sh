#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/env.sh"
# mobile_watch.sh — контроль мобильной подписки между прогонами (каждые 30 мин).
#
# Зачем: 16.11 клиент показывал «ни один не работает», потому что в gist лежала
# версия двухчасовой давности из 10 мёртвых нод, а обновление происходило только
# дважды в сутки. Теперь живой монитор на малинке (xray-checker, порт 2113) и
# проверка свежести публикации ловят это в течение получаса.
set -uo pipefail

require PI_HOST
PI="${PI_HOST#*@}"
MIN_ALIVE=${MIN_ALIVE:-4}
MIN_FRAC_PCT=${MIN_FRAC_PCT:-40}   # ниже 40% живых — тоже тревога
STATE=$VPN_CACHE/mobile_watch.json
GIST_ID=${GIST_ID:?не задан GIST_ID}
LOCAL=$VPN_OUT/sub-yota/nodes-yota.txt

alert() {
  echo "ALERT: $1"
  notify "⚠️ $1" >/dev/null 2>&1 || true
}

mkdir -p "$(dirname "$STATE")"

# 1. живые ноды глазами малинки (реальное скачивание 12 КБ через каждую ноду)
metrics=$(curl -s --max-time 20 "http://$PI:2113/metrics" || true)
if [ -z "$metrics" ]; then
  alert "Монитор мобильной подписки на малинке не отвечает ($PI:2113)"
  exit 0
fi

read -r total alive <<<"$(printf '%s\n' "$metrics" | python3 -c "
import sys
lat=[int(l.rsplit(' ',1)[1]) for l in sys.stdin if l.startswith('xray_proxy_latency_ms{')]
print(len(lat), sum(1 for v in lat if v>0))")"

# 2. свежесть публикации: клиент видит gist, а не локальный файл
pub=$(curl -s --max-time 20 "https://api.github.com/gists/$GIST_ID" | python3 -c "
import json,sys,datetime
g=json.load(sys.stdin)
c=g['files'].get('yota-nodes.txt',{}).get('content','')
age=(datetime.datetime.utcnow()-datetime.datetime.strptime(g['updated_at'],'%Y-%m-%dT%H:%M:%SZ')).total_seconds()/3600
print(c.count('://'), round(age,1))" 2>/dev/null || echo "0 999")
read -r pub_n pub_age <<<"$pub"
local_n=$(grep -c '://' "$LOCAL" 2>/dev/null || echo 0)

prev=$(cat "$STATE" 2>/dev/null || echo '{}')
python3 - "$STATE" "$total" "$alive" "$pub_n" "$pub_age" "$local_n" <<'PY'
import json, sys
state_f, total, alive, pub_n, pub_age, local_n = sys.argv[1:7]
d = {"total": int(total), "alive": int(alive), "pub_nodes": int(pub_n),
     "pub_age_h": float(pub_age), "local_nodes": int(local_n)}
json.dump(d, open(state_f, "w"), indent=1)
PY

echo "живых $alive из $total | в gist $pub_n нод, возраст ${pub_age} ч | локально $local_n"

frac=$(( total > 0 ? alive * 100 / total : 0 ))
if [ "$alive" -lt "$MIN_ALIVE" ] && [ "$frac" -lt "$MIN_FRAC_PCT" ]; then
  alert "Мобильная подписка: живых $alive из $total (${frac}%, порог $MIN_ALIVE). Прогон: bash ~/bin/refresh_yota.sh"
fi
[ "$pub_age" != "999" ] && [ "$(echo "$pub_age > 8" | bc -l 2>/dev/null || echo 0)" = "1" ] && \
  alert "Мобильная подписка не публиковалась ${pub_age} ч (в gist $pub_n нод). Проверь publish_pub.py"
[ "$pub_n" -ne "$local_n" ] && [ "$local_n" -gt 0 ] && \
  alert "gist ($pub_n нод) расходится с локальной подпиской ($local_n) — публикация не дошла"

exit 0
