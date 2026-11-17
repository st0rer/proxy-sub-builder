#!/bin/bash
# Сторож для sing-box на роутере Тургенева.
#
# Держит выбранным узлом свою Cloudflare-ноду (tag cf) в селекторе gcp, через который идут
# только Google-домены: Google принимает выход CF, а датацентровые IP free-нод помечает
# как «страна не поддерживается». Если CF недоступна — gcp уходит на пул free-нод (auto).
# Частота 15 мин: каждый probe через cf — это +1 запрос к Worker (лимит 100k/сутки).
#
# Запуск по cron; состояние — в логе.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env.sh
. "$DIR/lib/env.sh"

ROUTER_HOST="${ROUTER_HOST:-root@192.168.1.1}"
ROUTER_PASS="${ROUTER_PASS:-}"
if [ -z "$ROUTER_PASS" ] && [ -f "$VPN_SECRETS/router_pass" ]; then
    ROUTER_PASS=$(tr -d '\r\n ' < "$VPN_SECRETS/router_pass")
fi
require ROUTER_PASS

SSHOPTS=(-o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=8)
API="http://127.0.0.1:${CLASH_API_PORT:-19090}"
LOG_DIR="${SINGBOX_LOG_DIR:-$PROXY_SUB_HOME/logs}"
LOG="$LOG_DIR/cf-watchdog.log"
PROBE_URL="${SINGBOX_PROBE_URL:-https://www.gstatic.com/generate_204}"
CF_TAG="${SINGBOX_CF_TAG:-cf}"
GCP_SELECTOR="${SINGBOX_GCP_SELECTOR:-gcp}"
mkdir -p "$LOG_DIR"

log() { echo "[$(date -u +%F' '%T)UTC] $*" >> "$LOG"; }

# туннель до clash_api (убираем прежний, чтобы не копились)
for pid in $(pgrep -f '19090:127.0.0.1'); do kill "$pid" 2>/dev/null; done
if ! sshpass -p "$PW" ssh -f -N "${SSHOPTS[@]}" -o ExitOnForwardFailure=yes \
        -L 19090:127.0.0.1:9090 "$ROUTER_HOST" 2>/dev/null; then
    log "нет доступа к роутеру"
    exit 1
fi
sleep 1

now=$(curl -s -m 5 "$API/proxies/$GCP_SELECTOR" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("now",""))' 2>/dev/null)
delay=$(curl -s -m 12 "$API/proxies/$CF_TAG/delay?timeout=8000&url=$PROBE_URL" \
        | python3 -c 'import json,sys;print(json.load(sys.stdin).get("delay",0))' 2>/dev/null)

switch() {  # $1 = tag
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X PUT \
           -H 'Content-Type: application/json' -d "{\"name\":\"$1\"}" "$API/proxies/$GCP_SELECTOR")
    [ "$code" = "204" ] && log "gcp -> $1 (было $now)" || log "не смог gcp -> $1: HTTP $code"
}
close_tunnel() { for pid in $(pgrep -f '19090:127.0.0.1'); do kill "$pid" 2>/dev/null; done; }
trap close_tunnel EXIT

if [ -z "${delay:-}" ] || [ "$delay" = "0" ]; then
    if [ "$now" != "auto" ]; then switch auto; else log "cf лежит, уже на auto"; fi
else
    if [ "$now" != "$CF_TAG" ]; then switch "$CF_TAG"; else log "cf жив, ${delay}ms, ничего не менял"; fi
fi
