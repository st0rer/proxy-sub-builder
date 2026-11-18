#!/bin/bash
# Сторож Google-выхода для Antigravity IDE на мини-ПК Z1 (Windows).
#
# Зачем: language_server ходит на daily-cloudcode-pa.googleapis.com и aicode.googleapis.com.
# Google отдаёт 403 LOCATION_NOT_ELIGIBLE («Your location is not eligible… Detected location: XX»)
# и 400 FAILED_PRECONDITION («User location is not supported for the API use»), если ему не
# нравится страна выхода. Вердикт зависит от страны выхода, а не от страны аккаунта: смена
# outbound меняет код страны в ответе.
#
# История: до 18.11.2026 скрипт принудительно держал селектор gcp на своей CF-ноде (tag cf),
# исходя из того, что «Google принимает выход CF». Проверено фактами 18.11.2026 — путь через
# Cloudflare Workers гейт НЕ проходит ни в одном из вариантов:
#   1) дефолтный релей воркера ({colo}.proxyip.cmliussss.net; сеть резолвится в т.ч. в proxyip.ru…,
#      egress плавает HK → DE → SE → RU);
#   2) пин ?proxyip=<host> в WS-пути — воркер его игнорирует;
#   3) привязка env.PROXYIP — применяется, egress стабилизируется (например, SE), вердикт всё равно RU;
#   4) выбор ingress-colo входным CF-IP (104.16.0.1 → ARN, Стокгольм) — egress SE, вердикт RU.
#   Заголовки при этом чистые (httpbin: только Accept/Host/User-Agent, XFF и CF-Connecting-IP
#   не текут). Значит режется сам факт прохождения через Workers, а не страна релея.
# Поэтому cf из кандидатов исключён: рабочая нода — вне Cloudflare.
#
# Логика: читаем НОВЫЕ строки геоблока в логе language_server на Z1 (по WinRM) и сравниваем со
# счётчиком в state-файле. Появились (или gcp стоит на cf) — ротируем селектор на первый живой
# узел пула. Смена селектора не рвёт уже открытые соединения, поэтому после ротации IDE может
# ещё минуту показывать старое — нужен рестарт language_server (taskkill /F /IM language_server.exe;
# Stop-Process иногда молча не срабатывает).
#
# Переопределяется окружением: ROUTER_HOST, ROUTER_PASS, CLASH_API_PORT, SINGBOX_LOG_DIR,
# SINGBOX_GCP_SELECTOR, SINGBOX_GCP_POOL, Z1_HOST, Z1_WINPY, Z1_WINRUN.
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
API_PORT="${CLASH_API_PORT:-19090}"
API="http://127.0.0.1:$API_PORT"
LOG_DIR="${SINGBOX_LOG_DIR:-$PROXY_SUB_HOME/logs}"
LOG="$LOG_DIR/cf-watchdog.log"
STATE="$LOG_DIR/cf-watchdog.state"
PROBE_URL="${SINGBOX_PROBE_URL:-https://www.gstatic.com/generate_204}"
GCP_SELECTOR="${SINGBOX_GCP_SELECTOR:-gcp}"

# Приоритет пула: DE → FR → SG → US. cf сюда не входит (см. шапку).
read -r -a POOL <<< "${SINGBOX_GCP_POOL:-hyst-9 hyst-3 hyst-10 hyst-6}"

Z1_HOST="${Z1_HOST:-192.168.1.200}"
Z1_WINPY="${Z1_WINPY:-$HOME/.hermes/venvs/z1win/bin/python}"
Z1_WINRUN="${Z1_WINRUN:-$HOME/.hermes/skills/mlops/inference/z1x-mini-hermes/scripts/z1win_any.py}"

mkdir -p "$LOG_DIR"
log() { echo "[$(date -u +%F' '%T)UTC] $*" >> "$LOG"; }

# туннель до clash_api (убираем прежний, чтобы не копились)
for pid in $(pgrep -f "$API_PORT:127.0.0.1"); do kill "$pid" 2>/dev/null; done
if ! sshpass -p "$ROUTER_PASS" ssh -f -N "${SSHOPTS[@]}" -o ExitOnForwardFailure=yes \
        -L "$API_PORT:127.0.0.1:9090" "$ROUTER_HOST" 2>/dev/null; then
    log "нет доступа к роутеру"
    exit 1
fi
sleep 1
close_tunnel() { for pid in $(pgrep -f "$API_PORT:127.0.0.1"); do kill "$pid" 2>/dev/null; done; }
trap close_tunnel EXIT

now=$(curl -s -m 5 "$API/proxies/$GCP_SELECTOR" \
      | python3 -c 'import json,sys;print(json.load(sys.stdin).get("now",""))' 2>/dev/null)

delay_of() {  # $1 = tag → ms, 0 если молчит
    curl -s -m 12 "$API/proxies/$1/delay?timeout=8000&url=$PROBE_URL" \
        | python3 -c 'import json,sys;print(json.load(sys.stdin).get("delay",0))' 2>/dev/null
}

# --- здоровье IDE: новые строки геоблока в логе language_server (через WinRM) ---
probe_ide() {
    local ps
    ps='$f=Join-Path $env:APPDATA "Antigravity\logs\language_server.log"; if(Test-Path $f){$a=Get-Content $f; $g=($a|Select-String -Pattern "location is not supported|Detected location").Count; "$($a.Count) $g"} else {"0 0"}'
    Z1HOST="$Z1_HOST" timeout 90 "$Z1_WINPY" "$Z1_WINRUN" "$ps" 2>/dev/null \
        | tr -d '\r' | grep -E '^[0-9]+ [0-9]+$' | tail -1
}

cur=$(probe_ide || true)
broken=0
if [ -n "${cur:-}" ]; then
    read -r total geo <<< "$cur"
    if [ -f "$STATE" ]; then
        read -r pt pg < "$STATE" || { pt=0; pg=0; }
        # лог пересоздан после рестарта LS — счётчики сбрасываем
        if [ "$total" -lt "${pt:-0}" ]; then pt=$total; pg=$geo; fi
        if [ "${geo:-0}" -gt "${pg:-0}" ]; then
            broken=1
            log "новые ошибки геоблока: было $pg, стало $geo (строк $total)"
        fi
    fi
    echo "$total $geo" > "$STATE"
else
    log "не смог прочитать лог IDE (WinRM), работаю по состоянию селектора"
fi

# cf для этого гейта не годится всегда — уводим даже без ошибок в логе
if [ "$now" = "cf" ]; then broken=1; log "$GCP_SELECTOR стоит на cf — уводим"; fi

if [ "$broken" = "0" ]; then
    d=$(delay_of "$now")
    if [ -n "${d:-}" ] && [ "${d:-0}" != "0" ]; then
        log "ок: $now жив (${d}ms), новых ошибок нет"
        exit 0
    fi
    log "текущий узел $now не отвечает (${d:-?}) — ротация"
fi

pick=""; pick_ms=""
for n in "${POOL[@]}"; do
    [ "$n" = "$now" ] && continue
    d=$(delay_of "$n")
    if [ -n "${d:-}" ] && [ "${d:-0}" != "0" ]; then pick="$n"; pick_ms="$d"; break; fi
done

if [ -z "$pick" ]; then
    log "нет живых узлов в пуле — оставляю $now"
    exit 1
fi

code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X PUT \
       -H 'Content-Type: application/json' -d "{\"name\":\"$pick\"}" "$API/proxies/$GCP_SELECTOR")
if [ "$code" = "204" ]; then
    log "$GCP_SELECTOR -> $pick (${pick_ms}ms, было $now)"
else
    log "не смог $GCP_SELECTOR -> $pick: HTTP $code"
fi
