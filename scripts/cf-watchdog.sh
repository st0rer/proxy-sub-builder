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
SOCKS_PORT="${SINGBOX_SOCKS_PORT:-11091}"

# Приоритет пула по умолчанию (если селектор пуст)
DEFAULT_POOL="${SINGBOX_GCP_POOL:-hyst-9 hyst-3 hyst-10 hyst-6}"

Z1_HOST="${Z1_HOST:-192.168.1.200}"
Z1_WINPY="${Z1_WINPY:-$HOME/.hermes/venvs/z1win/bin/python}"
Z1_WINRUN="${Z1_WINRUN:-$HOME/.hermes/skills/mlops/inference/z1x-mini-hermes/scripts/z1win_any.py}"

mkdir -p "$LOG_DIR"
log() { echo "[$(date -u +%F' '%T)UTC] $*" >> "$LOG"; }

# туннель до clash_api. PID держим сами: pgrep -f "<порт>:127.0.0.1" убивал всё,
# в чьей командной строке встречался порт — включая чужие шеллы и замер sb_refresh
PIDFILE="${TMPDIR:-/tmp}/cf-watchdog-tunnel.$API_PORT.pid"
if [ -f "$PIDFILE" ]; then kill "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; rm -f "$PIDFILE"; fi
sshpass -p "$ROUTER_PASS" ssh -N "${SSHOPTS[@]}" -o ExitOnForwardFailure=yes \
    -L "$API_PORT:127.0.0.1:9090" -L "${SOCKS_PORT}:127.0.0.1:1080" "$ROUTER_HOST" >/dev/null 2>&1 &
TUN_PID=$!
echo "$TUN_PID" > "$PIDFILE"
# ждём готовности форварда: фиксированный sleep 1 не всегда хватает (туннель поднимается
# асинхронно), и сторож видел пустой ответ API → «узел не отвечает» → PUT в пустоту
ready=0
for _ in $(seq 1 20); do
    if curl -s -m 2 "$API/proxies/$GCP_SELECTOR" | grep -q '"now"'; then ready=1; break; fi
    sleep 0.5
done
if [ "$ready" != "1" ]; then log "clash_api не отвечает через туннель — пропускаю цикл"; exit 1; fi
close_tunnel() { [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null; rm -f "$PIDFILE" 2>/dev/null; }
trap close_tunnel EXIT

# Точечный сброс залипших видео-соединений YouTube через Clash API
drop_stalled_video_conns() {
    python3 - "$API" <<'PY'
import json, urllib.request, time, sys

API = sys.argv[1]

def get_conns():
    try:
        req = urllib.request.Request(f"{API}/connections")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read().decode()).get("connections", [])
    except Exception:
        return []

def is_video(c):
    host = (c.get("metadata", {}).get("host") or "").lower()
    return "googlevideo.com" in host or "youtube.com" in host

c0 = {c["id"]: c.get("download", 0) for c in get_conns() if is_video(c)}
if not c0:
    sys.exit(0)

time.sleep(2)

c1 = {c["id"]: (c.get("download", 0), c.get("metadata", {}).get("host", "")) for c in get_conns() if is_video(c)}

for cid, (dl1, host) in c1.items():
    if cid in c0:
        dl0 = c0[cid]
        if dl1 == dl0:
            try:
                del_req = urllib.request.Request(f"{API}/connections/{cid}", method="DELETE")
                with urllib.request.urlopen(del_req, timeout=2):
                    pass
                print(f"сброшено залипшее видео-соединение: {cid[:8]} ({host})")
            except Exception:
                pass
PY
}

# 1. Проверяем и точечно сбрасываем залипшие соединения YouTube
drop_stalled_video_conns 2>/dev/null | while IFS= read -r line; do
    [ -n "$line" ] && log "$line"
done

meta=$(curl -s -m 5 "$API/proxies/$GCP_SELECTOR" \
       | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    now = d.get("now", "")
    all_nodes = [x for x in d.get("all", []) if x not in ("cf", "auto", "direct")]
    print(now + "|" + " ".join(all_nodes))
except Exception:
    print("|")' 2>/dev/null)

now="${meta%%|*}"
pool_str="${meta#*|}"
if [ -n "$pool_str" ]; then
    read -r -a POOL <<< "$pool_str"
else
    read -r -a POOL <<< "$DEFAULT_POOL"
fi

# Гейт Google глазами клиента: 401 на loadCodeAssist (ждёт токен) и 200 на gemini.google.com/app.
# 403 = IP забанен целиком (типично для хостинговых подсетей), 400 = геоблок локации.
gate_probe() {  # $1 = тег; печатает "lca gemini"
    local lca g
    lca=$(curl -s -o /dev/null -w '%{http_code}' -m 8 -X POST -H 'Content-Type: application/json' \
          -d '{}' --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
          https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist 2>/dev/null)
    g=$(curl -s -o /dev/null -w '%{http_code}' -m 8 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
        https://gemini.google.com/app 2>/dev/null)
    echo "${lca:-000} ${g:-000}"
}

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

# гейт проверяем всегда: узел может быть жив по задержке и при этом забанен Google
read -r glca ggem <<< "$(gate_probe "$now")"
gate_ok=0
case "${glca:-000}" in
    401|200) [ "${ggem:-000}" = "200" ] && gate_ok=1 ;;
esac
if [ "$gate_ok" = "0" ]; then
    broken=1
    log "гейт через $now: loadCodeAssist $glca, gemini $ggem — ротация"
fi

if [ "$broken" = "0" ]; then
    d=$(delay_of "$now")
    if [ -n "${d:-}" ] && [ "${d:-0}" != "0" ]; then
        log "ок: $now жив (${d}ms), гейт $glca/$ggem, новых ошибок нет"
        exit 0
    fi
    log "текущий узел $now не отвечает (${d:-?}) — ротация"
fi

pick=""; pick_ms=""
for n in "${POOL[@]}"; do
    [ "$n" = "$now" ] && continue
    d=$(delay_of "$n")
    [ -n "${d:-}" ] && [ "${d:-0}" != "0" ] || continue
    # гейт можно померить только с самого узла, поэтому сначала переключаем на него
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X PUT \
           -H 'Content-Type: application/json' -d "{\"name\":\"$n\"}" "$API/proxies/$GCP_SELECTOR")
    [ "$code" = "204" ] || { log "  $n: переключение HTTP $code — пропускаю"; continue; }
    sleep 0.4
    read -r clca cgem <<< "$(gate_probe "$n")"
    case "${clca:-000}" in
        401|200) if [ "${cgem:-000}" = "200" ]; then pick="$n"; pick_ms="$d"; break; fi
                 log "  $n: жив, но гейт $clca/$cgem — пропускаю" ;;
        *) log "  $n: жив, но гейт $clca/$cgem — пропускаю" ;;
    esac
done

if [ -z "$pick" ]; then
    # откат: ни один кандидат гейт не прошёл — возвращаем прежний узел
    curl -s -o /dev/null -m 5 -X PUT -H 'Content-Type: application/json' \
         -d "{\"name\":\"$now\"}" "$API/proxies/$GCP_SELECTOR"
    log "нет узлов с проходящим гейтом — оставляю $now"
    exit 1
fi
if true; then
    log "$GCP_SELECTOR -> $pick (${pick_ms}ms, гейт ${clca}/${cgem}, было $now)"
else
    log "не смог $GCP_SELECTOR -> $pick: HTTP $code"
fi
