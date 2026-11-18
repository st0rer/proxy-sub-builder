#!/bin/bash
# Обновление sing-box на роутере Тургенева из подписки st0rer/proxy-sub.
#
# Две фазы:
#   1) публикуем полный конфиг, замеряем страну выхода каждой ноды (clash_api + socks)
#   2) публикуем конфиг без нод с российским выходом (Google/Gemini отдают геоблок)
#
# Рабочий конфиг не подменяется, пока новый не прошёл sing-box check.
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

GEN="${SINGBOX_GEN:-$DIR/sbgen.py}"
SCRATCH="${SINGBOX_SCRATCH:-$PROXY_SUB_HOME/scratch}"
SRC="$SCRATCH/ps_nodes.txt"
CFG="$SCRATCH/sb-config.json"
GEO="$SCRATCH/sb-geo.json"
FULL="$SCRATCH/sb-full.json"
export SINGBOX_CONFIG="$CFG"   # sbgen по умолчанию пишет /tmp — привязываем к CFG
EXCLUDE_CC="${SINGBOX_EXCLUDE_CC:-RU}"
REMOTE_CFG="${SINGBOX_REMOTE_CONFIG:-/etc/sing-box/config.json}"
LOG_DIR="${SINGBOX_LOG_DIR:-$PROXY_SUB_HOME}"
SSHOPTS=(-o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=10)
SSH() { sshpass -p "$ROUTER_PASS" ssh "${SSHOPTS[@]}" "$ROUTER_HOST" "$@"; }
SCP() { sshpass -p "$ROUTER_PASS" scp -O "${SSHOPTS[@]}" "$@"; }
mkdir -p "$SCRATCH"

log() { echo "[$(date -u +%F' '%T)UTC] $*"; }

deploy() {  # $1 = файл конфига; валидация до подмены
    SCP "$1" "$ROUTER_HOST:/tmp/sb-config.new.json" >/dev/null 2>&1 || { log "SCP FAILED"; return 1; }
    if ! SSH 'sing-box check -c /tmp/sb-config.new.json' >/dev/null 2>&1; then
        log "CHECK FAILED — оставляю прежний конфиг"
        return 1
    fi
    SSH 'mv /tmp/sb-config.new.json "$REMOTE_CFG"
         /etc/init.d/sing-box restart >/dev/null 2>&1
         sleep 45
         ip route replace default dev sb0 table pbr_sbtun 2>/dev/null'
    return 0
}

close_tunnel() {
    python3 - <<'PY'
import os, signal
for pid in os.listdir('/proc'):
    if not pid.isdigit():
        continue
    try:
        cl = open(f'/proc/{pid}/cmdline', 'rb').read().decode(errors='ignore')
    except Exception:
        continue
    if '11080:127.0.0.1' in cl and 'ssh' in cl:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except Exception:
            pass
PY
}

log "refresh start"

# фильтрованная подписка (base64); nodes.txt — резерв, содержимое идентично
curl -sf -m 60 -o "$SRC" https://raw.githubusercontent.com/st0rer/proxy-sub/main/v2ray.txt \
    || curl -sf -m 60 -o "$SRC" https://raw.githubusercontent.com/st0rer/proxy-sub/main/nodes.txt \
    || { log "FETCH FAILED"; exit 1; }
[ -s "$SRC" ] || { log "EMPTY LIST"; exit 1; }

# --- фаза 1: полный конфиг как измерительный стенд ---
python3 "$GEN" || { log "GENERATE FAILED"; exit 1; }
cp "$CFG" "$FULL"
deploy /tmp/sb-full.json || exit 1

# --- замер страны выхода каждой ноды ---
log "measuring exit country per node"
close_tunnel   # на случай, если остался туннель от предыдущего запуска
sshpass -p "$ROUTER_PASS" ssh -f -N "${SSHOPTS[@]}" -o ExitOnForwardFailure=yes \
    -L 11080:127.0.0.1:1080 -L 19090:127.0.0.1:9090 "$ROUTER_HOST" || { log "TUNNEL FAILED"; exit 1; }
sleep 3

SINGBOX_FULL="$FULL" python3 - "$GEO" <<'PY'
import json, os, subprocess, sys

geo_path = sys.argv[1]
cfg = json.load(open(os.environ['SINGBOX_FULL']))
nodes = [o for o in cfg['outbounds'] if o.get('server')]
geo = {}
for n in nodes:
    tag = n['tag']
    key = f"{n['type']}|{n['server']}|{n['server_port']}"
    sw = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-m', '5', '-X', 'PUT',
                         '-H', 'Content-Type: application/json', '-d', json.dumps({'name': tag}),
                         'http://127.0.0.1:19090/proxies/proxy'],
                        capture_output=True, text=True).stdout.strip()
    if sw != '204':
        geo[key] = {'cc': '', 'err': 'switch'}
        continue
    body = subprocess.run(['curl', '-s', '-m', '10', '--socks5-hostname', '127.0.0.1:11080',
                           'http://ip-api.com/json/?fields=status,countryCode,isp,query'],
                          capture_output=True, text=True).stdout
    try:
        d = json.loads(body)
        geo[key] = {'cc': (d.get('countryCode') or '').upper(),
                    'isp': d.get('isp') or '', 'ip': d.get('query') or ''}
    except Exception:
        geo[key] = {'cc': '', 'err': 'no answer'}
        continue

    # второй фильтр: как ноду принимает Google/Gemini и Antigravity (daily-cloudcode-pa).
    # 401 на loadCodeAssist = локация разрешена (ждёт токен). 400/403 = геоблок локации/Workers.
    gcode = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-m', '6',
                            '-X', 'POST', '-H', 'Content-Type: application/json', '-d', '{}',
                            '--socks5-hostname', '127.0.0.1:11080',
                            'https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist'],
                           capture_output=True, text=True).stdout.strip()
    if gcode == '401':
        geo[key]['gemini'] = 'ok'
    elif gcode in ('400', '403'):
        geo[key]['gemini'] = 'geoblock'
    else:
        # резервный тест: gemini.google.com/app (200 = ok, 403 = геоблок, 302 sorry = анти-бот)
        hdr = subprocess.run(['curl', '-s', '-m', '10', '--socks5-hostname', '127.0.0.1:11080',
                              '-D', '-', '-o', '/dev/null', 'https://gemini.google.com/app'],
                             capture_output=True, text=True).stdout
        code, loc = '', ''
        for line in hdr.splitlines():
            if line.startswith('HTTP/'):
                parts = line.split()
                if len(parts) > 1:
                    code = parts[1]
            elif line.lower().startswith('location:'):
                loc = line.split(':', 1)[1].strip()
        geo[key]['gemini'] = 'ok' if code == '200' else ('sorry' if 'sorry' in loc else (code or 'нет ответа'))

json.dump(geo, open(geo_path, 'w'), indent=1, ensure_ascii=False)
ccs = {}
for v in geo.values():
    ccs[v['cc'] or 'нет'] = ccs.get(v['cc'] or 'нет', 0) + 1
print('exit countries:', dict(sorted(ccs.items(), key=lambda x: -x[1])))
gm = {}
for v in geo.values():
    k = v.get('gemini') or 'нет'
    gm[k] = gm.get(k, 0) + 1
print('gemini verdicts:', dict(sorted(gm.items(), key=lambda x: -x[1])))
PY

close_tunnel

# --- фаза 2: публикация без РФ-выходов ---
log "publishing filtered config (exclude $EXCLUDE_CC)"
# --strict: ноды, которые не ответили на замер, тоже выкидываем — иначе urltest может
# выбрать такую и уйти через неизвестную (возможно российскую) страну
python3 "$GEN" --geo "$GEO" --exclude "$EXCLUDE_CC" --strict --require-gemini || { log "FILTER FAILED"; exit 1; }
COUNT=$(python3 -c "import json;c=json.load(open('$CFG'));print(sum(1 for o in c['outbounds'] if o.get('server')))")
log "nodes after filter: $COUNT"
[ "$COUNT" -ge 5 ] || { log "TOO FEW NODES — остаюсь на полном конфиге"; exit 1; }
deploy "$CFG" || exit 1

SSH 'ps | grep -q "[s]ing-box run" && echo "service: RUNNING" || echo "service: DOWN"
     ip route show table pbr_sbtun | grep -q "dev sb0" && echo "route: OK" || echo "route: MISSING"'

log "refresh done"
