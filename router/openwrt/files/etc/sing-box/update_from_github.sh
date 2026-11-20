#!/bin/sh
# /etc/sing-box/update_from_github.sh
# Автономное обновление нод из GitHub (st0rer/proxy-sub) и генерация конфига sing-box
# на самом роутере Тургенева.
#
# ВАЖНО (грабли 20.11.2026): генерация БЕЗ замера страны выхода ставит в gcp ноды
# с российским выходом — Google отвечает «Detected location: RU», Antigravity
# перестаёт работать. Поэтому здесь три фазы, как в sb-refresh на N100:
#   1) полный конфиг -> временно накатываем как стенд
#   2) замер по каждой ноде: страна выхода + вердикт Gemini
#   3) генерация отфильтрованного конфига (--geo --exclude RU --strict --require-gemini)
# При любой ошибке после накатки полного конфига возвращаем предыдущий.
set -u

URL="https://raw.githubusercontent.com/st0rer/proxy-sub/main/nodes.txt"
URL2="https://raw.githubusercontent.com/st0rer/proxy-sub/main/v2ray.txt"
SCRATCH="/tmp/singbox_update"
TARGET="/etc/sing-box/config.json"
PREV="$SCRATCH/config.prev.json"
FULL="$SCRATCH/config.full.json"
FILT="$SCRATCH/config.filtered.json"
GEO="$SCRATCH/sb-geo.json"
SRC="$SCRATCH/nodes.txt"
SBGEN="/etc/sing-box/sbgen.py"
CF_NODE="/etc/sing-box/cf_node.json"

mkdir -p "$SCRATCH"
log() { echo "[$(date -u +%F' '%T)UTC] [update] $*"; }

restore_prev() {
    if [ -s "$PREV" ]; then
        cp "$PREV" "$TARGET"
        /etc/init.d/sing-box restart >/dev/null 2>&1
        sleep 5
        log "восстановил предыдущий конфиг"
    fi
}

# --- 1. список нод ---
if ! curl -sf -m 30 -o "$SRC" "$URL"; then
    if ! curl -sf -m 30 -o "$SRC" "$URL2"; then
        log "ОШИБКА: не скачал список нод, конфиг не трогаю"
        exit 1
    fi
fi
[ -s "$SRC" ] || { log "ОШИБКА: скачанный список пуст"; exit 1; }
log "нод в источнике: $(grep -c '://' "$SRC" 2>/dev/null || echo 0)"

cp "$TARGET" "$PREV" 2>/dev/null || true

# --- 2. полный конфиг ---
export SINGBOX_SOURCE="$SRC"
export SINGBOX_CONFIG="$FULL"
export SINGBOX_CF_NODE="$CF_NODE"
python3 "$SBGEN" >/dev/null || { log "ОШИБКА: sbgen упал на полном конфиге"; exit 1; }
if ! sing-box check -c "$FULL" >/dev/null 2>&1; then
    log "ОШИБКА: полный конфиг не прошёл sing-box check — остаюсь на текущем"
    exit 1
fi

# --- 3. стенд для замера ---
cp "$FULL" "$TARGET"
/etc/init.d/sing-box restart >/dev/null 2>&1 || { log "ОШИБКА: сервис не поднялся"; restore_prev; exit 1; }
sleep 12
if ! curl -sf -m 5 http://127.0.0.1:9090/proxies >/dev/null 2>&1; then
    log "ОШИБКА: clash_api не отвечает после рестарта"
    restore_prev
    exit 1
fi

# --- 4. замер страны выхода и вердикта Gemini по каждой ноде ---
log "замер выхода и Gemini по нодам…"
python3 - "$FULL" "$GEO" <<'PY'
import json, subprocess, sys

full_path, geo_path = sys.argv[1], sys.argv[2]
cfg = json.load(open(full_path))
nodes = [o for o in cfg.get("outbounds", []) if o.get("server")]
geo = {}
for n in nodes:
    tag = n["tag"]
    key = f"{n['type']}|{n['server']}|{n['server_port']}"
    sw = ""
    for _ in range(3):
        sw = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "5", "-X", "PUT",
                             "-H", "Content-Type: application/json", "-d", json.dumps({"name": tag}),
                             "http://127.0.0.1:9090/proxies/proxy"],
                            capture_output=True, text=True).stdout.strip()
        if sw == "204":
            break
    if sw != "204":
        geo[key] = {"cc": "", "err": "switch_failed"}
        continue
    body = subprocess.run(["curl", "-s", "-m", "8", "--socks5-hostname", "127.0.0.1:1080",
                           "http://ip-api.com/json/?fields=status,countryCode,isp,query"],
                          capture_output=True, text=True).stdout
    try:
        d = json.loads(body)
        geo[key] = {"cc": (d.get("countryCode") or "").upper(),
                    "isp": d.get("isp") or "", "ip": d.get("query") or ""}
    except Exception:
        geo[key] = {"cc": "", "err": "no_answer"}
        continue
    hdr = subprocess.run(["curl", "-s", "-m", "10", "--socks5-hostname", "127.0.0.1:1080",
                          "-D", "-", "-o", "/dev/null", "https://gemini.google.com/app"],
                         capture_output=True, text=True).stdout
    code, loc = "", ""
    for line in hdr.splitlines():
        if line.startswith("HTTP/"):
            p = line.split()
            if len(p) > 1:
                code = p[1]
        elif line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
    geo[key]["gemini"] = "ok" if code == "200" else ("sorry" if "sorry" in loc else (code or "no_resp"))

json.dump(geo, open(geo_path, "w"), indent=1, ensure_ascii=False)
ccs = {}
for v in geo.values():
    ccs[v["cc"] or "нет"] = ccs.get(v["cc"] or "нет", 0) + 1
gm = {}
for v in geo.values():
    k = v.get("gemini") or "нет"
    gm[k] = gm.get(k, 0) + 1
print("  страны:", dict(sorted(ccs.items(), key=lambda x: -x[1])))
print("  gemini:", dict(sorted(gm.items(), key=lambda x: -x[1])))
sw = sum(1 for v in geo.values() if v.get("err") == "switch_failed")
if sw > max(2, len(nodes) // 3):
    print(f"  ABORT: не переключилось {sw} из {len(nodes)}")
    sys.exit(3)
PY
if [ $? -ne 0 ]; then
    log "ОШИБКА: замер прерван — возвращаю предыдущий конфиг"
    restore_prev
    exit 1
fi

# --- 5. отфильтрованный конфиг: без РФ-выходов, без геоблока Gemini ---
export SINGBOX_CONFIG="$FILT"
if ! python3 "$SBGEN" --geo "$GEO" --exclude RU --strict --require-gemini >/dev/null; then
    log "ОШИБКА: sbgen упал на фильтрации"
    restore_prev
    exit 1
fi
COUNT=$(python3 -c "import json;c=json.load(open('$FILT'));print(sum(1 for o in c.get('outbounds',[]) if o.get('server')))" 2>/dev/null || echo 0)
log "нод после фильтра: $COUNT"
if [ "$COUNT" -lt 4 ]; then
    log "ОШИБКА: после фильтра осталось $COUNT нод — оставляю прежний конфиг"
    restore_prev
    exit 1
fi
if ! sing-box check -c "$FILT" >/dev/null 2>&1; then
    log "ОШИБКА: отфильтрованный конфиг не валиден"
    restore_prev
    exit 1
fi

# --- 6. атомарная замена ---
cp "$TARGET" "$TARGET.bak" 2>/dev/null || true
cp "$FILT" "$TARGET"
/etc/init.d/sing-box restart >/dev/null 2>&1
sleep 20
ip route replace default dev sb0 table pbr_sbtun 2>/dev/null
if curl -sf -m 5 http://127.0.0.1:9090/proxies >/dev/null 2>&1; then
    log "готово: конфиг обновлён, сервис отвечает"
else
    log "ОШИБКА: сервис не отвечает после замены — откат"
    restore_prev
    exit 1
fi
rm -f "$FULL" 2>/dev/null || true
exit 0
