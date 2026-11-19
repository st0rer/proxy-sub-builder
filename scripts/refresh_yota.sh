#!/bin/bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/env.sh"
# refresh_yota.sh — подписка для мобильного (Yota), проверка с малинки в Радищево.
#
# Отличия от домашнего прогона:
#   * ноды проверяются ИЗ СЕТИ Yota — там другой DPI, а не тот, что дома;
#   * трафик мобильный, поэтому бюджет ≈ 12–14 МБ за прогон (задержка ~6 КБ/нода,
#     скорость 1 МБ и только для SPEED_TOP лучших);
#   * вперёд ставятся vless, а не hy2: на этом пути QUIC не проходит (замер ниже).
set -uo pipefail
if [ -z "${PI_HOST:-}" ]; then
  if [ -f "$VPN_SECRETS/pi_host" ]; then
    PI_HOST=$(tr -d '\r\n ' < "$VPN_SECRETS/pi_host")
  fi
fi
if [ -z "${PI_PASS:-}" ]; then
  if [ -f "$VPN_SECRETS/pi_pass" ]; then
    PI_PASS=$(tr -d '\r\n ' < "$VPN_SECRETS/pi_pass")
  fi
fi
export PI_HOST="${PI_HOST:-}"
export PI_PASS="${PI_PASS:-}"
B="$BIN_DIR"
LOG=$VPN_OUT/refresh_yota.log
OUT=$VPN_OUT/sub-yota
HERMES=notify
LOCK=$VPN_CACHE/.yota.lock
mkdir -p "$OUT"

exec 9>"$LOCK"
if ! flock -n 9; then echo "=== $(date -Is) пропуск: идёт другой мобильный прогон ===" >> "$LOG"; exit 0; fi

{
  echo "=== $(date -Is) start yota ==="
  # жива ли малинка по Zerotier
  if ! timeout 12 sshpass -p "${PI_PASS:?не задан PI_PASS}" ssh -o StrictHostKeyChecking=no \
        -o PubkeyAuthentication=no -o ConnectTimeout=8 $PI_HOST true 2>/dev/null; then
    # ВРЕМЕННЫЙ режим: пока малинка мертва, не оставляем клиентов со старым
    # yota.txt. Ссылка должна жить, поэтому собираем подписку из живых нод,
    # проверенных на N100 и отсеянных из домашней (потолки/дедуп/скорость).
    echo "малинка недоступна по ZT — собираю временную подписку из домашних проверенных нод"
    python3 "$B/yota_fallback.py" || { echo "fallback: нечего собрать"; exit 1; }
    SUB_FROM=$VPN_OUT/mobile_fallback.json \
    SUB_OUT="$OUT" \
    SUB_CAPS="vless=60,ss=30,hy2=10,anytls=15,trojan=10,tuic=0,vmess=0" \
    SUB_MAX_PER_PANEL=6 \
    SUB_ORDER=tcp \
    SUB_MIN_SPEED=0.03 \
    SUB_MIN_NODES=${SUB_MIN_NODES:-3} \
    SUB_ALLOW_SHRINK=1 \
    SUB_NODES=nodes-yota.txt \
    SUB_V2RAY=yota.txt \
    SUB_REQUIRE_GEMINI=1 \
    SKIP_XRAY_GATE=1 \
    python3 "$B/publish_sub.py" || { echo "fallback: публикация не собралась"; exit 1; }
    python3 "$B/publish_pub.py"        || echo "repo publish yota (fallback) failed"
    python3 "$B/publish_pub.py" --gist || echo "gist publish yota (fallback) failed"
    echo "=== $(date -Is) done yota (fallback) ==="
    exit 0
  fi

  PI_MIN_SPEED=0.03 python3 "$B/mobile_push.py" || { echo "проверка на малинке не удалась"; exit 1; }

  SUB_FROM=$VPN_OUT/mobile_results.json \
  SUB_OUT="$OUT" \
  SUB_CAPS="vless=60,ss=30,hy2=10,anytls=15,trojan=10,tuic=0,vmess=0" \
  SUB_MAX_PER_PANEL=6 \
  SUB_ORDER=tcp \
  SUB_MIN_SPEED=0.03 \
  SUB_MIN_NODES=${SUB_MIN_NODES:-3} \
  SUB_ALLOW_SHRINK=1 \
  SUB_NODES=nodes-yota.txt \
  SUB_V2RAY=yota.txt \
  SUB_REQUIRE_GEMINI=1 \
  SKIP_XRAY_GATE=1 \
  python3 "$B/publish_sub.py" || echo "публикация yota не удалась"

  # публикация в repo и gist: без этого шага клиент продолжает тянуть старый файл,
  # а локальные 13 нод остаются на диске (так и получилось 16.11 — в gist висели
  # 10 мёртвых нод от 01:27, и «список стал коротким, ни один не работает»)
  python3 "$B/publish_pub.py"        || echo "repo publish yota failed"
  python3 "$B/publish_pub.py" --gist || echo "gist publish yota failed"

  # снимок мобильной подписки: своя история, отдельно от домашней
  SUB_DIR="$OUT" SUB_GOOD=$VPN_OUT/good-yota SUB_FILES=nodes-yota.txt,yota.txt,clash.yaml,index.json SUB_MIN_NODES=3 \
    python3 "$B/sub_snapshot.py" save || echo "снимок yota не снят"

  python3 "$B/gc_engine.py" || echo "gc failed"

  # hy2-подписку для мобильного не публикуем: QUIC там не проходит
  echo "=== $(date -Is) done yota ==="
} >> "$LOG" 2>&1
