#!/bin/bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/env.sh"
# refresh_subs.sh — обновление подписки: скан -> чистка -> публикация -> GitHub
#
# Выживание: при отсутствии интернета прогон не начинается вообще (ничего не трогаем),
# публикация пишется атомарно, после неё снимается снимок и делается самопроверка,
# битая подписка откатывается из последнего снимка. В конце — сборка мусора.
set -uo pipefail
S="$BIN_DIR"
B="$BIN_DIR"
LOG=$VPN_OUT/refresh.log
HERMES=notify
LOCK=$VPN_CACHE/.refresh.lock
mkdir -p $VPN_OUT $VPN_CACHE
source $VPN_SECRETS/scan.env 2>/dev/null || true

# Два одновременных прогона (таймер + ручной запуск) пишут в одни и те же
# scan_N.yaml / all_links.json / verified.json и портят друг другу результаты.
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "=== $(date -Is) пропуск: уже идёт другой прогон ===" >> "$LOG"
  exit 0
fi

# --- preflight: без сети не начинаем, иначе промежуточные файлы перезапишутся пустотой
net_ok=0
URLS=${PREFLIGHT_URLS:-"https://api.github.com/rate_limit https://1.1.1.1/cdn-cgi/trace https://raw.githubusercontent.com/robots.txt"}
for u in $URLS; do
  if curl -s -o /dev/null --max-time 6 "$u"; then net_ok=$((net_ok+1)); fi
done
if [ "$net_ok" -eq 0 ]; then
  echo "=== $(date -Is) нет интернета (0/3 эндпоинта) — прогон отменён, подписка не тронута ===" >> "$LOG"
  exit 0
fi
gh_ok=0
curl -s -o /dev/null --max-time 6 https://api.github.com/rate_limit && gh_ok=1

{
  echo "=== $(date -Is) start (net $net_ok/3, github $gh_ok) ==="

  # Свет погас посреди прошлого прогона? Тогда файл мог остаться обрезанным —
  # лечим из последнего снимка до того, как что-то перезапишем.
  if [ -f $VPN_OUT/good/LAST ]; then
    if ! python3 "$B/sub_snapshot.py" check >/dev/null 2>&1; then
      echo "!! подписка битая на входе — восстанавливаю из снимка"
      python3 "$B/sub_snapshot.py" restore
    fi
  fi

  # сайты-каталоги ключей: их нет в GitHub-списках, часть отдаёт ссылки только в HTML.
  # vpnkeys.me перепроверяет ключи каждые 60 с — выход живыми там 8/12 против 1/4 у GitHub.
  timeout 600 $PY_SCRAPLING "$B/scrape_web.py" \
    "https://vpnkeys.me/" "https://vpnkeys.me/klyuchi/vless/" \
    "https://vpnkeys.me/country/de/" "https://vpnkeys.me/country/nl/" \
    "https://vpnkeys.me/country/fi/" "https://vpnkeys.me/country/se/" \
    "https://vpnkeys.me/country/us/" "https://t.me/s/outlineOpenKey" \
    || echo "scrape failed (не критично: списки GitHub остаются)"

  # редкие протоколы (anytls/tuic/hysteria v1) почти не встречаются в GitHub-списках,
  # но регулярно постятся в телеграм-каналах: берём публичные превью t.me/s/
  timeout 600 python3 "$B/discover_channels.py" --search \
    || echo "discover_channels failed (не критично)"
  timeout 420 python3 "$B/tg_scrape.py" 400 \
    || echo "tg_scrape failed (не критично)"

  python3 "$S/scan_any.py" collect   || echo "collect failed"
  python3 "$S/scan_any.py" latency   || echo "latency failed"
  python3 "$S/scan_any.py" verify 280 || echo "verify failed"
  python3 "$S/scan_any.py" clean     || echo "clean failed"

  out=$(python3 "$B/publish_sub.py" 2>&1); rc=$?
  echo "$out"

  if [ $rc -eq 0 ]; then
    python3 "$B/sub_snapshot.py" save || echo "snapshot failed"
    if ! python3 "$B/sub_snapshot.py" check; then
      echo "!! подписка не прошла самопроверку — откат"
      python3 "$B/sub_snapshot.py" restore
      "$HERMES" send -t telegram "⚠️ Подписка не прошла проверку после публикации, откатил из снимка" 2>&1 || echo "alert failed"
    fi
    if [ "$gh_ok" -eq 1 ]; then
      python3 "$B/publish_pub.py"        || echo "repo publish failed"
      python3 "$B/publish_pub.py" --gist || echo "gist publish failed"
    else
      echo "GitHub недоступен — публикую только локально, на GitHub уйдёт на следующем прогоне"
    fi
  else
    # тихий отказ — худший сценарий: клиенты остались бы со старым списком и никто бы не узнал
    "$HERMES" send -t telegram "⚠️ Подписка не обновлена (код $rc): $out" 2>&1 || echo "alert failed"
  fi

  python3 "$B/gc_engine.py" || echo "gc failed"
  echo "=== $(date -Is) done (publish rc=$rc) ==="
} >> "$LOG" 2>&1
