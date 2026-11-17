#!/bin/bash
# Расход суточной квоты Cloudflare Worker (free = 100 000 запросов/сутки, сброс в 00:00 UTC).
# Считает запросы указанного воркера (CF_WORKER_SCRIPT) через GraphQL Analytics API.
# Ошибка 1027 у Cloudflare — это и есть «квота кончилась».
#   cf-usage.sh          — за сегодня
#   cf-usage.sh 7        — за последние 7 дней (по дням)
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env.sh
. "$DIR/lib/env.sh"

ACC="${CF_ACCOUNT_ID:-}"
SCRIPT="${CF_WORKER_SCRIPT:-}"
LIMIT="${CF_DAILY_LIMIT:-100000}"
DAYS="${1:-1}"
LOG_DIR="${SINGBOX_LOG_DIR:-$PROXY_SUB_HOME/logs}"
LOG="$LOG_DIR/cf-usage.log"
TOKEN="${CF_API_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -f "$VPN_SECRETS/cf_token" ]; then
    TOKEN=$(tr -d '\r\n ' < "$VPN_SECRETS/cf_token")
fi
require ACC
require SCRIPT
require TOKEN
mkdir -p "$LOG_DIR"
TMP="${TMPDIR:-/tmp}/cf-usage-$$.json"

from=$(date -u -d "$((DAYS-1)) days ago" +%Y-%m-%d)
to=$(date -u +%Y-%m-%d)

printf '{"query":"query { viewer { accounts(filter: {accountTag: \\"%s\\"}) { workersInvocationsAdaptive(filter: {datetime_geq: \\"%sT00:00:00Z\\", datetime_leq: \\"%sT23:59:59Z\\"}, limit: 1000) { sum { requests errors subrequests } dimensions { scriptName date } } } } }"}' \
    "$ACC" "$from" "$to" > "$TMP.req"

curl -s -m 30 -X POST https://api.cloudflare.com/client/v4/graphql \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    --data @"$TMP.req" -o "$TMP"

python3 - "$TMP" "$SCRIPT" "$LIMIT" "$DAYS" >> "$LOG" 2>&1 <<'PY'
import json, sys, collections

path, script, limit, days = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
try:
    d = json.load(open(path))
    rows = d["data"]["viewer"]["accounts"][0]["workersInvocationsAdaptive"]
except Exception:
    raw = open(path, encoding="utf-8", errors="ignore").read()[:300]
    print(f"[usage] не удалось получить аналитику: {raw}")
    raise SystemExit(1)

by = collections.defaultdict(lambda: [0, 0, 0])
for r in rows:
    if r["dimensions"].get("scriptName") != script:
        continue
    acc = by[r["dimensions"]["date"]]
    acc[0] += r["sum"]["requests"]
    acc[1] += r["sum"]["errors"]
    acc[2] += r["sum"]["subrequests"]

if not by:
    print(f"[usage] за период данных по {script} нет")
    raise SystemExit(0)

for day in sorted(by):
    req, err, sub = by[day]
    pct = req * 100.0 / limit
    flag = "OK"
    if pct >= 90:
        flag = "КРИТИЧНО"
    elif pct >= 70:
        flag = "внимание"
    print(f"[{day}] {script}: {req} запросов из {limit} ({pct:.1f}%), ошибок {err}, subrequests {sub} — {flag}")
PY

rm -f "$TMP" "$TMP.req"
tail -"$DAYS" "$LOG"

last=$(tail -1 "$LOG")
case "$last" in
  *КРИТИЧНО*|*внимание*) echo "$last" > "$LOG_DIR/CF-QUOTA-WARNING.txt" ;;
  *) rm -f "$LOG_DIR/CF-QUOTA-WARNING.txt" ;;
esac
