#!/usr/bin/env bash
# lib/env.sh — общие переменные для bash-обвязки (refresh_*.sh, mobile_watch.sh).
#
# Ничего личного: всё переопределяется переменными окружения.
#   PROXY_SUB_HOME  ~/.proxy-sub      корень (cache, out, secrets)
#   VPN_OUT         $PROXY_SUB_HOME/out
#   VPN_CACHE       $PROXY_SUB_HOME/cache
#   VPN_SECRETS     $PROXY_SUB_HOME/secrets
#   BIN_DIR         каталог со скриптами и движками
#   NOTIFY_CMD      команда уведомления, например: hermes send -t telegram
#   PI_HOST         root@host  — малинка в мобильной сети
#   PI_PASS         пароль ssh к ней
#   GIST_ID         id гиста с подпиской
#   PY_SCRAPLING    python со Scrapling (по умолчанию python3)

: "${PROXY_SUB_HOME:=$HOME/.proxy-sub}"
: "${VPN_OUT:=$( [ -d "$HOME/vpn_results" ] && echo "$HOME/vpn_results" || echo "$PROXY_SUB_HOME/out" )}"
: "${VPN_CACHE:=$( [ -d "$HOME/.cache/vpn-search" ] && echo "$HOME/.cache/vpn-search" || echo "$PROXY_SUB_HOME/cache" )}"
: "${VPN_SECRETS:=$( [ -d "$HOME/.hermes/secrets" ] && echo "$HOME/.hermes/secrets" || echo "$PROXY_SUB_HOME/secrets" )}"
: "${BIN_DIR:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
if [ -z "${PY_SCRAPLING:-}" ]; then
  if [ -x "$HOME/.hermes/venvs/scrapling/bin/python3" ]; then
    PY_SCRAPLING="$HOME/.hermes/venvs/scrapling/bin/python3"
  elif [ -x "/home/claw/.hermes/venvs/scrapling/bin/python3" ]; then
    PY_SCRAPLING="/home/claw/.hermes/venvs/scrapling/bin/python3"
  else
    PY_SCRAPLING="python3"
  fi
fi
: "${NOTIFY_CMD:=}"

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

if [ -z "${GIST_ID:-}" ]; then
  if [ -f "$VPN_SECRETS/gist_id" ]; then
    GIST_ID=$(tr -d '\r\n ' < "$VPN_SECRETS/gist_id")
  elif [ -f "$VPN_SECRETS/pub_target.json" ]; then
    GIST_ID=$(python3 -c "import json; print(json.load(open('$VPN_SECRETS/pub_target.json')).get('gist_id',''))" 2>/dev/null || true)
  fi
fi
export GIST_ID="${GIST_ID:-}"

export PROXY_SUB_HOME VPN_OUT VPN_CACHE VPN_SECRETS BIN_DIR PY_SCRAPLING NOTIFY_CMD
export PROXY_SUB_OUT="$VPN_OUT" PROXY_SUB_CACHE="$VPN_CACHE" PROXY_SUB_SECRETS="$VPN_SECRETS"
export PROXY_SUB_BIN="$BIN_DIR"

mkdir -p "$VPN_OUT" "$VPN_CACHE" "$VPN_SECRETS"

notify() {
  if [ -n "$NOTIFY_CMD" ]; then
    $NOTIFY_CMD "$1" >/dev/null 2>&1 || true
  else
    echo "NOTIFY: $1"
  fi
}

require() {
  local name=$1
  if [ -z "${!name:-}" ]; then
    echo "не задана переменная $name (см. env.example)" >&2
    exit 2
  fi
}
