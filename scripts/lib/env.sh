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
: "${VPN_OUT:=$PROXY_SUB_HOME/out}"
: "${VPN_CACHE:=$PROXY_SUB_HOME/cache}"
: "${VPN_SECRETS:=$PROXY_SUB_HOME/secrets}"
: "${BIN_DIR:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
: "${PY_SCRAPLING:=python3}"
: "${NOTIFY_CMD:=}"

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
