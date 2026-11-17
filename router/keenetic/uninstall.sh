#!/bin/sh
# uninstall.sh — Полное и чистое удаление singbox-client с KeeneticOS 5
set -u

echo "Останавливаю службу..."
if [ -x /opt/etc/init.d/S99singbox-client ]; then
	/opt/etc/init.d/S99singbox-client stop >/dev/null 2>&1 || true
fi

echo "Очищаю правила маршрутизации и хуки NDM..."
rm -f /opt/etc/ndm/netfilter.d/100-singbox.sh
rm -f /opt/etc/ndm/ifstatechanged.d/100-singbox.sh
rm -f /opt/etc/init.d/S99singbox-client

echo "Удаляю скрипты..."
rm -f /opt/bin/sbgen.py /opt/bin/sb-refresh /opt/bin/cf-watchdog
rm -rf /opt/tmp/sb-client

echo "Очищаю crontab..."
if [ -f /opt/etc/crontab ]; then
	sed -i '/sb-refresh/d' /opt/etc/crontab
	sed -i '/cf-watchdog/d' /opt/etc/crontab
	[ -x /opt/etc/init.d/S10cron ] && /opt/etc/init.d/S10cron restart >/dev/null 2>&1 || true
fi

echo "singbox-client удален. Конфигурация в /opt/etc/singbox-client сохранена."
echo "Если хотите удалить и её: rm -rf /opt/etc/singbox-client /opt/etc/sing-box"
