#!/bin/sh
# install-openwrt.sh — Быстрый прямой установщик singbox-sub-client на OpenWrt
set -eu

REPO_RAW="https://raw.githubusercontent.com/st0rer/proxy-sub-builder/main"

echo "=== 1. Проверка и установка пакетов OpenWrt ==="
opkg update
for pkg in sing-box curl jq ca-bundle kmod-tun python3-light; do
	if ! opkg list-installed | grep -q "^${pkg} "; then
		echo "Устанавливаю $pkg..."
		opkg install "$pkg" || echo "Предупреждение: $pkg не удалось установить через opkg"
	fi
done

echo "=== 2. Создание каталогов ==="
mkdir -p /usr/bin /etc/sing-box /etc/config /etc/init.d /etc/hotplug.d/net /usr/share/sb-client /tmp/sb-client

echo "=== 3. Скачивание исполняемых компонентов ==="
curl -sfL "$REPO_RAW/router/openwrt/files/usr/bin/sbgen.py" -o /usr/bin/sbgen.py
curl -sfL "$REPO_RAW/router/openwrt/files/usr/bin/sb-refresh" -o /usr/bin/sb-refresh
curl -sfL "$REPO_RAW/router/openwrt/files/usr/bin/cf-watchdog" -o /usr/bin/cf-watchdog
curl -sfL "$REPO_RAW/router/openwrt/files/usr/share/sb-client/google-nets.txt" -o /usr/share/sb-client/google-nets.txt
curl -sfL "$REPO_RAW/router/openwrt/files/etc/hotplug.d/net/50-sbtun-route" -o /etc/hotplug.d/net/50-sbtun-route
curl -sfL "$REPO_RAW/router/openwrt/files/etc/init.d/sb-client" -o /etc/init.d/sb-client

if [ ! -f /etc/config/sb-client ]; then
	curl -sfL "$REPO_RAW/router/openwrt/files/etc/config/sb-client" -o /etc/config/sb-client
fi

chmod +x /usr/bin/sbgen.py /usr/bin/sb-refresh /usr/bin/cf-watchdog /etc/init.d/sb-client /etc/hotplug.d/net/50-sbtun-route

echo "=== 4. Активация сервиса ==="
/etc/init.d/sb-client enable
/etc/init.d/sb-client start || true

echo "=== Установка завершена успешно! ==="
echo "Настройте параметры в: /etc/config/sb-client"
echo "Лог службы: logread -e sb-client"
