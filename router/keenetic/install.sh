#!/bin/sh
# install.sh — Инсталлятор singbox-client для KeeneticOS 5 (Entware)
set -eu

REPO_RAW="https://raw.githubusercontent.com/st0rer/proxy-sub-builder/main"

echo "=== 1. Проверка окружения Entware ==="
if [ ! -d "/opt/bin" ] || [ ! -x "/opt/bin/opkg" ]; then
	echo "ОШИБКА: Entware не обнаружен в /opt!"
	echo "Убедитесь, что в KeeneticOS установлен компонент 'Поддержка открытых пакетов OPKG'"
	echo "и подключен USB-накопитель (или настроен раздел UBIFS)."
	exit 1
fi

echo "=== 2. Установка зависимостей через opkg ==="
/opt/bin/opkg update
# Базовые утилиты
for pkg in curl jq ca-certificates iptables; do
	if ! /opt/bin/opkg list-installed | grep -q "^${pkg} "; then
		echo "Устанавливаю $pkg..."
		/opt/bin/opkg install "$pkg" || echo "Предупреждение: не удалось установить $pkg"
	fi
done

# sing-box: в Entware пакет называется sing-box-go (или sing-box)
if ! /opt/bin/opkg list-installed | grep -E -q '^(sing-box|sing-box-go) '; then
	echo "Устанавливаю sing-box..."
	/opt/bin/opkg install sing-box-go || /opt/bin/opkg install sing-box || echo "Предупреждение: не удалось установить sing-box"
fi
if [ -x /opt/bin/sing-box-go ] && [ ! -e /opt/bin/sing-box ]; then
	ln -sf /opt/bin/sing-box-go /opt/bin/sing-box
fi

# python3: в Entware пакет называется python3 (или python3-base)
if ! /opt/bin/opkg list-installed | grep -E -q '^(python3|python3-light|python3-base) '; then
	echo "Устанавливаю python3..."
	/opt/bin/opkg install python3 || /opt/bin/opkg install python3-light || echo "Предупреждение: не удалось установить python3"
fi

echo "=== 3. Создание каталогов ==="
mkdir -p /opt/bin /opt/etc/sing-box /opt/etc/singbox-client /opt/etc/init.d \
         /opt/etc/ndm/netfilter.d /opt/etc/ndm/ifstatechanged.d /opt/tmp/sb-client /opt/var/log

echo "=== 4. Развертывание скриптов и хуков ==="
curl -sfL "$REPO_RAW/router/keenetic/opt/bin/sbgen.py" -o /opt/bin/sbgen.py
curl -sfL "$REPO_RAW/router/keenetic/opt/bin/sb-refresh" -o /opt/bin/sb-refresh
curl -sfL "$REPO_RAW/router/keenetic/opt/bin/cf-watchdog" -o /opt/bin/cf-watchdog
curl -sfL "$REPO_RAW/router/keenetic/opt/etc/singbox-client/google-nets.txt" -o /opt/etc/singbox-client/google-nets.txt
curl -sfL "$REPO_RAW/router/keenetic/opt/etc/init.d/S99singbox-client" -o /opt/etc/init.d/S99singbox-client
curl -sfL "$REPO_RAW/router/keenetic/opt/etc/ndm/netfilter.d/100-singbox.sh" -o /opt/etc/ndm/netfilter.d/100-singbox.sh
curl -sfL "$REPO_RAW/router/keenetic/opt/etc/ndm/ifstatechanged.d/100-singbox.sh" -o /opt/etc/ndm/ifstatechanged.d/100-singbox.sh

if [ ! -f /opt/etc/singbox-client/singbox-client.conf ]; then
	curl -sfL "$REPO_RAW/router/keenetic/opt/etc/singbox-client/singbox-client.conf" -o /opt/etc/singbox-client/singbox-client.conf
fi

chmod +x /opt/bin/sbgen.py /opt/bin/sb-refresh /opt/bin/cf-watchdog \
         /opt/etc/init.d/S99singbox-client \
         /opt/etc/ndm/netfilter.d/100-singbox.sh \
         /opt/etc/ndm/ifstatechanged.d/100-singbox.sh

echo "=== 5. Запуск службы ==="
/opt/etc/init.d/S99singbox-client start || true

echo "=== Установка на KeeneticOS 5 завершена! ==="
echo "Конфигурация: /opt/etc/singbox-client/singbox-client.conf"
echo "Управление: /opt/etc/init.d/S99singbox-client {start|stop|restart|status|refresh}"
echo "Логи: /opt/var/log/sing-box.log"
