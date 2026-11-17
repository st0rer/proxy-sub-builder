#!/bin/sh
# NDM hook: автоматически вызывается KeeneticOS при перестроении правил Netfilter
# Гарантирует, что маршруты и фильтры sing-box не сбросятся при сетевых событиях

[ -f /opt/etc/singbox-client/singbox-client.conf ] || exit 0
. /opt/etc/singbox-client/singbox-client.conf

[ "$MODE" = "tun" ] || [ "$MODE" = "tproxy" ] || exit 0

# 1. Отключаем строгий rp_filter на туннеле
if [ -d "/proc/sys/net/ipv4/conf/${TUN_DEV}" ]; then
	sysctl -w "net.ipv4.conf.${TUN_DEV}.rp_filter=0" >/dev/null 2>&1 || true
fi
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true

# 2. Восстанавливаем маршрут в отдельную таблицу
if ip link show "$TUN_DEV" >/dev/null 2>&1; then
	ip route replace default dev "$TUN_DEV" table "$TABLE_ID" 2>/dev/null || true
	ip link set dev "$TUN_DEV" mtu "$TUN_MTU" 2>/dev/null || true

	# Проверяем правило ip rule по метке fwmark
	if ! ip rule show | grep -q "lookup $TABLE_ID"; then
		ip rule add fwmark "$FWMARK" table "$TABLE_ID" 2>/dev/null || true
	fi
fi

# 3. Если используется TProxy режим
if [ "$MODE" = "tproxy" ]; then
	iptables -t mangle -N SINGBOX 2>/dev/null || iptables -t mangle -F SINGBOX
	iptables -t mangle -A SINGBOX -d 0.0.0.0/8 -j RETURN
	iptables -t mangle -A SINGBOX -d 10.0.0.0/8 -j RETURN
	iptables -t mangle -A SINGBOX -d 127.0.0.0/8 -j RETURN
	iptables -t mangle -A SINGBOX -d 169.254.0.0/16 -j RETURN
	iptables -t mangle -A SINGBOX -d 172.16.0.0/12 -j RETURN
	iptables -t mangle -A SINGBOX -d 192.168.0.0/16 -j RETURN
	iptables -t mangle -A SINGBOX -d 224.0.0.0/4 -j RETURN
	iptables -t mangle -A SINGBOX -d 240.0.0.0/4 -j RETURN
	iptables -t mangle -A SINGBOX -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"
	iptables -t mangle -A SINGBOX -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$FWMARK"
fi

exit 0
