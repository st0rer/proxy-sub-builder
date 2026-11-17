#!/bin/sh
# NDM hook: вызывается KeeneticOS при изменении статуса сетевых интерфейсов

[ -f /opt/etc/ndm/netfilter.d/100-singbox.sh ] && /opt/etc/ndm/netfilter.d/100-singbox.sh
exit 0
