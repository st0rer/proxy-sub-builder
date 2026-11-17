# Пакет singbox-sub-client для OpenWrt

Автономный агент для роутеров под управлением OpenWrt (21.02 / 22.03 / 23.05 / 24+).
Потребляет готовую подписку (VLESS Reality, Hysteria 2, Shadowsocks) от `proxy-sub-builder`,
проводит двухфазный замер выхода (включая проверку Gemini и фильтр РФ-выходов), поднимает
интерфейс `sb0` (gvisor, MTU 1200) и бесшовно интегрируется с Policy-Based Routing (pbr).

---

## Архитектура на OpenWrt

```
[Интернет] ──▶ [Подписка / Gist]
                     │
               sb-refresh (05:17)
                     │
           ┌─────────┴─────────┐
           ▼                   ▼
      Фаза 1: стенд      Фаза 2: фильтр
    (замер стран +     (исключение РФ/блоков,
    Gemini вердикт)     sing-box check)
           │                   │
           └─────────┬─────────┘
                     ▼
             /etc/sing-box/config.json
                     │
             procd: sing-box (tun: sb0)
                     │
     hotplug.d: 50-sbtun-route (rp_filter=0 + ip route pbr_sbtun)
                     │
               pbr / nftables
```

---

## Способы установки

### Вариант 1. Быстрая установка в 1 команду (без сборки)

Подключитесь к роутеру по SSH и выполните:

```bash
curl -sSL https://raw.githubusercontent.com/st0rer/proxy-sub-builder/main/router/openwrt/install-openwrt.sh | sh
```

Скрипт автоматически:
1. Установит необходимые пакеты (`sing-box`, `curl`, `jq`, `ca-bundle`, `kmod-tun`, `python3-light`).
2. Развернет скрипты в `/usr/bin/`, хуки в `/etc/hotplug.d/net/` и службу `/etc/init.d/sb-client`.
3. Создаст стандартный конфиг `/etc/config/sb-client`.
4. Сгенерирует первоначальный конфиг и запустит службу.

---

### Вариант 2. Сборка официального пакета `.ipk` в OpenWrt SDK

Если вы собираете свой образ или используете кастомный фид пакетов:

1. Скопируйте папку пакета в дерево сборки:
   ```bash
   cp -r router/openwrt package/singbox-sub-client
   ```
2. Выберите пакет в `menuconfig`:
   ```bash
   make menuconfig
   # Network -> Routing -> singbox-sub-client (выберите M или *)
   ```
3. Скомпилируйте универсальный пакет:
   ```bash
   make package/singbox-sub-client/compile V=s
   ```
4. Установите полученный `.ipk` на роутер:
   ```bash
   opkg install bin/packages/.../singbox-sub-client_1.1.0-1_all.ipk
   ```

---

## Настройка (`/etc/config/sb-client`)

Конфигурация хранится в стандартном формате UCI:

```text
config sb-client 'main'
	option enabled '1'
	option sub_url 'https://raw.githubusercontent.com/st0rer/proxy-sub/main/v2ray.txt'
	option fallback_url 'http://192.168.1.100:8899/yota.txt'
	option tun_dev 'sb0'
	option tun_mtu '1200'
	option routing_table 'pbr_sbtun'
	option exclude_cc 'RU'
	option require_gemini '1'
	option auto_refresh '1'
	option cf_watchdog '1'
```

Применить изменения:
```bash
/etc/init.d/sb-client reload
# или принудительно обновить подписку прямо сейчас:
/etc/init.d/sb-client refresh
```

---

## Подводные камни и оптимизации в OpenWrt

1. **Сброс маршрутов при падении интерфейса:**
   При каждом перезапуске `sing-box` туннель `sb0` пересоздается, а маршрут в таблице `pbr_sbtun` исчезает.
   *Решение:* скрипт `/etc/hotplug.d/net/50-sbtun-route` автоматически ловит событие `ifup` и мгновенно восстанавливает маршрут.
2. **`rp_filter` (Reverse Path Filtering):**
   Если на `sb0` включен строгий режим, ядро Linux молча отбрасывает входящие пакеты из прокси-туннеля.
   *Решение:* hotplug и сервис выставляют `sysctl -w net.ipv4.conf.sb0.rp_filter=0`.
3. **Безопасный MTU 1200:**
   Из-за накладных расходов VLESS/TLS/QUIC стандартный MTU 1500 вызывает фрагментацию и обрывы TCP-соединений. В конфиге жестко зафиксирован MTU 1200.
4. **Легковесный Python:**
   `sbgen.py` написан исключительно на стандартной библиотеке Python. Достаточно пакета `python3-light` (~12 МБ), никаких сторонних pip-модулей не требуется.
