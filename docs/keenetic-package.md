# Пакет singbox-client для KeeneticOS 5 (Entware)

Автономный агент обхода блокировок для роутеров Keenetic под управлением KeeneticOS 5.
Использует среду Entware (OPKG) и учитывает специфику работы демона NDM и фаервола Keenetic.

---

## Архитектура на KeeneticOS 5

```
[Интернет] ──▶ [Подписка: Gist / N100]
                     │
         /opt/bin/sb-refresh (05:17)
                     │
           ┌─────────┴─────────┐
           ▼                   ▼
      Фаза 1: стенд      Фаза 2: фильтр
    (замер стран +     (исключение РФ,
    Gemini вердикт)     sing-box check)
           │                   │
           └─────────┬─────────┘
                     ▼
          /opt/etc/sing-box/config.json
                     │
         S99singbox-client (tun sb0 / tproxy)
                     │
  NDM Hook: /opt/etc/ndm/netfilter.d/100-singbox.sh
  (восстановление iptables, rp_filter=0 и ip rule)
```

---

## Требования к Keenetic

1. **KeeneticOS 5** (или 4.x).
2. Установленный компонент прошивки: **«Поддержка открытых пакетов OPKG»**.
3. Инициализированный накопитель Entware:
   * USB-флешка/диск с файловой системой EXT4 (компонент «Файловая система Ext»).
   * Либо встроенная flash-память (раздел UBIFS на моделях Titan KN-1811/1812, Hero, Peak).
4. Установленный компонент прошивки: **«Модули ядра для работы с Netfilter»** (требуется для перехвата трафика и работы туннелей).

---

## Установка в 1 команду

Подключитесь к роутеру по SSH (порт 222 или 22 в зависимости от настроек Entware):

```bash
curl -sSL https://raw.githubusercontent.com/st0rer/proxy-sub-builder/main/router/keenetic/install.sh | sh
```

Инсталлятор выполнит:
1. Проверку наличия `/opt/bin/opkg`.
2. Установку зависимостей: `sing-box`, `curl`, `jq`, `ca-certificates`, `python3-light`, `iptables`.
3. Развертывание скриптов в `/opt/bin/` и конфигурации в `/opt/etc/singbox-client/`.
4. Установку демона автозапуска `/opt/etc/init.d/S99singbox-client`.
5. Регистрацию хуков NDM (`netfilter.d` и `ifstatechanged.d`), чтобы правила маршрутизации переживали переподключения интернета и сбросы фаервола.
6. Первый прогон генерации конфига и запуск службы.

---

## Настройка (`/opt/etc/singbox-client/singbox-client.conf`)

Основные параметры:

```bash
# Ссылка на подписку
SUB_URL="https://raw.githubusercontent.com/st0rer/proxy-sub/main/v2ray.txt"
FALLBACK_URL="http://192.168.1.100:8899/yota.txt"

# Режим: "tun" или "tproxy"
MODE="tun"
TUN_DEV="sb0"
TUN_MTU="1200"

# Фильтрация
EXCLUDE_CC="RU"
REQUIRE_GEMINI="1"
MIN_NODES="4"

# Автообновление
AUTO_REFRESH="1"
CF_WATCHDOG="1"
```

Команды управления:
```bash
/opt/etc/init.d/S99singbox-client status    # статус работы
/opt/etc/init.d/S99singbox-client restart   # перезапуск
/opt/etc/init.d/S99singbox-client refresh   # принудительное обновление нод
/opt/etc/init.d/S99singbox-client check     # валидация конфига
```

Удаление:
```bash
curl -sSL https://raw.githubusercontent.com/st0rer/proxy-sub-builder/main/router/keenetic/uninstall.sh | sh
```

---

## Подводные камни и оптимизации в KeeneticOS 5

1. **Сброс правил iptables демоном NDM:**
   В KeeneticOS фаерволом управляет фирменный сервис NDM. При любом переподключении WAN, Wi-Fi или изменении настроек в веб-интерфейсе NDM полностью очищает цепочки iptables (`iptables -F`).
   *Решение:* скрипт зарегистрирован в `/opt/etc/ndm/netfilter.d/100-singbox.sh`. NDM автоматически вызывает все скрипты из этой папки сразу после пересоздания своих таблиц.
2. **`rp_filter` в ядре Keenetic:**
   Для корректной работы tun-интерфейса `sb0` необходимо отключать строгий reverse path filtering (`net.ipv4.conf.sb0.rp_filter=0`). Это действие также встроено в хук `netfilter.d`.
3. **Безопасная изоляция путей `/opt/`:**
   Корневая файловая система KeeneticOS находится в `SquashFS` (read-only). Все файлы, скрипты, логи и временные данные изолированы строго внутри `/opt/` и `/opt/tmp/`.
4. **Интеграция с доменной маршрутизацией KeeneticOS 5:**
   В 5-й версии Keenetic появилась нативная поддержка маршрутизации по доменам в веб-интерфейсе. Вы можете использовать `sing-box` как прозрачный шлюз (через `sb0` или локальный socks/tproxy), распределяя клиентов через стандартное меню «Приоритеты подключений» Keenetic.
