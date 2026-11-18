# proxy-sub-builder

Сборщик публичной подписки на бесплатные прокси (VLESS / Hysteria2 / Shadowsocks /
anytls / tuic) с проверкой реального трафика и публикацией в GitHub.

Задача не «собрать ссылок», а **не врать клиенту**: в подписке должны быть только
ноды, через которые прямо сейчас идёт трафик, отсортированные по скорости, с
откатом на предыдущий список, если новый оказался хуже.

## Что здесь есть

```
scripts/
  find_free_vpn.py     библиотека: парсинг ссылок → proxy-dict, генерация YAML
  scan_any.py          домашний движок: collect / latency / verify / clean / report
  scrape_web.py        сайты-каталоги ключей (vpnkeys.me и подобные)
  discover_channels.py поиск телеграм-каналов с конфигами (списки из репозиториев, SearXNG)
  tg_scrape.py         сбор ссылок из публичных превью t.me/s/<канал>
  fast_pass.py         быстрый проход по свежим постам между полными циклами
  sb_verify.py         проверка пачки нод одним процессом sing-box (домашний профиль)
  pi_sb_verify.py      то же для малинки: TCP-фаза, три ступени, второй проход
  mobile_push.py       мобильный профиль: отбор кандидатов и прогон на малинке
  publish_sub.py       nodes.txt / v2ray.txt / clash.yaml / index.json + потолки и дедуп
  publish_pub.py       публикация в репозиторий и гист + чтение назад для сверки
  sub_snapshot.py      снимки подписки, самопроверка, откат
  gc_engine.py         уборка кэшей и мусора
  add_verified.py      долить проверенные ноды вручную
  make_sr.py           сборка подписки для Shadowrocket
  xray_gate.py         дополнительный гейт через xray-knife
  refresh_subs.sh      полный домашний цикл (сеть → сбор → проверка → публикация → снимок)
  refresh_yota.sh      мобильный цикл (проверка из сети оператора → публикация)
  mobile_watch.sh      монитор между прогонами: живые ноды + свежесть публикации
  sbgen.py             генератор конфига sing-box из подписки (гео/Gemini-фильтр, своя CF-нода)
  sb_refresh.sh        обновление конфига на роутере: две фазы (замер → публикация)
  cf-watchdog.sh       сторож Google-выхода: ротация селектора gcp по пулу нод вне Cloudflare,
                       триггер — новые строки геоблока в логе Antigravity на Z1 (cf исключён)
  cf_usage.sh          расход суточной квоты Cloudflare Worker через GraphQL
  google-nets.txt      IPv4-префиксы Google (AS15169/36040/43515/19527) для политики pbr
  paths.py             единственное место с путями (всё через переменные окружения)
  lib/env.sh           то же для bash-обвязки
docs/                  архитектура, конвейер, фильтры, публикация, роутер, подводные камни
router/                клиентские пакеты для домашних роутеров (OpenWrt и KeeneticOS 5)
systemd/               юниты и таймеры
env.example            все переменные с пояснениями
```

## Клиентские пакеты для роутеров (OpenWrt и KeeneticOS 5)

В репозитории подготовлены автономные клиентские пакеты, превращающие готовую подписку в отказоустойчивый обход блокировок на роутере:

* **OpenWrt (21.02 / 22.03 / 23.05 / 24+):**
  * Сборка пакета `.ipk`/`.apk` через buildroot (`router/openwrt/Makefile`).
  * Быстрая установка в одну команду: `curl -sSL .../router/openwrt/install-openwrt.sh | sh`
  * Подробная инструкция: [docs/openwrt-package.md](docs/openwrt-package.md).
* **KeeneticOS 5 (Entware):**
  * Полная совместимость со средой Entware на USB или внутренней памяти (UBIFS).
  * Интеграция с NDM-фаерволом (`/opt/etc/ndm/netfilter.d/`) для защиты маршрутов от сброса.
  * Установка в одну команду: `curl -sSL .../router/keenetic/install.sh | sh`
  * Подробная инструкция: [docs/keenetic-package.md](docs/keenetic-package.md).

## Два независимых профиля подписки

Проект формирует и поддерживает **ровно 2 раздельных профиля**:

1. **Домашний (Home)** — для домашнего интернета и широкополосных провайдеров:
   * Файлы: `nodes.txt` (сырые ссылки), `v2ray.txt` (base64), `clash.yaml` (Mihomo / Clash Verge Rev).
   * Проверяется прямо на сервере (N100). В топе — быстрые Hysteria2 и VLESS Reality.
2. **Мобильный (Mobile / Yota)** — для мобильных сетей с агрессивным DPI:
   * Файлы: `nodes-yota.txt`, `yota.txt` (base64), `yota-clash.yaml` (или `clash.yaml` в подкаталоге `sub-yota`).
   * Проверяется **изнутри реальной сети оператора** через удалённую Raspberry Pi (ZeroTier) с модемом Yota.
   * Учитывает специфику мобильного DPI: QUIC на 443 порту заблокирован оператором, поэтому в приоритете VLESS Reality с фрагментацией TLS ClientHello, Shadowsocks 2022, AnyTLS, TUIC и Hy2 на нестандартных портах.

## Как это работает

1. **Сбор (40 000+ нод).** Агрегация специализированных антицензурных списков для РФ (фиды igareck, kort0881 RU-SNI, mahdibland, vlesscollector, Telegram-каналы, каталоги vpnkeys.me). Дедупликация по строке и по параметрам подключения (протокол + сервер + порт + ключ + SNI).
2. **Проверка.** 
   * Дома: url-test через `mihomo` + реальный трафик через `sing-box`.
   * На мобильном: `pi_sb_verify.py` на Raspberry Pi — проверка TCP (с ретраями против джиттера радиоканала), трёхступенчатая загрузка через `sing-box` с контролем размера тела (защита от заглушек оператора), fallback-проход для нестабильных нод, контроль IP выхода.
3. **Отбор и сортировка.** Потолки по типам, дедупликация панелей (одинаковый UUID/панель на разных портах), сортировка по пингу и скорости.
4. **Публикация и доставка.** Атомарное обновление локального HTTP-сервера подписок (`:8899`), репозитория GitHub и GitHub Gist (`yota.txt`), мгновенный снимок (`good/`, `good-yota/`) и автоматический откат при регрессии.
5. **Сборка мусора и контроль памяти.** `gc_engine.py` очищает scratch-файлы, ротирует логи > 5 МБ, чистит историю > 30 дней. Все сервисы ограничены cgroups (`MemoryMax`).

Подробности: [docs/architecture.md](docs/architecture.md),
[docs/pipeline-home.md](docs/pipeline-home.md),
[docs/pipeline-mobile.md](docs/pipeline-mobile.md),
[docs/filters.md](docs/filters.md),
[docs/publishing.md](docs/publishing.md),
[docs/telegram-sources.md](docs/telegram-sources.md),
[docs/operations.md](docs/operations.md).

## Быстрый старт

```bash
git clone https://github.com/<you>/proxy-sub-builder.git
cd proxy-sub-builder
cp env.example .env && $EDITOR .env
export $(grep -v '^#' .env | xargs)

mkdir -p "$PROXY_SUB_HOME/secrets"
echo '<github_pat>' > "$PROXY_SUB_HOME/secrets/gist_token" && chmod 600 "$PROXY_SUB_HOME/secrets/gist_token"

# движки: положите sing-box / mihomo / xray-knife в $PROXY_SUB_BIN
#   https://github.com/SagerNet/sing-box/releases
#   https://github.com/MetaCubeX/mihomo/releases
#   https://github.com/XrayR-project/XrayR (или xray-knife)

python3 scripts/scan_any.py collect      # скачать источники
python3 scripts/scan_any.py latency      # url-test через mihomo
python3 scripts/scan_any.py verify 280   # реальный выход + скорость
python3 scripts/publish_sub.py           # собрать nodes.txt / v2ray.txt / clash.yaml
python3 scripts/publish_pub.py --gist    # опубликовать
```

Полный цикл с проверками и откатом — `scripts/refresh_subs.sh`, мобильный —
`scripts/refresh_yota.sh`.

## Требования

- Linux, Python 3.9+ (только стандартная библиотека).
- `sing-box` (проверка), `mihomo` (url-test и валидация `clash.yaml`),
  `xray-knife` (опциональный гейт).
- `curl`, `flock`, `sshpass` (только если мобильный профиль ходит по паролю).
- Scrapling — опционально, для сайтов с антиботом.

## Чего здесь нет

- Готовых «рабочих ссылок» — они устаревают за часы, смысл проекта в конвейере.
- Ваших секретов: токены, пароли, адреса и ID читаются из окружения и файлов
  `secrets/`, в репозиторий не попадают.

## Лицензия

MIT — см. [LICENSE](LICENSE).
