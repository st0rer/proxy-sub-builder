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
  paths.py             единственное место с путями (всё через переменные окружения)
  lib/env.sh           то же для bash-обвязки
docs/                  архитектура, конвейер, фильтры, публикация, подводные камни
systemd/               юниты и таймеры
env.example            все переменные с пояснениями
```

## Как это работает

1. **Сбор.** GitHub-списки + сайты-каталоги + публичные превью телеграм-каналов.
   Ссылки дедуплицируются по строке, затем по «идентичности подключения»
   (протокол + сервер + порт + ключ + SNI + path + host).
2. **Проверка.** Каждая нода поднимается отдельным outbound в sing-box, наружу
   отдаётся socks-порт. Проверка идёт **тем же ядром, что у клиента**, тремя
   ступенями URL, с повтором и контролем размера тела.
3. **Отбор.** Потолки по протоколам, порог скорости, дедуп по подключению,
   сортировка: быстрые первыми (дома — hy2 вперёд, на мобильном — vless).
4. **Публикация.** Атомарная запись, публикация в репозиторий и гист, **чтение
   назад** и сверка, снимок, при расхождении — откат.

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
