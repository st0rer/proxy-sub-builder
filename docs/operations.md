# Эксплуатация

## Расписание (systemd-user)

| таймер | когда | что делает |
|---|---|---|
| `subs-refresh.timer` | `00/6:30` | полный домашний цикл |
| `subs-yota.timer` | 02:30, 10:30, 18:30 UTC | мобильная подписка |
| `fast-pass.timer` | `00/3:20` | быстрый проход по свежим постам |
| `mobile-watch.timer` | каждые 30 мин | монитор мобильной подписки |

Установка:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/*.service systemd/*.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now subs-refresh.timer subs-yota.timer fast-pass.timer mobile-watch.timer
journalctl --user -u subs-refresh.service -n 50
```

Юниты читают `EnvironmentFile=%h/.proxy-sub/env` — положите туда `env.example`
с заполненными значениями.

## Мониторинг

Два независимых наблюдателя:

- **дома** — `xray-checker` (Docker или systemd), порт 2112, интервал 600 с;
- **в мобильной сети** — `xray-checker` на малинке, порт 2113, интервал 900 с,
  `MemoryMax=180M`, `CPUQuota=40%`.

`mobile_watch.sh` читает метрики малинки и сравнивает публикацию с локальным
файлом. Тревоги:

- живых меньше 4 **и** меньше 40 %;
- публикация старше 8 часов;
- число нод в гисте не совпадает с локальным.

Проверяя метрики, помните: **xray-checker не умеет hy2 / anytls / tuic** — для
него они всегда нулевые. Не делайте по нему вывод о всей подписке.

## Здоровье железа

Малинка 3B в мобильной сети работает на пределе: `vcgencmd get_throttled`
показывает `0x50000` — не хватает питания (нужен блок 5 В / 2.5 А). Симптом —
случайные отвалы SSH и провалы проверки.

Проверки перед прогоном: `free -m` (нужно >120 МБ свободных, иначе прогон
отменяется), `df -h /`, температура, `pgrep -af 'sing-box run'` (осиротевшие
процессы убиваются на старте).

## Бюджет и лимиты

- мобильный трафик: `BUDGET_MB=12` на прогон, ~30 МБ в сутки;
- домашний `verify`: 280 нод, скорость у 10 самых быстрых;
- диск: `gc_engine.py` чистит старые `clean_*.txt` и кэш гео-баз.

## Что смотреть, когда «ноды кончились»

1. `~/vpn_results/refresh.log` и `refresh_yota.log` — где остановилось.
2. `mobile_results.json` / `verified.json` — сколько живых и на какой ступени.
3. `xray-checker` метрики — что видят клиенты.
4. Сверить gist и локальный файл — публикация могла не дойти.
5. Проверить, что IP сервера с подпиской не заблокирован у оператора.

## Переменные, которые чаще всего нужны

```bash
SUB_CAPS="vless=40,hy2=15,ss=10,trojan=0,vmess=0"
SUB_ORDER=tcp
SUB_MIN_SPEED=0.03
SUB_MIN_NODES=3
SUB_ALLOW_SHRINK=1
BUDGET_MB=12
SPEED_TOP=10
NO_RECOVERY=1        # отключить второй проход (быстрее, но теряет ~28 % живых)
REQUIRE_EXIT_IP=1    # строгий режим: без ответа ipify нода отбрасывается
```
