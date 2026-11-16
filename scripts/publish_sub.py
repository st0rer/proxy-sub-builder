#!/usr/bin/env python3
"""publish_sub.py — превратить проверенный список нод в файлы подписки.

Вход:  $PROXY_SUB_HOME/cache/final.json (или clean_*.txt)
Выход: $PROXY_SUB_HOME/out/sub/nodes.txt   — plain, по одной ссылке в строке
       $PROXY_SUB_HOME/out/sub/v2ray.txt   — base64 (v2rayNG / Hiddify / NekoBox)
       $PROXY_SUB_HOME/out/sub/clash.yaml  — mihomo/clash с группой select
       $PROXY_SUB_HOME/out/sub/index.json  — метаданные (когда обновлено, сколько нод)
"""
import base64, json, os, re, sys, time
import paths  # noqa: E402  (локальные пути проекта)

HOME = os.path.expanduser("~")
CACHE = paths.CACHE
OUT = os.environ.get("SUB_OUT") or os.path.join(paths.OUT, "sub")
SCRIPTS = paths.SCRIPT_DIR
sys.path.insert(0, SCRIPTS)
import find_free_vpn as ffv
import scan_any as sa          # sanitize_proxy/filter_valid: тот же отбор, что в скане


def awrite(path, text):
    """Атомарная запись: tmp + fsync + rename. При обрыве питания старый файл цел."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        dfd = os.open(os.path.dirname(path) or ".", os.O_DIRECTORY)
        os.fsync(dfd)
        os.close(dfd)
    except Exception:
        pass


def conn_id(link):
    """Идентичность подключения — то, чем ноды реально различаются.

    Дедуп по строке ссылки не работает: те же сервер и ключ приходят с разными
    именами и эмодзи, и подписка пухнет копиями. Замер: 165 строк = 44 подключения,
    121 строка была переименованными дублями.
    """
    p = ffv.link_to_proxy(link, "x")
    if not p:
        return link
    ws = p.get("ws-opts") or {}
    grpc = p.get("grpc-opts") or {}
    return (link.split("://")[0].split(":")[0], p.get("server"), int(p.get("port") or 0),
            str(p.get("uuid") or p.get("password") or p.get("auth") or ""),
            (p.get("servername") or p.get("sni") or "").lower(),
            str(ws.get("path") or grpc.get("grpc-service-name") or ""),
            str((ws.get("headers") or {}).get("Host") or "").lower(),
            p.get("network") or "tcp", bool(p.get("tls") or p.get("reality-opts")))


def yaml_str(s):
    s = re.sub(r"[^\x20-\x7e]", "", str(s).split("#")[0])
    return ffv.yaml_str(s)


def yaml_proxy(p):
    lines = [f"  - name: {yaml_str(p['name'])}"]
    for k, v in p.items():
        if k == "name":
            continue
        if isinstance(v, (dict, list)):
            lines.append(f"    {k}:")
            lines.append(ffv.dump_yaml_value(v, 6))
        elif isinstance(v, bool):
            lines.append(f"    {k}: {'true' if v else 'false'}")
        else:
            lines.append(f"    {k}: {yaml_str(v)}")
    return lines


OWNED = os.path.join(paths.SECRETS, "owned_nodes.txt")


SKIP_HOSTS = [h.strip() for h in os.environ.get("SUB_SKIP_HOSTS", "").split(",") if h.strip()]


def owned_links():
    """Свои узлы (CF Worker и т.п.) — они не зависят от скана и должны быть в подписке всегда."""
    if not os.path.exists(OWNED):
        return []
    out = []
    for l in (x.strip() for x in open(OWNED)):
        if not l or l.startswith("#"):
            continue
        # наш собственный воркер-раздатчик подписки прокси не является: он отдаёт
        # страницу на любой запрос, поэтому проверка «204/200» его пропускает
        # Домены, которые не являются прокси (например, свой воркер-раздатчик
        # подписки: он отвечает 200 на любой запрос и проходит первую ступень).
        if any(h and h in l for h in SKIP_HOSTS):
            print("owned: пропускаю ссылку из SUB_SKIP_HOSTS")
            continue
        out.append(l)
    return out


def extra_links():
    """EXTRA_LINKS=<file> — добавить ноды из другого набора (например, прошлые
    проверенные vless, когда текущий прогон собран только по hy2).

    Без явного EXTRA_LINKS берём прошлую подписку: прогон проверяет ~80 нод, и без
    слияния каждый раз публиковались бы только они, а остальные 60 живых нод
    вылетали просто потому, что до них не дошла очередь. Убираем только те, что
    в этом прогоне реально тестировались и умерли.
    """
    f = os.environ.get("EXTRA_LINKS")
    if f and os.path.exists(f):
        return [l.strip() for l in open(f) if l.strip() and not l.startswith("#")]
    if os.environ.get("NO_MERGE") == "1":
        return []
    prev = os.path.join(OUT, "nodes.txt")
    if not os.path.exists(prev):
        return []
    tested_p, alive_p = os.path.join(CACHE, "tested.json"), os.path.join(CACHE, "alive.json")
    tested, alive = set(), set()
    try:
        tested = set(json.load(open(tested_p)))
        alive = set(json.load(open(alive_p)))
    except Exception:
        pass
    # возраст: нода, которую не подтверждали дольше MAX_AGE_H часов, уходит из
    # подписки — иначе мёртвые накапливаются и клиент перебирает трупы
    try:
        hist = json.load(open(os.path.join(CACHE, "history.json")))
    except Exception:
        hist = {}
    max_age = float(os.environ.get("SUB_MAX_AGE_H", "72")) * 3600
    now = time.time()
    keep, aged = [], 0
    for l in (x.strip() for x in open(prev) if x.strip()):
        if l in tested and l not in alive:
            continue          # проверяли в этом прогоне и не ожила
        ts = hist.get(l)
        if ts and now - ts > max_age:
            aged += 1
            continue          # давно не подтверждалась
        keep.append(l)
    if aged:
        print(f"убрано по возрасту (> {max_age/3600:.0f} ч без проверки): {aged}")
    return keep


def load_links():
    # 1) самый свежий clean_*.txt (уже проверен на «идёт напрямую»)
    import glob
    files = sorted(glob.glob(os.path.join(HOME, "vpn_results", "clean_*.txt")))
    if files:
        links = [l.strip() for l in open(files[-1]) if l.strip()]
        if links:
            return links
    for f in ("verified.json", "final.json"):
        p = os.path.join(CACHE, f)
        if os.path.exists(p):
            data = json.load(open(p))
            if isinstance(data, list):
                return [x["link"] if isinstance(x, dict) else x for x in data]
    return []


MIN_NODES = int(os.environ.get("SUB_MIN_NODES", "10"))


def prev_count():
    """Сколько было нод в прошлой подписке — по уникальным подключениям.

    Сравнивать сырые строки нельзя: после включения дедупа по подключению
    подписка законно сжимается втрое, и гвард деградации заблокировал бы публикацию.
    """
    for f in ("nodes.txt",):
        p = os.path.join(OUT, f)
        if os.path.exists(p):
            links = [l.strip() for l in open(p) if l.strip()]
            if links:
                return len({conn_id(l) for l in links})
    try:
        return int(json.load(open(os.path.join(OUT, "index.json")))["count"])
    except Exception:
        return 0


def main():
    owned = owned_links()
    # Профиль mobile: источник — результат проверки с малинки (сеть Yota), а не
    # домашний clean_*.txt. Поэтому и квоты, и порог скорости задаются отдельно.
    src = os.environ.get("SUB_FROM")
    if src:
        rows = json.load(open(src))
        links = [r["link"] for r in rows if r.get("delay")]
        links = [l for l in links if re.match(r"^(vless|vmess|hy2|hysteria2|hysteria|trojan|ss|ssr|tuic|anytls|juicity)://", l)]
        # скорость 0.0 = «не мерили»: ключ None, иначе MIN_SPEED выбросит живую ноду
        # 0.0 при speed_measured=True — «мерили и не поехало»: такую ноду выбрасываем.
        # Раньше 0.0 превращался в None («не мерили») и мёртвая нода попадала в подписку.
        speeds = {}
        for r in rows:
            if r.get("speed_measured"):
                speeds[r["link"]] = float(r.get("speed") or 0.0)
            elif r.get("speed") is not None:
                speeds[r["link"]] = float(r["speed"])
            else:
                speeds[r["link"]] = None
        print(f"источник: {os.path.basename(src)} ({len(links)} живых из {len(rows)})")
    else:
        links = load_links() + extra_links()
    links = [l for l in links if re.match(r"^(vless|vmess|hy2|hysteria2|hysteria|trojan|ss|ssr|tuic|anytls|juicity)://", l)]
    # порядок в подписке = порядок в клиенте: быстрые вперёд (скорость из verified.json)
    speeds = speeds if src else {}
    vf = os.path.join(CACHE, "verified.json")
    if not src and os.path.exists(vf):
        try:
            for v in json.load(open(vf)):
                if isinstance(v, dict) and v.get("link"):
                    speeds[v["link"]] = float(v.get("speed_MBps") or 0)
        except Exception:
            pass
    # hy2 первыми: на мобильных операторах (Yota/МегаФон) VLESS режут по отпечатку,
    # а QUIC живёт — клиенту нужен рабочий узел в начале списка, не самый быстрый vless.
    def is_hy2(l):
        return l.startswith(("hy2://", "hysteria2://", "hysteria://"))
    # ноды, которые отдали выходной IP, но нулевую скорость (0.0 МБ/с), — мусор:
    # соединение есть, трафика нет. Из проверенных такие выбрасываем, а незнакомые
    # (пришедшие через EXTRA_LINKS) оставляем — у них замера просто нет.
    MIN_SPEED = float(os.environ.get("SUB_MIN_SPEED", "0.1"))
    links = [l for l in links if speeds.get(l, None) is None or speeds.get(l, 0) >= MIN_SPEED]
    # Порядок в списке = приоритет в клиенте. Дома hy2 впереди (TCP там режут),
    # на Yota наоборот: QUIC не проходит, а vless с рабочим SNI живёт.
    if os.environ.get("SUB_ORDER") == "tcp":
        rank = lambda l: 0 if l.startswith("vless") else 1 if l.startswith("trojan") else 2 if l.startswith("ss") else 3
        links.sort(key=lambda l: (rank(l), -(speeds.get(l) or 0)))
    else:
        links.sort(key=lambda l: (is_hy2(l), speeds.get(l) or 0), reverse=True)

    seen, uniq = set(), []
    for l in links:
        cid = conn_id(l)
        if cid in seen:
            continue
        seen.add(cid)
        uniq.append(l)
    if len(uniq) != len(links):
        print(f"дедуп по подключению: {len(links)} -> {len(uniq)}")
    links = uniq
    # Потолок на протокол: подписка не должна расти бесконечно (клиент перебирает
    # мёртвых), но и не должна стать чисто ss — hy2 на мобильных решает.
    CAPS = {"hy2": 45, "vless": 60, "ss": 60, "trojan": 20, "vmess": 20,
            "ssr": 15, "tuic": 15, "anytls": 10, "hysteria": 10}
    if os.environ.get("SUB_CAPS"):
        CAPS.update({k: int(v) for k, v in (x.split("=") for x in os.environ["SUB_CAPS"].split(","))})
    fam = lambda l: "hy2" if is_hy2(l) else l.split("://")[0]
    kept, cnt = [], {}
    for l in links:
        f = fam(l)
        if cnt.get(f, 0) >= CAPS.get(f, 30):
            continue
        cnt[f] = cnt.get(f, 0) + 1
        kept.append(l)
    if len(kept) < len(links):
        print(f"потолок по протоколу: {len(links)} -> {len(kept)} {dict(cnt)}")
    links = kept


    # Второй фильтр настоящим Xray-core: клиент пользователя именно на нём,
    # и 5-10 % нод, живых для mihomo, в Xray не поднимаются.
    if os.environ.get("SKIP_XRAY_GATE") != "1":
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import xray_gate
            gated, bad = xray_gate.gate(links)
            if bad:
                print(f"xray-фильтр отбросил {len(bad)}: " + "; ".join(f"{b[0][:22]}…({b[1][:28]})" for b in bad[:3]))
            links = gated
        except Exception as e:
            print(f"xray-фильтр недоступен ({type(e).__name__}) — публикую после mihomo")

    links = owned + [l for l in links if l not in owned]
    os.makedirs(OUT, exist_ok=True)
    if not links:
        print("нет нод — нечего публиковать, старый список не трогаю")
        return 2
    # Защита от деградации: не перезаписывать рабочий список пустым/огрызком.
    # Иначе упавший скан (или блокировка всех источников) тихо портит подписку.
    prev = prev_count()
    if len(links) < MIN_NODES:
        print(f"только {len(links)} нод (< {MIN_NODES}) — публикацию пропускаю, оставляю прошлый список ({prev})")
        return 3
    if prev and len(links) < prev * 0.5:
        # Защита от деградации спасает от пустого списка, но мешает, когда старый
        # список уже мёртв: 16.11.2026 из 13 нод мобильной подписки проверку
        # проходили 3. Если прогон честно проверил старые ноды и они мертвы,
        # вызывающий ставит SUB_ALLOW_SHRINK=1 — тогда публикуем проверенный минимум.
        if os.environ.get("SUB_ALLOW_SHRINK") == "1":
            print(f"сжатие {prev} -> {len(links)} разрешено: старые ноды проверены и мертвы")
        else:
            print(f"деградация: {len(links)} против {prev} в прошлый раз — пропускаю публикацию")
            return 3

    awrite(os.path.join(OUT, os.environ.get("SUB_NODES", "nodes.txt")), "\n".join(links) + "\n")
    awrite(os.path.join(OUT, os.environ.get("SUB_V2RAY", "v2ray.txt")),
           base64.b64encode("\n".join(links).encode()).decode())

    # отдельная hy2-only подписка: клиенту на мобильном операторе не нужно
    # перебирать vless, который там всё равно мёртв
    hy2_only = [l for l in links if is_hy2(l)]
    # в мобильном профиле hy2 не публикуем вовсе (QUIC на Yota не проходит) —
    # пустые файлы в каталоге только путают клиент
    if not hy2_only and os.environ.get("SUB_CAPS"):
        hy2_only = []
    if hy2_only or not os.environ.get("SUB_CAPS"):
        awrite(os.path.join(OUT, "hy2_nodes.txt"), "\n".join(hy2_only) + "\n")
        awrite(os.path.join(OUT, "hy2.txt"), base64.b64encode("\n".join(hy2_only).encode()).decode())

    proxies = []
    for i, l in enumerate(links):
        p = ffv.link_to_proxy(l, f"node-{i + 1:02d}-{l.split('://')[0]}")
        p = sa.sanitize_proxy(p) if p else None   # иначе одна битая нода ломает clash.yaml целиком
        if p:
            p["port"] = int(p["port"])
            proxies.append(p)
    proxies = sa.filter_valid(proxies) if proxies else []
    body = ["mixed-port: 7890", "allow-lan: false", "mode: rule", "log-level: info",
            "ipv6: false", "", "proxies:"]
    for p in proxies:
        body += yaml_proxy(p)
    # AUTO — самый быстрый по замеру; FALLBACK — страховка: если выбранная
    # нода умерла между проверками, клиент падает на следующую, а не в таймаут.
    TEST_URL = "'https://www.gstatic.com/generate_204'"
    body += ["", "proxy-groups:",
             "  - name: AUTO", "    type: url-test",
             f"    url: {TEST_URL}",
             "    interval: 120", "    tolerance: 80", "    lazy: false", "    proxies:"]
    body += ["      - " + yaml_str(p["name"]) for p in proxies]
    body += ["  - name: FALLBACK", "    type: fallback",
             f"    url: {TEST_URL}",
             "    interval: 120", "    proxies:",
             "      - AUTO"]
    body += ["      - " + yaml_str(p["name"]) for p in proxies]
    body += ["", "rules:",
             "  - DOMAIN-SUFFIX,local,DIRECT",
             "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
             "  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
             "  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
             "  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
             # российские сайты — напрямую: через CF они медленнее, а банки/госуслуги вообще режут
             "  - GEOIP,RU,DIRECT",
             "  - GEOSITE,category-ru,DIRECT",
             "  - MATCH,FALLBACK"]
    awrite(os.path.join(OUT, "clash.yaml"), "\n".join(body) + "\n")

    awrite(os.path.join(OUT, "index.json"), json.dumps(
        {"updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "count": len(links),
         "unique_connections": len({conn_id(l) for l in links}),
         "files": ["nodes.txt", "v2ray.txt", "clash.yaml", "hy2_nodes.txt", "hy2.txt"],
         "hy2_count": len(hy2_only)}, indent=1))
    print(f"опубликовано {len(links)} нод -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
