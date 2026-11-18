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


def is_hy2(l):
    """Определяет, относится ли ссылка к семейству Hysteria 2."""
    return l.startswith(("hy2://", "hysteria2://", "hysteria://"))


def cc_to_flag(cc):
    """Преобразует двухбуквенный ISO-код страны в эмодзи-флаг."""
    if cc and len(cc) == 2 and cc.isalpha():
        return chr(0x1F1E6 + ord(cc[0].upper()) - ord('A')) + chr(0x1F1E6 + ord(cc[1].upper()) - ord('A'))
    return ""


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


def prev_count(out_dir=None):
    """Сколько было нод в прошлой подписке — по уникальным подключениям.

    Сравнивать сырые строки нельзя: после включения дедупа по подключению
    подписка законно сжимается втрое, и гвард деградации заблокировал бы публикацию.
    """
    target_out = out_dir or os.environ.get("SUB_OUT") or OUT
    sub_nodes_name = os.environ.get("SUB_NODES", "nodes.txt")
    for f in (sub_nodes_name, "nodes.txt"):
        p = os.path.join(target_out, f)
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="ignore") as fp:
                links = [l.strip() for l in fp if l.strip()]
            if links:
                return len({conn_id(l) for l in links})
    try:
        with open(os.path.join(target_out, "index.json"), encoding="utf-8") as fp:
            return int(json.load(fp)["count"])
    except Exception:
        return 0


def main():
    owned = owned_links()
    req_gemini = os.environ.get("SUB_REQUIRE_GEMINI") == "1" or "--require-gemini" in sys.argv
    # Профиль mobile: источник — результат проверки с малинки (сеть Yota), а не
    # домашний clean_*.txt. Поэтому и квоты, и порог скорости задаются отдельно.
    src = os.environ.get("SUB_FROM")
    if src:
        with open(src, encoding="utf-8") as fp:
            rows = json.load(fp)
        if req_gemini:
            total_live = len([r for r in rows if r.get("delay")])
            rows = [r for r in rows if r.get("delay") and r.get("gemini") == "ok"]
            print(f"фильтр Gemini/Antigravity: {total_live} -> {len(rows)} нод")
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
        if req_gemini:
            geo_f = os.environ.get("GEO_PATH") or os.path.join(CACHE, "geo.json")
            if os.path.exists(geo_f):
                try:
                    geo = json.load(open(geo_f))
                    def is_geo_gemini_ok(l):
                        pr = ffv.link_to_proxy(l, "x")
                        if not pr:
                            return False
                        k = f"{pr.get('type')}|{pr.get('server')}|{pr.get('port')}"
                        return geo.get(k, {}).get("gemini") == "ok"
                    before = len(links)
                    links = [l for l in links if is_geo_gemini_ok(l)]
                    print(f"фильтр Gemini/Antigravity (geo.json): {before} -> {len(links)} нод")
                except Exception as e:
                    print(f"ошибка чтения geo.json для Gemini фильтра: {e}")
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
    # ноды, которые отдали выходной IP, но нулевую скорость (0.0 МБ/с), — мусор:
    # соединение есть, трафика нет. Из проверенных такие выбрасываем, а незнакомые
    # (пришедшие через EXTRA_LINKS) оставляем — у них замера просто нет.
    min_speed_env = os.environ.get("SUB_MIN_SPEED")
    min_speed = float(min_speed_env) if min_speed_env is not None else 0.0
    if min_speed > 0:
        links = [l for l in links if speeds.get(l, None) is None or speeds.get(l, 0) >= min_speed]
    # Порядок в списке = приоритет в клиенте. Дома hy2/tuic впереди (TCP там режут),
    # на Yota наоборот: QUIC не проходит, а vless с рабочим SNI живёт.
    if os.environ.get("SUB_ORDER") == "tcp":
        rank = lambda l: 0 if l.startswith("vless") else 1 if l.startswith("trojan") else 2 if l.startswith("ss") else 3
        links.sort(key=lambda l: (rank(l), -(speeds.get(l) or 0)))
    else:
        def proto_priority(l):
            if is_hy2(l) or l.startswith("tuic://"):
                return 2
            elif l.startswith("vless://"):
                return 1
            return 0
        links.sort(key=lambda l: (proto_priority(l), speeds.get(l) or 0), reverse=True)

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
    # Потолок на протокол: расширены квоты для устойчивых современных протоколов (hy2, vless, tuic)
    CAPS = {"hy2": 60, "vless": 80, "ss": 60, "trojan": 25, "vmess": 20,
            "ssr": 15, "tuic": 30, "anytls": 15, "hysteria": 10}
    if os.environ.get("SUB_CAPS"):
        CAPS.update({k: int(v) for k, v in (x.split("=") for x in os.environ["SUB_CAPS"].split(","))})
    # Потолок на панель: одинаковый ключ = один сервер с разными входными IP.
    # Подписка, собранная из одной панели, умирает целиком вместе с ней.
    MAX_PER_PANEL = int(os.environ.get("SUB_MAX_PER_PANEL", "3"))
    panel_seen = {}
    fam = lambda l: "hy2" if is_hy2(l) else l.split("://")[0]
    kept, cnt = [], {}
    for l in links:
        f = fam(l)
        if cnt.get(f, 0) >= CAPS.get(f, 30):
            continue
        pr = ffv.link_to_proxy(l, "x") or {}
        pk = (f, str(pr.get("uuid") or pr.get("password") or pr.get("auth") or ""))
        if pk[1] and panel_seen.get(pk, 0) >= MAX_PER_PANEL:
            continue
        panel_seen[pk] = panel_seen.get(pk, 0) + 1
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

    out_dir = os.environ.get("SUB_OUT") or OUT
    min_nodes = int(os.environ.get("SUB_MIN_NODES", "10"))
    links = owned + [l for l in links if l not in owned]
    os.makedirs(out_dir, exist_ok=True)
    if not links:
        print("нет нод — нечего публиковать, старый список не трогаю")
        return 2
    # Защита от деградации: не перезаписывать рабочий список пустым/огрызком.
    # Иначе упавший скан (или блокировка всех источников) тихо портит подписку.
    prev = prev_count(out_dir)
    if len(links) < min_nodes:
        print(f"только {len(links)} нод (< {min_nodes}) — публикацию пропускаю, оставляю прошлый список ({prev})")
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

    awrite(os.path.join(out_dir, os.environ.get("SUB_NODES", "nodes.txt")), "\n".join(links) + "\n")
    awrite(os.path.join(out_dir, os.environ.get("SUB_V2RAY", "v2ray.txt")),
           base64.b64encode("\n".join(links).encode()).decode())

    # отдельная hy2-only подписка: клиенту на мобильном операторе не нужно
    # перебирать vless, который там всё равно мёртв
    hy2_only = [l for l in links if is_hy2(l)]
    # в мобильном профиле hy2 не публикуем вовсе (QUIC на Yota не проходит) —
    # пустые файлы в каталоге только путают клиент
    if not hy2_only and os.environ.get("SUB_CAPS"):
        hy2_only = []
    if hy2_only or not os.environ.get("SUB_CAPS"):
        awrite(os.path.join(out_dir, "hy2_nodes.txt"), "\n".join(hy2_only) + "\n")
        awrite(os.path.join(out_dir, "hy2.txt"), base64.b64encode("\n".join(hy2_only).encode()).decode())

    # протокольные разделы: VLESS, Reality, Shadowsocks
    vless_only = [l for l in links if l.startswith("vless://")]
    if vless_only:
        awrite(os.path.join(out_dir, "vless_nodes.txt"), "\n".join(vless_only) + "\n")
        awrite(os.path.join(out_dir, "vless.txt"), base64.b64encode("\n".join(vless_only).encode()).decode())

    reality_only = [l for l in vless_only if "pbk=" in l or "security=reality" in l]
    if reality_only:
        awrite(os.path.join(out_dir, "reality_nodes.txt"), "\n".join(reality_only) + "\n")
        awrite(os.path.join(out_dir, "reality.txt"), base64.b64encode("\n".join(reality_only).encode()).decode())

    ss_only = [l for l in links if l.startswith("ss://")]
    if ss_only:
        awrite(os.path.join(out_dir, "ss_nodes.txt"), "\n".join(ss_only) + "\n")
        awrite(os.path.join(out_dir, "ss.txt"), base64.b64encode("\n".join(ss_only).encode()).decode())

    cc_map = {}
    try:
        vf_file = os.path.join(CACHE, "verified.json")
        if os.path.exists(vf_file):
            with open(vf_file, encoding="utf-8") as fp:
                for v in json.load(fp):
                    if isinstance(v, dict) and v.get("link") and v.get("cc"):
                        cc_map[v["link"]] = v["cc"].strip().upper()
    except Exception:
        pass

    proxies = []
    for i, l in enumerate(links):
        proto = l.split("://")[0]
        cc = cc_map.get(l, "")
        flag = cc_to_flag(cc)
        name = f"{flag} {cc} {i + 1:02d} [{proto}]" if flag else f"node-{i + 1:02d}-{proto}"
        p = ffv.link_to_proxy(l, name)
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
    awrite(os.path.join(out_dir, "clash.yaml"), "\n".join(body) + "\n")

    pub_files = ["nodes.txt", "v2ray.txt", "clash.yaml", "hy2_nodes.txt", "hy2.txt"]
    if vless_only: pub_files += ["vless_nodes.txt", "vless.txt"]
    if reality_only: pub_files += ["reality_nodes.txt", "reality.txt"]
    if ss_only: pub_files += ["ss_nodes.txt", "ss.txt"]

    awrite(os.path.join(out_dir, "index.json"), json.dumps(
        {"updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "count": len(links),
         "unique_connections": len({conn_id(l) for l in links}),
         "gemini_only": req_gemini,
         "files": pub_files,
         "vless_count": len(vless_only),
         "reality_count": len(reality_only),
         "ss_count": len(ss_only),
         "hy2_count": len(hy2_only)}, indent=1))
    print(f"опубликовано {len(links)} нод -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
