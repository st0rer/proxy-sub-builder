#!/usr/bin/env python3
"""mobile_push.py — отбор нод, проверенных ИЗ СЕТИ YOTA (малинка за Keenetic).

Домашний скан видит один DPI, мобильный — другой: на Yota режут по отпечатку TLS
и по адресу иначе. Поэтому подписка для телефона проверяется отдельно, с малинки,
которая сидит на USB-модеме Keenetic.

Что делает:
  1. берёт пул (alive.json — ноды, у которых уже ответил порт),
  2. выбирает кандидатов: hy2 первыми, потом vless, потом ss; не больше 2 с адреса,
  3. собирает конфиг mihomo со socks-слушателями (udp: true — нужен для проверки UDP),
  4. заливает конфиг и скрипт на малинку, запускает проверку, забирает результат,
  5. кладёт $PROXY_SUB_HOME/out/mobile_results.json.

Трафик мобильный, поэтому бюджет жёсткий: задержка ~6 КБ/нода, скорость 1 МБ и
только для SPEED_TOP лучших. Типовой прогон на 60 нод ≈ 12–14 МБ.
"""
import json
import os
import socket
import subprocess
import time
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
import paths  # noqa: E402  (локальные пути проекта)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_free_vpn as ffv
import scan_any as sa
import sb_verify as sbv

PI = os.environ.get("PI_HOST") or paths.secret("pi_host", "")
PI_PASS = os.environ.get("PI_PASS") or paths.secret("pi_pass", "")
WORK = "/run/vpntest"          # tmpfs на малинке: SD-карту не изнашиваем
OUT = os.path.join(paths.OUT, "mobile_results.json")
CACHE = paths.CACHE
N_HY2 = int(os.environ.get("PI_N_HY2", "60"))
N_VLESS = int(os.environ.get("PI_N_VLESS", "120"))
N_SS = int(os.environ.get("PI_N_SS", "20"))
N_ANYTLS = int(os.environ.get("PI_N_ANYTLS", "30"))
N_TUIC = int(os.environ.get("PI_N_TUIC", "10"))
N_TROJAN = int(os.environ.get("PI_N_TROJAN", "40"))
N_POOL = int(os.environ.get("PI_N_POOL", "120"))  # добор из пула
N_SIB = int(os.environ.get("PI_N_SIB", "60"))     # адреса рабочих панелей (выход 45% против 8%)
PER_ADDR = 2
PER_NET = int(os.environ.get("PI_PER_NET", "3"))  # нод с одной /24: Yota режет диапазонами целиком
API_PORT = 9099
BASE_PORT = 21000
FAST_TCP_PRECHECK = os.environ.get("FAST_TCP_PRECHECK", "1") == "1"


def _net24(host):
    """Первые три октета IPv4 — Yota блокирует подсети, а не отдельные адреса."""
    try:
        import ipaddress
        return str(ipaddress.ip_network(host + "/24", strict=False))
    except Exception:
        return host


def diverse_by_net(links, per_net=None):
    """Не больше per_net нод с одной /24: иначе пул забивается одной подсетью,
    которую Yota режет целиком, и половина кандидатов мертва ещё до отправки."""
    per_net = PER_NET if per_net is None else per_net
    seen = {}
    out = []
    for l in links:
        a = sa._host_of(l)
        key = _net24(a[0]) if a else l
        if seen.get(key, 0) >= per_net:
            continue
        seen[key] = seen.get(key, 0) + 1
        out.append(l)
    return out


def filter_live_tcp(links, timeout=1.6, max_workers=48):
    """Быстрая проверка доступности TCP-порта прямо на N100 перед отправкой на малинку.
    Отсеивает ноды с закрытыми портами за 2-4 секунды, избавляя слабый CPU Raspberry Pi 3
    от сотен секунд бессмысленных проверок мертвого пула в фазе RECOVERY.
    """
    if not FAST_TCP_PRECHECK or not links:
        return list(links)

    def probe_one(l):
        proto = l.split("://")[0]
        if proto in ("hy2", "hysteria2", "hysteria", "tuic"):
            return l
        a = sa._host_of(l)
        if not a:
            return None
        try:
            with socket.create_connection((a[0], int(a[1])), timeout=timeout):
                return l
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        return [l for l in ex.map(probe_one, links) if l is not None]


def ssh(cmd, input_bytes=None, timeout=900):
    args = ["sshpass", "-p", PI_PASS, "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "PubkeyAuthentication=no", "-o", "ConnectTimeout=10", PI, cmd]
    return subprocess.run(args, input=input_bytes, capture_output=True, timeout=timeout)


def mobile_history_path():
    return os.path.join(CACHE, "mobile_history.json")


def pick_candidates():
    # 1. Извлекаем проверенные ноды из verified.json и исключаем RU-выходы (для Gemini они гарантированный 403)
    verif_f = os.path.join(CACHE, "verified.json")
    known_ru = set()
    known_blocked_ips = set()
    verified_non_ru = []
    if os.path.exists(verif_f):
        try:
            with open(verif_f, encoding="utf-8") as f:
                verified = json.load(f)
            for v in verified:
                cc = (v.get("cc") or "").upper()
                link = v.get("link", "")
                if cc in ("RU", "BY", "IR", "KP", "CN"):
                    if link:
                        known_ru.add(link)
                    a = sa._host_of(link)
                    if a:
                        known_blocked_ips.add(a[0])
                elif link:
                    verified_non_ru.append(v)
        except Exception:
            pass

    alive_f = os.path.join(CACHE, "alive.json")
    if os.path.exists(alive_f):
        try:
            with open(alive_f, encoding="utf-8") as f:
                alive = json.load(f)
        except Exception:
            alive = {}
    else:
        alive = {}
    is_h2 = lambda l: l.startswith(("hy2://", "hysteria2://", "hysteria://"))
    fam = lambda l: "hy2" if is_h2(l) else l.split("://")[0]
    groups = {"hy2": [], "vless": [], "ss": [], "anytls": [], "tuic": [], "trojan": []}

    # Добавляем сначала verified_non_ru (с подтвержденной низкой задержкой и чистым гео)
    for v in verified_non_ru:
        l = v.get("link")
        if not l or l in known_ru:
            continue
        a = sa._host_of(l)
        if a and a[0] in known_blocked_ips:
            continue
        f = fam(l)
        if f in groups:
            groups[f].append((l, v.get("delay", 100)))

    # Затем добавляем ноды из alive.json (если их ещё нет в groups)
    seen_in_groups = {item[0] for g in groups.values() for item in g}
    for link, delay in sorted(alive.items(), key=lambda kv: kv[1]):
        if link in known_ru or link in seen_in_groups:
            continue
        a = sa._host_of(link)
        if a and a[0] in known_blocked_ips:
            continue
        f = fam(link)
        if f in groups:
            groups[f].append((link, delay))
            seen_in_groups.add(link)

    def vless_pri(item):
        link, delay = item
        # Reality и RU-SNI первыми, так как они лучше всего проходят ТСПУ мобильных сетей
        is_reality = ("pbk=" in link or "security=reality" in link)
        is_ru_sni = any(dom in link.lower() for dom in (".ru", "vk.com", "yandex.ru", "mail.ru", "gosuslugi.ru", "storage.yandex.net", "ads.x5.ru", "max.ru"))
        a = sa._host_of(link)
        non_std_port = (a[1] != 443) if a else False
        pri = 0
        if is_reality: pri += 3
        if is_ru_sni: pri += 4
        if non_std_port: pri += 2
        return (-pri, delay)

    def hy2_pri(item):
        link, delay = item
        # На Yota порт UDP 443 режется оператором: приоритет non-443 и obfs
        a = sa._host_of(link)
        port = a[1] if a else 443
        non_std_port = (port != 443)
        has_obfs = "obfs=" in link or "salamander" in link
        pri = 0
        if non_std_port: pri += 5
        if has_obfs: pri += 4
        if not non_std_port and not has_obfs: pri -= 10
        return (-pri, delay)

    groups["vless"].sort(key=vless_pri)
    groups["hy2"].sort(key=hy2_pri)

    picked, per_addr = [], {}
    for f, budget in (("anytls", N_ANYTLS), ("hy2", N_HY2), ("vless", N_VLESS),
                      ("trojan", N_TROJAN), ("ss", N_SS), ("tuic", N_TUIC)):
        taken = 0
        for link, delay in groups[f]:
            a = sa._host_of(link)
            if not a:
                continue
            if per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(link)
            taken += 1
            if taken >= budget:
                break

    # Добор VLESS и Shadowsocks из all_links.json:
    # alive.json часто содержит мало TCP-нод (большинство hy2).
    # В all_links.json лежат тысячи Reality VLESS и SS.
    # Проверяем TCP-порт на N100 и добираем до квоты!
    pool_f = os.path.join(CACHE, "all_links.json")
    if os.path.exists(pool_f):
        try:
            with open(pool_f, encoding="utf-8") as f:
                pool = json.load(f)
        except Exception:
            pool = []
    else:
        pool = []

    tested_f = os.path.join(CACHE, "mobile_tested.json")
    if os.path.exists(tested_f):
        try:
            with open(tested_f, encoding="utf-8") as f:
                mtested = json.load(f)
        except Exception:
            mtested = {}
    else:
        mtested = {}
    now_ts = int(time.time())
    # 2 часа локаута вместо 48 ч, чтобы не морить пул голодом при разовых мобильных сбоях
    mtested = {k: v for k, v in mtested.items() if now_ts - v < 7200}

    picked_set = set(picked)

    # 0) Добор Hysteria 2 из пула (только non-443 или obfs!)
    hy2_count = sum(1 for l in picked if l.startswith(("hy2://", "hysteria2://", "hysteria://")))
    if hy2_count < N_HY2 and pool:
        needed = N_HY2 - hy2_count
        cands = []
        for l in pool:
            if not l.startswith(("hy2://", "hysteria2://", "hysteria://")) or l in picked_set or l in known_ru or l in mtested:
                continue
            a = sa._host_of(l)
            if not a or a[0] in known_blocked_ips or per_addr.get(a, 0) >= PER_ADDR:
                continue
            port = a[1] if a else 443
            non_std_port = (port != 443)
            has_obfs = "obfs=" in l or "salamander" in l
            if not non_std_port and not has_obfs:
                continue
            pri = (3 if non_std_port and has_obfs else (2 if non_std_port else (1 if has_obfs else 0)))
            cands.append((l, pri))
        cands.sort(key=lambda x: -x[1])
        for l, _ in cands:
            a = sa._host_of(l)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(l)
            picked_set.add(l)
            hy2_count += 1
            if hy2_count >= N_HY2:
                break

    # 1) Добор VLESS (Reality с RU-SNI и non-443 в высшем приоритете)
    vless_count = sum(1 for l in picked if l.startswith("vless://"))
    if vless_count < N_VLESS and pool:
        needed = N_VLESS - vless_count
        cands = []
        for l in pool:
            if not l.startswith("vless://") or l in picked_set or l in known_ru or l in mtested:
                continue
            a = sa._host_of(l)
            if not a or a[0] in known_blocked_ips or per_addr.get(a, 0) >= PER_ADDR:
                continue
            cands.append(l)

        def vless_cand_pri(l):
            is_reality = ("pbk=" in l or "security=reality" in l)
            is_ru = any(dom in l.lower() for dom in (".ru", "vk.com", "yandex.ru", "mail.ru", "gosuslugi.ru", "storage.yandex.net", "ads.x5.ru", "max.ru"))
            a = sa._host_of(l)
            is_non_443 = (a[1] != 443) if a else False
            pri = 0
            if is_reality: pri += 10
            if is_ru: pri += 20
            if is_non_443: pri += 5
            return -pri

        cands.sort(key=vless_cand_pri)
        check_batch = cands[:needed * 4]
        live_tcp = filter_live_tcp(check_batch)
        for l in live_tcp:
            a = sa._host_of(l)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(l)
            picked_set.add(l)
            vless_count += 1
            if vless_count >= N_VLESS:
                break

    # 2) Добор Trojan из пула
    tr_count = sum(1 for l in picked if l.startswith("trojan://"))
    if tr_count < N_TROJAN and pool:
        needed = N_TROJAN - tr_count
        cands = []
        for l in pool:
            if not l.startswith("trojan://") or l in picked_set or l in known_ru or l in mtested:
                continue
            a = sa._host_of(l)
            if not a or a[0] in known_blocked_ips or per_addr.get(a, 0) >= PER_ADDR:
                continue
            cands.append(l)
        check_batch = cands[:needed * 3]
        live_tcp = filter_live_tcp(check_batch)
        for l in live_tcp:
            a = sa._host_of(l)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(l)
            picked_set.add(l)
            tr_count += 1
            if tr_count >= N_TROJAN:
                break

    # 3) Добор Shadowsocks
    ss_count = sum(1 for l in picked if l.startswith("ss://"))
    if ss_count < N_SS and pool:
        needed = N_SS - ss_count
        cands = []
        for l in pool:
            if not l.startswith("ss://") or l in picked_set or l in known_ru or l in mtested:
                continue
            a = sa._host_of(l)
            if not a or a[0] in known_blocked_ips or per_addr.get(a, 0) >= PER_ADDR:
                continue
            cands.append(l)
        check_batch = cands[:needed * 3]
        live_tcp = filter_live_tcp(check_batch)
        for l in live_tcp:
            a = sa._host_of(l)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(l)
            picked_set.add(l)
            ss_count += 1
            if ss_count >= N_SS:
                break

    # 2b) Добор Trojan: в пуле 1700+ свежих троянов, а мобильный пайплайн их
    # вообще не брал (группы не было). Протокол TCP-ный, пречек работает.
    tr_count = sum(1 for l in picked if l.startswith("trojan://"))
    if tr_count < N_TROJAN and pool:
        needed = N_TROJAN - tr_count
        cands = []
        for l in pool:
            if not l.startswith("trojan://") or l in picked_set or l in known_ru or l in mtested:
                continue
            a = sa._host_of(l)
            if not a or a[0] in known_blocked_ips or per_addr.get(a, 0) >= PER_ADDR:
                continue
            cands.append(l)
        live_tcp = filter_live_tcp(cands[:needed * 3])
        for l in live_tcp:
            a = sa._host_of(l)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(l)
            picked_set.add(l)
            tr_count += 1
            if tr_count >= N_TROJAN:
                break

    # 3) anytls / tuic из пула
    for fam_name, budget in (("anytls", N_ANYTLS), ("tuic", N_TUIC)):
        if not budget:
            continue
        taken = sum(1 for l in picked if l.startswith(fam_name + "://"))
        if taken >= budget:
            continue
        cands = []
        for link in pool:
            if not link.startswith(fam_name + "://") or link in picked_set or link in known_ru or link in mtested:
                continue
            a = sa._host_of(link)
            if not a or a[0] in known_blocked_ips or per_addr.get(a, 0) >= PER_ADDR:
                continue
            if any(sa._host_of(p) == a for p in picked):
                continue
            cands.append(link)
        if fam_name == "anytls":
            cands = filter_live_tcp(cands[: (budget - taken) * 3])
        for link in cands:
            a = sa._host_of(link)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(link)
            picked_set.add(link)
            taken += 1
            if taken >= budget:
                break

    # Свежая кровь из общего пула (web_links.txt)
    web_f = os.path.join(CACHE, "web_links.txt")
    if os.path.exists(web_f):
        with open(web_f) as f:
            tail = f.readlines()[-6000:]
        pool_cands = []
        for raw_line in reversed(tail):
            l = raw_line.strip()
            if not l.startswith(("vless://", "hy2://", "hysteria2://", "ss://", "tuic://", "anytls://")):
                continue
            if l in picked_set or l in mtested or l in known_ru:
                continue
            a = sa._host_of(l)
            if not a or a[0] in known_blocked_ips or per_addr.get(a, 0) >= PER_ADDR:
                continue
            pool_cands.append(l)
            if len(pool_cands) >= N_POOL * 3:
                break
        live_pool = filter_live_tcp(pool_cands)
        taken_pool = 0
        for l in live_pool:
            a = sa._host_of(l)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(l)
            picked_set.add(l)
            taken_pool += 1
            if taken_pool >= N_POOL:
                break

    # «Родственники» рабочей панели: тот же uuid/пароль, другой входной адрес.
    good_keys = set()
    try:
        hist_all = json.load(open(mobile_history_path()))
        for l, v in hist_all.items():
            if (v.get("speed") or 0) > 0:
                pr = ffv.link_to_proxy(l, "x")
                if pr:
                    good_keys.add((pr.get("type"), pr.get("uuid") or pr.get("password")))
    except Exception:
        pass
    for l in picked:
        pr = ffv.link_to_proxy(l, "x")
        if pr:
            good_keys.add((pr.get("type"), pr.get("uuid") or pr.get("password")))
    good_keys.discard((None, None))
    if good_keys and pool:
        sib_cands = []
        for l in pool:
            if l in picked_set or l in known_ru:
                continue
            pr = ffv.link_to_proxy(l, "x")
            if not pr:
                continue
            if (pr.get("type"), pr.get("uuid") or pr.get("password")) not in good_keys:
                continue
            a = sa._host_of(l)
            if not a or a[0] in known_blocked_ips or per_addr.get(a, 0) >= PER_ADDR:
                continue
            sib_cands.append(l)
            if len(sib_cands) >= N_SIB * 3:
                break
        live_sib = filter_live_tcp(sib_cands)
        taken_sib = 0
        for l in live_sib:
            a = sa._host_of(l)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(l)
            picked_set.add(l)
            taken_sib += 1
            if taken_sib >= N_SIB:
                break

    # Ноды, которые уже работали с Yota, но выпали из домашнего alive.json:
    # Приоритет отдаём подтверждённым нодам с Gemini/Antigravity.
    hist_f = os.path.join(CACHE, "mobile_history.json")
    if os.path.exists(hist_f):
        hist = json.load(open(hist_f))
        have = set(picked)
        def hist_sort_key(item):
            _, v = item
            is_gem = 1 if v.get("gemini") == "ok" else 0
            fails = v.get("consecutive_fails", 0)
            score = v.get("score", 0)
            return (-is_gem, fails, -score, -v.get("ts", 0))
        for link, _v in sorted(hist.items(), key=hist_sort_key):
            if link in have or link in known_ru:
                continue
            a = sa._host_of(link)
            if not a or a[0] in known_blocked_ips or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(link)
            if len(picked) % 10 == 0 and len(picked) > N_HY2 + N_VLESS + N_SS + N_ANYTLS + N_TUIC + 30:
                break

    # Разнообразие по подсетям: Yota режет диапазоны целиком, поэтому десяток
    # нод из одной /24 даёт один шанс на всех. Режем до PER_NET на подсеть.
    before = len(picked)
    picked = diverse_by_net(picked)
    if len(picked) < before:
        print(f"  разнообразие по /24: {before} -> {len(picked)} кандидатов")
    return picked


def prune_invalid_sb(cfg, nodes_list, sb_bin, max_round=100):
    """Выкидывает ноды, из-за которых sing-box отказывается стартовать.

    `sing-box check` падает на одной битой ноде ('initialize outbound[61]:
    decode key: illegal base64 data'), а вместе с ней рушится весь прогон:
    в подписку не попадает ничего. Убираем такие outbounds по одному вместе
    с их inbound'ом и правилом роутинга, пока конфиг не станет валидным.
    """
    import re as _re

    if not sb_bin:
        return nodes_list, True, []

    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "sb.json")
    dropped = []
    try:
        for _ in range(max_round):
            with open(p, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False)
            try:
                r = subprocess.run([sb_bin, "check", "-c", p], capture_output=True, text=True)
            except (FileNotFoundError, OSError) as e:
                print(f"sing-box check skipped ({e}): локальный бинарник недоступен")
                return nodes_list, True, dropped
            if r.returncode == 0:
                return nodes_list, True, dropped
            m = _re.search(r"outbound\[(\d+)\]", r.stderr or "")
            if not m or int(m.group(1)) >= len(nodes_list):
                print("sing-box check: " + (r.stderr or "").strip()[-300:])
                return nodes_list, False, dropped
            idx = int(m.group(1))
            n = nodes_list.pop(idx)
            cfg["outbounds"].pop(idx)
            tag = "in" + n["name"]
            cfg["inbounds"] = [i for i in cfg["inbounds"] if i.get("tag") != tag]
            cfg["route"]["rules"] = [rl for rl in cfg["route"]["rules"] if rl.get("inbound") != [tag]]
            dropped.append(n)
            print(f"  выкинул ноду {n['name']} (не проходит sing-box check): {n['link'][:52]}")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return nodes_list, False, dropped


def build_config(links):
    proxies, nodes = [], []
    for i, l in enumerate(links):
        name = f"N{i}"
        p = ffv.link_to_proxy(l, name)
        p = sa.sanitize_proxy(p) if p else None
        if not p:
            continue
        p["port"] = int(p["port"])
        proxies.append(p)
        nodes.append({"name": name, "port": BASE_PORT + i, "link": l,
                      "dst": [p["server"], int(p["port"])]})

    out = ["mixed-port: 7900", "allow-lan: false", "mode: rule", "log-level: warning",
           "ipv6: false", f"external-controller: 127.0.0.1:{API_PORT}", "", "proxies:"]
    for pr in proxies:
        out.append("  - name: " + sa.yaml_str(pr["name"]))
        for k, v in pr.items():
            if k == "name":
                continue
            if isinstance(v, (dict, list)):
                out += [f"    {k}:", ffv.dump_yaml_value(v, 6)]
            elif isinstance(v, bool):
                out.append(f"    {k}: {'true' if v else 'false'}")
            else:
                out.append(f"    {k}: {sa.yaml_str(v)}")
    out += ["", "listeners:"]
    for n in nodes:
        out += [f"  - name: {n['name']}", "    type: socks", "    listen: 127.0.0.1",
                f"    port: {n['port']}", "    udp: true",
                "    proxy: " + sa.yaml_str(n["name"])]
    out += ["", "rules:", "  - MATCH,DIRECT"]
    return "\n".join(out) + "\n", nodes, list(zip(proxies, nodes))


# sing-box не умеет ssr, juicity и транспорт xhttp — такие ноды в него не кладём,
# иначе он проверит не то соединение, что в ссылке, и пометит ноду мёртвой
SB_SKIP_TYPES = {"ssr", "juicity"}
SB_SKIP_NETS = {"xhttp", "kcp", "mkcp"}


def build_sb_config(pairs):
    inbounds, outbounds, rules, used = [], [], [], 0
    sb_nodes = []
    for p, n in pairs:
        if p.get("type") in SB_SKIP_TYPES or p.get("network") in SB_SKIP_NETS:
            continue
        ob = sbv.to_singbox(p, n["name"])
        if not ob:
            continue
        # Битый flow валит sing-box на малинке: поддерживается только xtls-rprx-vision
        flow = str(ob.get("flow") or "")
        if flow and flow != "xtls-rprx-vision":
            continue
        inbounds.append({"type": "socks", "tag": "in" + n["name"], "listen": "127.0.0.1",
                         "listen_port": n["port"]})
        outbounds.append(ob)
        rules.append({"inbound": ["in" + n["name"]], "outbound": n["name"]})
        used += 1
        sb_nodes.append(n)
    outbounds.append({"type": "direct", "tag": "direct"})
    cfg = {"log": {"level": "warn"}, "inbounds": inbounds, "outbounds": outbounds,
           "route": {"rules": rules, "final": "direct"}}
    return cfg, used, sb_nodes


def main():
    links = pick_candidates()
    if not links:
        print("нет кандидатов: alive.json пуст — сначала домашний прогон")
        return 1
    cfg, nodes, pairs = build_config(links)
    if not nodes:
        print("ни одна ссылка не собралась в конфиг")
        return 1
    print(f"кандидатов на мобильную проверку: {len(nodes)}")

    sb_cfg, sb_used, sb_nodes = build_sb_config(pairs)
    if not sb_used:
        print("ни одна нода не собралась в конфиг sing-box")
        return 1
    sb_nodes, sb_valid, dropped_sb = prune_invalid_sb(sb_cfg, sb_nodes, paths.binary("sing-box"))
    if not sb_valid:
        print("конфиг sing-box не проходит проверку даже после чистки")
        return 1
    sb_used = len(sb_nodes)
    if dropped_sb:
        print(f"битых для sing-box: {len(dropped_sb)}, осталось {sb_used}")
    print(f"кандидатов на мобильную проверку (sing-box): {sb_used}")

    tmp = tempfile.mkdtemp()
    sb_f = os.path.join(tmp, "sb.json")
    sb_nodes_f = os.path.join(tmp, "sb_nodes.json")
    json.dump(sb_cfg, open(sb_f, "w"), ensure_ascii=False)
    json.dump(sb_nodes, open(sb_nodes_f, "w"), ensure_ascii=False)

    r = ssh(f"mkdir -p {WORK} /opt/vpntest && rm -f {WORK}/out.json && cat > {WORK}/sb.json",
            input_bytes=json.dumps(sb_cfg).encode())
    if r.returncode:
        print("не залил конфиг sing-box:", r.stderr.decode()[:200])
        return 2
    r = ssh(f"cat > {WORK}/sb_nodes.json", input_bytes=json.dumps(sb_nodes).encode())
    if r.returncode:
        print("не залил список нод:", r.stderr.decode()[:200])
        return 2
    r = ssh("cat > /opt/vpntest/pi_sb_verify.py",
            input_bytes=open(os.path.join(paths.SCRIPT_DIR, "pi_sb_verify.py"), "rb").read())
    if r.returncode:
        print("не залил скрипт проверки:", r.stderr.decode()[:200])
        return 2

    print(f"проверяю через Yota (малинка, sing-box, нод {sb_used})…")
    r = ssh(f"python3 /opt/vpntest/pi_sb_verify.py {WORK}/sb.json {WORK}/sb_nodes.json "
            f"{WORK}/out.json", timeout=int(os.environ.get("PI_TIMEOUT", "4200")))
    print((r.stdout.decode(errors="ignore") or "")[-1500:])
    if r.returncode:
        print("ошибка на малинке:", r.stderr.decode(errors="ignore")[-400:])
        return 3

    r = ssh(f"cat {WORK}/out.json")
    if r.returncode or not r.stdout.strip():
        print("не забрал результат")
        return 4
    rows = json.loads(r.stdout.decode())
    # Снимок прогона: по нему считается отдача каждого протокола (сколько
    # отправлено -> сколько прошло TCP -> сколько живых). Без этого квоты
    # настраиваются наугад. Храним последние 20 прогонов.
    try:
        runs_dir = os.path.join(CACHE, "runs")
        d = os.path.join(runs_dir, time.strftime("%Y%m%d-%H%M"))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "run.json"), "w", encoding="utf-8") as f:
            json.dump({"ts": int(time.time()), "sent": sb_nodes, "out": rows}, f,
                      ensure_ascii=False)
        olds = sorted(x for x in os.listdir(runs_dir) if x[:8].isdigit())
        for x in olds[:-20]:
            shutil.rmtree(os.path.join(runs_dir, x), ignore_errors=True)
    except Exception as e:
        print(f"снимок прогона не сохранён: {e}")
    # 0.0 при speed_measured=True значит «мерили и не поехало» — такие ноды в
    # подписке бесполезны (именно так туда попали воркер-заглушки с 204).
    MIN_SPEED = float(os.environ.get("PI_MIN_SPEED", "0.03"))
    live = [x for x in rows if x.get("delay")
            and not (x.get("speed_measured") and (x.get("speed") or 0) < MIN_SPEED)]
    dead_slow = [x for x in rows if x.get("delay") and x not in live]
    if dead_slow:
        print(f"отсеяно «живых без скорости»: {len(dead_slow)}")
    hist_p = os.path.join(CACHE, "mobile_history.json")
    hist = json.load(open(hist_p)) if os.path.exists(hist_p) else {}
    now = int(time.time())
    live_set = {x["link"] for x in live}
    for x in rows:
        link = x["link"]
        is_live = link in live_set
        prev = hist.get(link, {})
        prev_ok = prev.get("runs_ok", 1 if prev.get("ts") else 0)
        prev_total = prev.get("runs_total", 1 if prev.get("ts") else 0)
        runs_ok = prev_ok + (1 if is_live else 0)
        runs_total = prev_total + 1
        fails = 0 if is_live else (prev.get("consecutive_fails", 0) + 1)
        sp = x.get("speed") or (prev.get("speed") if is_live else 0) or 0
        gem = x.get("gemini") if is_live else prev.get("gemini")

        # Байесовский скор надёжности
        rel = (runs_ok + 1.0) / (runs_total + 2.0)
        sp_factor = min(1.0, max(0.0, float(sp) / 3.0))
        sc = rel * 0.6 + sp_factor * 0.4
        if fails > 0:
            sc *= (0.5 ** min(fails, 4))
        sc = round(sc, 4)

        if is_live:
            hist[link] = {
                "ts": now, "speed": sp, "delay": x.get("delay"),
                "gemini": gem, "runs_ok": runs_ok, "runs_total": runs_total,
                "consecutive_fails": 0, "score": sc
            }
        elif link in hist:
            hist[link]["runs_total"] = runs_total
            hist[link]["consecutive_fails"] = fails
            hist[link]["score"] = sc
    hist = {k: v for k, v in hist.items() if now - v.get("ts", 0) < 7 * 86400 and v.get("consecutive_fails", 0) < 5}
    json.dump(hist, open(hist_p, "w"), ensure_ascii=False, indent=1)
    json.dump(rows, open(OUT, "w"), ensure_ascii=False, indent=1)
    tf = os.path.join(CACHE, "mobile_tested.json")
    hist_t = json.load(open(tf)) if os.path.exists(tf) else {}
    for x in rows:
        hist_t[x["link"]] = int(time.time())
    json.dump(hist_t, open(tf, "w"))
    gem_ok = [x for x in live if x.get("gemini") == "ok"]
    print(f"из Yota живых: {len(live)} из {len(rows)} -> {OUT}")
    print(f"из них проверено для Gemini/Antigravity: {len(gem_ok)} из {len(live)}")
    for x in sorted(live, key=lambda y: -hist.get(y["link"], {}).get("score", 0))[:5]:
        sc = hist.get(x["link"], {}).get("score", 0)
        print(f"   [score: {sc:.3f}] {(x.get('speed') or 0):>5.2f} МБ/с {x['delay']:>5} мс "
              f"gemini={x.get('gemini', 'skip')} {x['link'][:44]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
