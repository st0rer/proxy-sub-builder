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
N_HY2 = int(os.environ.get("PI_N_HY2", "8"))
N_VLESS = int(os.environ.get("PI_N_VLESS", "80"))
N_SS = int(os.environ.get("PI_N_SS", "35"))
N_ANYTLS = int(os.environ.get("PI_N_ANYTLS", "15"))
N_TUIC = int(os.environ.get("PI_N_TUIC", "4"))
N_POOL = int(os.environ.get("PI_N_POOL", "80"))  # добор из пула
N_SIB = int(os.environ.get("PI_N_SIB", "40"))     # адреса рабочих панелей (выход 45% против 8%)
PER_ADDR = 2
API_PORT = 9099
BASE_PORT = 21000
FAST_TCP_PRECHECK = os.environ.get("FAST_TCP_PRECHECK", "1") == "1"


def filter_live_tcp(links, timeout=1.2, max_workers=25):
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
    groups = {"hy2": [], "vless": [], "ss": [], "anytls": [], "tuic": []}

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
        is_ru_sni = any(dom in link for dom in (".ru", "vk.com", "yandex.ru", "mail.ru", "gosuslugi.ru"))
        pri = 0
        if is_reality: pri += 2
        if is_ru_sni: pri += 1
        return (-pri, delay)

    def hy2_pri(item):
        link, delay = item
        # На Yota порт UDP 443 режется оператором: штрафуем 443 без обфускации
        a = sa._host_of(link)
        port = a[1] if a else 443
        non_std_port = (port != 443)
        has_obfs = "obfs=" in link or "salamander" in link
        pri = 0
        if non_std_port: pri += 3
        if has_obfs: pri += 2
        if not non_std_port and not has_obfs: pri -= 5
        return (-pri, delay)

    groups["vless"].sort(key=vless_pri)
    groups["hy2"].sort(key=hy2_pri)

    picked, per_addr = [], {}
    for f, budget in (("hy2", N_HY2), ("vless", N_VLESS), ("ss", N_SS),
                      ("anytls", N_ANYTLS), ("tuic", N_TUIC)):
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
    mtested = {k: v for k, v in mtested.items() if now_ts - v < 2 * 86400}

    picked_set = set(picked)

    # 1) Добор VLESS (Reality в приоритете)
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
        cands.sort(key=lambda l: 0 if ("pbk=" in l or "security=reality" in l) else 1)
        check_batch = cands[:needed * 3]
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

    # 2) Добор Shadowsocks
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
            return (-is_gem, -v.get("ts", 0))
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
    return picked


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
    outbounds.append({"type": "direct", "tag": "direct"})
    cfg = {"log": {"level": "warn"}, "inbounds": inbounds, "outbounds": outbounds,
           "route": {"rules": rules, "final": "direct"}}
    return cfg, used


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

    sb_cfg, sb_used = build_sb_config(pairs)
    tmp = tempfile.mkdtemp()
    cfg_f = os.path.join(tmp, "config.yaml")
    nodes_f = os.path.join(tmp, "nodes.json")
    sb_f = os.path.join(tmp, "sb.json")
    open(cfg_f, "w").write(cfg)
    json.dump(nodes, open(nodes_f, "w"), ensure_ascii=False)
    json.dump(sb_cfg, open(sb_f, "w"), ensure_ascii=False)

    r = ssh(f"mkdir -p {WORK} /opt/vpntest && rm -f {WORK}/out.json && cat > {WORK}/config.yaml",
            input_bytes=cfg.encode())
    if r.returncode:
        print("не залил конфиг:", r.stderr.decode()[:200])
        return 2
    r = ssh(f"cat > {WORK}/nodes.json", input_bytes=json.dumps(nodes).encode())
    if r.returncode:
        print("не залил список:", r.stderr.decode()[:200])
        return 2
    r = ssh("cat > /opt/vpntest/pi_verify.py", input_bytes=open(os.path.join(paths.SCRIPT_DIR, "pi_verify.py"), "rb").read())
    if r.returncode:
        print("не залил скрипт:", r.stderr.decode()[:200])
        return 2

    # sing-box первым: он умеет anytls/tuic, которых mihomo 1.18.10 не знает
    engine = os.environ.get("PI_ENGINE", "sb")
    if engine == "sb" and sb_used:
        r = ssh(f"cat > {WORK}/sb.json", input_bytes=json.dumps(sb_cfg).encode())
        if r.returncode == 0:
            r = ssh("cat > /opt/vpntest/pi_sb_verify.py",
                    input_bytes=open(os.path.join(paths.SCRIPT_DIR, "pi_sb_verify.py"), "rb").read())
        print(f"проверяю через Yota (малинка, sing-box, нод {sb_used})…")
        r = ssh(f"python3 /opt/vpntest/pi_sb_verify.py {WORK}/sb.json {WORK}/nodes.json "
                f"{WORK}/out.json", timeout=int(os.environ.get("PI_TIMEOUT", "2400")))
        if r.returncode:
            print("sing-box не справился, откат на mihomo:",
                  r.stderr.decode(errors="ignore")[-300:])
            engine = "mihomo"
    if engine != "sb" or not sb_used:
        print("проверяю через Yota (малинка, mihomo)…")
        r = ssh(f"python3 /opt/vpntest/pi_verify.py {WORK}/config.yaml {WORK}/nodes.json "
                f"{WORK}/out.json", timeout=int(os.environ.get("PI_TIMEOUT", "2400")))
    print((r.stdout.decode(errors="ignore") or "")[-1500:])
    if r.returncode:
        print("ошибка на малинке:", r.stderr.decode(errors="ignore")[-400:])
        return 3

    r = ssh(f"cat {WORK}/out.json")
    if r.returncode or not r.stdout.strip():
        print("не забрал результат")
        return 4
    rows = json.loads(r.stdout.decode())
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
    for x in live:
        hist[x["link"]] = {"ts": now, "speed": x.get("speed") or 0, "delay": x.get("delay"),
                           "gemini": x.get("gemini")}
    hist = {k: v for k, v in hist.items() if now - v.get("ts", 0) < 7 * 86400}
    json.dump(hist, open(hist_p, "w"))
    json.dump(rows, open(OUT, "w"), ensure_ascii=False, indent=1)
    tf = os.path.join(CACHE, "mobile_tested.json")
    hist_t = json.load(open(tf)) if os.path.exists(tf) else {}
    for x in rows:
        hist_t[x["link"]] = int(time.time())
    json.dump(hist_t, open(tf, "w"))
    gem_ok = [x for x in live if x.get("gemini") == "ok"]
    print(f"из Yota живых: {len(live)} из {len(rows)} -> {OUT}")
    print(f"из них проверено для Gemini/Antigravity: {len(gem_ok)} из {len(live)}")
    for x in sorted(live, key=lambda y: -(y.get("speed") or 0))[:5]:
        print(f"   {(x.get('speed') or 0):>5.2f} МБ/с {x['delay']:>5} мс udp={'да' if x['udp'] else 'нет'} "
              f"gemini={x.get('gemini', 'skip')} {x['link'][:44]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
