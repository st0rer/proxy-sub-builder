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
import subprocess
import time
import sys
import tempfile
import paths  # noqa: E402  (локальные пути проекта)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_free_vpn as ffv
import scan_any as sa
import sb_verify as sbv

PI = os.environ.get("PI_HOST", "")
PI_PASS = os.environ.get("PI_PASS", "")
WORK = "/run/vpntest"          # tmpfs на малинке: SD-карту не изнашиваем
OUT = os.path.join(paths.OUT, "mobile_results.json")
CACHE = paths.CACHE
N_HY2 = int(os.environ.get("PI_N_HY2", "20"))
N_VLESS = int(os.environ.get("PI_N_VLESS", "30"))
N_SS = int(os.environ.get("PI_N_SS", "10"))
N_ANYTLS = int(os.environ.get("PI_N_ANYTLS", "8"))
N_TUIC = int(os.environ.get("PI_N_TUIC", "4"))
N_POOL = int(os.environ.get("PI_N_POOL", "22"))   # добор свежих нод из общего пула
N_SIB = int(os.environ.get("PI_N_SIB", "15"))     # адреса рабочих панелей
PER_ADDR = 2
API_PORT = 9099
BASE_PORT = 21000


def ssh(cmd, input_bytes=None, timeout=900):
    args = ["sshpass", "-p", PI_PASS, "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "PubkeyAuthentication=no", "-o", "ConnectTimeout=10", PI, cmd]
    return subprocess.run(args, input=input_bytes, capture_output=True, timeout=timeout)


def mobile_history_path():
    return os.path.join(CACHE, "mobile_history.json")


def pick_candidates():
    alive = json.load(open(os.path.join(CACHE, "alive.json")))
    is_h2 = lambda l: l.startswith(("hy2://", "hysteria2://", "hysteria://"))
    fam = lambda l: "hy2" if is_h2(l) else l.split("://")[0]
    groups = {"hy2": [], "vless": [], "ss": [], "anytls": [], "tuic": []}
    for link, delay in sorted(alive.items(), key=lambda kv: kv[1]):
        f = fam(link)
        if f in groups:
            groups[f].append((link, delay))

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

    # anytls/tuic не попадают в alive.json: там квоты только на hy2/vless/ss.
    # Берём их прямо из пула — sing-box на малинке эти протоколы умеет, mihomo нет.
    pool_f = os.path.join(CACHE, "all_links.json")
    if os.path.exists(pool_f):
        pool = json.load(open(pool_f))
        for fam_name, budget in (("anytls", N_ANYTLS), ("tuic", N_TUIC)):
            if not budget:
                continue
            taken = 0
            for link in pool:
                if not link.startswith(fam_name + "://") or link in picked:
                    continue
                a = sa._host_of(link)
                if not a or per_addr.get(a, 0) >= PER_ADDR:
                    continue
                # уже проверенная нода того же адреса — не дублируем
                if any(sa._host_of(p) == a for p in picked):
                    continue
                per_addr[a] = per_addr.get(a, 0) + 1
                picked.append(link)
                taken += 1
                if taken >= budget:
                    break
    # Свежая кровь из общего пула: домашний alive.json — это взгляд из домашней
    # сети, где многого из заблокированного Yota нет. Yota режет адреса иначе,
    # поэтому часть рабочих для неё нод дома просто не проверялась. Берём хвост
    # web_links.txt (самые свежие посты) и не повторяем то, что уже тестировали.
    tested_f = os.path.join(CACHE, "mobile_tested.json")
    mtested = json.load(open(tested_f)) if os.path.exists(tested_f) else {}
    now_ts = int(time.time())
    # 48 ч, а не неделя: нода, отвалившаяся на час, к вечеру часто оживает —
    # недельный карантин теряет такие возвраты (это и есть ложное отрицание).
    mtested = {k: v for k, v in mtested.items() if now_ts - v < 2 * 86400}
    web_f = os.path.join(CACHE, "web_links.txt")
    if os.path.exists(web_f):
        with open(web_f) as f:
            tail = f.readlines()[-6000:]
        picked_set = set(picked)
        taken_pool = 0
        for raw_line in reversed(tail):
            l = raw_line.strip()
            if not l.startswith(("vless://", "hy2://", "hysteria2://")):
                continue
            if l in picked_set or l in mtested:
                continue
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
    # Замер 16.11.2026: из 11 адресов одной панели с Yota работали 5 (45 %),
    # тогда как обычные кандидаты дают ~8 %. Поэтому панели, которые уже
    # отдавали трафик, добираем первыми.
    good_keys = set()
    for src in (mobile_history_path(), None):
        pass
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
    if good_keys:
        picked_set = set(picked)
        taken_sib = 0
        for l in pool:
            if l in picked_set:
                continue
            pr = ffv.link_to_proxy(l, "x")
            if not pr:
                continue
            if (pr.get("type"), pr.get("uuid") or pr.get("password")) not in good_keys:
                continue
            a = sa._host_of(l)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(l)
            taken_sib += 1
            if taken_sib >= N_SIB:
                break

    # Ноды, которые уже работали с Yota, но выпали из домашнего alive.json:
    # сеть Yota блокирует адреса не так, как домашний канал, поэтому домашний
    # отбор их не видит. Берём из истории, самые свежие первыми.
    hist_f = os.path.join(CACHE, "mobile_history.json")
    if os.path.exists(hist_f):
        hist = json.load(open(hist_f))
        have = set(picked)
        for link, _v in sorted(hist.items(), key=lambda kv: -kv[1].get("ts", 0)):
            if link in have:
                continue
            a = sa._host_of(link)
            if not a or per_addr.get(a, 0) >= PER_ADDR:
                continue
            per_addr[a] = per_addr.get(a, 0) + 1
            picked.append(link)
            if len(picked) % 10 == 0 and len(picked) > N_HY2 + N_VLESS + N_SS + N_ANYTLS + N_TUIC + 20:
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
                f"{WORK}/out.json", timeout=1200)
        if r.returncode:
            print("sing-box не справился, откат на mihomo:",
                  r.stderr.decode(errors="ignore")[-300:])
            engine = "mihomo"
    if engine != "sb" or not sb_used:
        print("проверяю через Yota (малинка, mihomo)…")
        r = ssh(f"python3 /opt/vpntest/pi_verify.py {WORK}/config.yaml {WORK}/nodes.json "
                f"{WORK}/out.json", timeout=1200)
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
        hist[x["link"]] = {"ts": now, "speed": x.get("speed") or 0, "delay": x.get("delay")}
    hist = {k: v for k, v in hist.items() if now - v.get("ts", 0) < 7 * 86400}
    json.dump(hist, open(hist_p, "w"))
    json.dump(rows, open(OUT, "w"), ensure_ascii=False, indent=1)
    tf = os.path.join(CACHE, "mobile_tested.json")
    hist_t = json.load(open(tf)) if os.path.exists(tf) else {}
    for x in rows:
        hist_t[x["link"]] = int(time.time())
    json.dump(hist_t, open(tf, "w"))
    print(f"из Yota живых: {len(live)} из {len(rows)} -> {OUT}")
    for x in sorted(live, key=lambda y: -(y.get("speed") or 0))[:5]:
        print(f"   {(x.get('speed') or 0):>5.2f} МБ/с {x['delay']:>5} мс udp={'да' if x['udp'] else 'нет'} "
              f"{x['link'][:44]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
