#!/usr/bin/env python3
"""Проверка нод через sing-box (второй движок).

Зачем: mihomo 1.19 умеет vless/vmess/trojan/ss/ssr/hy2/tuic/anytls, но не умеет
AmneziaWG и часть новых транспортов. sing-box добавляет их и валидирует конфиг
командой `check`. Скрипт поднимает по одному socks-inbound на ноду, гоняет
HTTPS-пробу (204) и, для лучших, замер скорости.

Использование:
    sb_verify.py <файл-со-ссылками> [лимит] > results.jsonl
"""
import concurrent.futures as cf
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import paths  # noqa: E402  (локальные пути проекта)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_free_vpn as ffv
import scan_any as sa

SB = paths.binary("sing-box")
# три ступени вместо одного URL: на замере 16.11 один gstatic давал 27% ложных отсевов
# среди достижимых нод (часть выходов режет gstatic, но данные при этом ходят)
TEST_URLS = (
    ("https://www.gstatic.com/generate_204", 204, "gstatic"),
    ("http://cp.cloudflare.com/generate_204", 204, "cp-cf"),
    ("https://speed.cloudflare.com/__down?bytes=16384", 200, "body16k"),
)
TEST_URL = TEST_URLS[0][0]
BASE_PORT = int(os.environ.get("SB_BASE_PORT", "31000"))
PAR = int(os.environ.get("SB_PAR", "12"))
TIMEOUT = int(os.environ.get("SB_TIMEOUT", "10"))
SPEED_TOP = int(os.environ.get("SB_SPEED_TOP", "25"))
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
WORKDIR = os.path.join(paths.SCRATCH, "sb_run")

SUPPORTED = {"vless", "vmess", "trojan", "shadowsocks", "ss", "anytls", "tuic", "hysteria2"}


def tls_block(p, quic=False, enable_fragment=True):
    tls = {"enabled": True,
           "server_name": p.get("sni") or p.get("servername") or p.get("server") or "",
           "insecure": bool(p.get("skip-cert-verify"))}
    if p.get("alpn"):
        tls["alpn"] = p["alpn"]
    if not quic:   # QUIC-протоколы (hy2/tuic) не умеют uTLS: "unsupported usage for uTLS"
        tls["utls"] = {"enabled": True, "fingerprint": p.get("client-fingerprint") or "chrome"}
        if enable_fragment:
            # Фрагментация ClientHello для обхода мобильного ТСПУ/DPI (Yota/Мегафон)
            tls["fragment"] = True
            tls["record_fragment"] = True
            tls["fragment_fallback_delay"] = "500ms"
    ro = p.get("reality-opts") or {}
    if p.get("reality-opts"):
        # Reality в sing-box требует uTLS — отпечаток обязателен, не выкидывать
        tls["reality"] = {"enabled": True,
                          "public_key": ro.get("public-key", ""),
                          "short_id": ro.get("short-id", "")}
    return tls


def transport_block(p):
    net = p.get("network")
    if net == "ws":
        ws = p.get("ws-opts") or {}
        path = ws.get("path") or "/"
        # "/?ed=2560" — это путь "/" плюс early-data в query; sing-box query в path не понимает
        if "?" in path:
            path = path.split("?", 1)[0] or "/"
        t = {"type": "ws", "path": path}
        if (ws.get("headers") or {}).get("Host"):
            t["headers"] = {"Host": ws["headers"]["Host"]}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": (p.get("grpc-opts") or {}).get("grpc-service-name") or ""}
    if net == "h2":
        h2 = p.get("h2-opts") or {}
        return {"type": "http", "path": h2.get("path") or "/",
                "host": h2.get("host") or []}
    return None


def to_singbox(p, tag):
    t = p["type"]
    ob = {"type": t, "tag": tag, "server": p["server"], "server_port": int(p["port"])}
    if t == "vless":
        ob["uuid"] = p["uuid"]
        if p.get("flow"):
            ob["flow"] = p["flow"]
        if p.get("tls"):
            ob["tls"] = tls_block(p)
        tr = transport_block(p)
        if tr:
            ob["transport"] = tr
    elif t == "vmess":
        ob["uuid"] = p["uuid"]
        ob["security"] = p.get("cipher") or "auto"
        ob["alter_id"] = int(p.get("alterId") or 0)
        if p.get("tls"):
            ob["tls"] = tls_block({**p, "sni": p.get("servername") or p.get("sni")})
        tr = transport_block(p)
        if tr:
            ob["transport"] = tr
    elif t == "trojan":
        ob["password"] = p["password"]
        ob["tls"] = tls_block(p)
        tr = transport_block(p)
        if tr:
            ob["transport"] = tr
    elif t in ("ss", "shadowsocks"):
        ob["type"] = "shadowsocks"
        ob["method"] = p["cipher"]
        ob["password"] = p["password"]
        if p.get("plugin") == "obfs":
            ob["plugin"] = "obfs-local"
            ob["plugin_opts"] = f"obfs={p['plugin-opts'].get('mode','http')};obfs-host={p['plugin-opts'].get('host','')}"
    elif t == "anytls":
        ob["password"] = p["password"]
        ob["tls"] = tls_block(p)
    elif t == "tuic":
        ob["uuid"] = p["uuid"]
        ob["password"] = p["password"]
        ob["tls"] = tls_block(p, quic=True)
        if p.get("congestion-controller"):
            ob["congestion_control"] = p["congestion-controller"]
        if p.get("udp-relay-mode"):
            ob["udp_relay_mode"] = p["udp-relay-mode"]
    elif t == "hysteria2":
        ob["password"] = p["password"]
        tls = tls_block(p, quic=True)
        # hysteria2 работает только поверх ALPN h3 — без него рукопожатие не поднимется
        tls["alpn"] = tls.get("alpn") or ["h3"]
        ob["tls"] = tls
        if p.get("obfs") and p.get("obfs-password"):
            ob["obfs"] = {"type": p["obfs"], "password": p["obfs-password"]}
    else:
        return None
    return ob


def build(links):
    inbounds, outbounds, rules = [], [], []
    meta = {}
    for i, link in enumerate(links):
        p = ffv.link_to_proxy(link, f"N{i}")
        p = sa.sanitize_proxy(p) if p else None
        if not p:
            continue
        ob = to_singbox(p, f"N{i}")
        if not ob:
            continue
        # Один битый flow валит ВЕСЬ конфиг: sing-box пишет
        # «initialize outbound[45]: unsupported flow: xtls-rprx-vision-udp443»
        # и не стартует — прогон даёт 0 живых из любого числа нод.
        flow = str(ob.get("flow") or "")
        if flow and flow != "xtls-rprx-vision":
            continue
        port = BASE_PORT + i
        inbounds.append({"type": "socks", "tag": f"in{i}", "listen": "127.0.0.1",
                         "listen_port": port})
        outbounds.append(ob)
        rules.append({"inbound": [f"in{i}"], "outbound": f"N{i}"})
        meta[f"N{i}"] = {"link": link, "port": port, "proto": ob["type"]}
    outbounds.append({"type": "direct", "tag": "direct"})
    cfg = {"log": {"level": "warn"},
           "inbounds": inbounds, "outbounds": outbounds,
           "route": {"rules": rules, "final": "direct"}}
    return cfg, meta


def check_cfg(cfg, path=None):
    if path is None:
        path = os.path.join(paths.SCRATCH, "sb_check.json")
    json.dump(cfg, open(path, "w"))
    r = subprocess.run([SB, "check", "-c", path], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()[:400]


def main():
    args = sys.argv[1:]
    if not args:
        print("usage: sb_verify.py <links.txt> [limit]", file=sys.stderr)
        return 2
    limit = int(args[1]) if len(args) > 1 else 200
    links = [l.strip() for l in open(args[0]) if l.strip().startswith(("vless://", "vmess://", "trojan://",
                                                                     "ss://", "anytls://", "tuic://",
                                                                     "hy2://", "hysteria2://"))][:limit]
    cfg, meta = build(links)
    if not meta:
        print("нечего проверять", file=sys.stderr)
        return 1
    ok, err = check_cfg(cfg)
    if not ok:
        # бисекция: выкидываем ноды, на которых конфиг не проходит
        keep = []
        for tag in list(meta):
            sub_cfg, sub_meta = build([meta[tag]["link"]])
            good, _ = check_cfg(sub_cfg)
            if good:
                keep.append(meta[tag]["link"])
            else:
                print(json.dumps({"link": meta[tag]["link"], "alive": False, "reason": "config-invalid"},
                                 ensure_ascii=False))
        cfg, meta = build(keep)
        ok, err = check_cfg(cfg)
        if not ok:
            print("конфиг всё ещё битый:", err, file=sys.stderr)
            return 1

    os.makedirs(WORKDIR, exist_ok=True)
    cpath = os.path.join(WORKDIR, "config.json")
    json.dump(cfg, open(cpath, "w"))
    proc = subprocess.Popen([SB, "run", "-c", cpath],
                            stdout=subprocess.DEVNULL, stderr=open(os.path.join(WORKDIR, "sb.log"), "w"))
    time.sleep(2.5)

    def probe(tag):
        info = meta[tag]
        port = info["port"]
        last = "000"
        for url, want, label in list(TEST_URLS) + [TEST_URLS[0]]:   # последняя — повтор flap-ноды
            r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download} %{time_total}",
                                "--max-time", str(TIMEOUT), "--socks5-hostname", f"127.0.0.1:{port}", url],
                               capture_output=True, text=True)
            out = r.stdout.split()
            code = out[0] if out else "000"
            # заглушка отвечает 200 страницей и проходит по коду, не везя трафик:
            # тело короче 15 КБ на запросе в 16 КБ — не CDN
            if code == "200" and "bytes=" in url and len(out) > 2 and float(out[1]) < 15000:
                code = "short"
            last = code
            if code in ("204", "200"):
                t = float(out[2]) if len(out) > 2 else 0.0
                return {"link": info["link"], "proto": info["proto"], "alive": True,
                        "delay": int(t * 1000), "speed_MBps": 0.0, "stage": label}
        return {"link": info["link"], "proto": info["proto"], "alive": False, "reason": f"http-{last}"}

    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=PAR) as ex:
        rows = list(ex.map(probe, list(meta)))
    # Второй проход по мёртвым с длинными таймаутами: замер на малинке (101 нода)
    # дал 10 живых в быстром режиме против 14 с повтором — 28 % рабочих терялись
    # на flap'ах. Дома то же самое, только дешевле по времени.
    dead = [r for r in rows if not r["alive"]]
    if dead and os.environ.get("NO_RECOVERY") != "1":
        RETRY = [("http://cp.cloudflare.com/generate_204", 204, "cp-cf-r", 15),
                 ("https://speed.cloudflare.com/__down?bytes=16384", 200, "body16k-r", 18),
                 ("https://www.gstatic.com/generate_204", 204, "gstatic-r", 12)]
        def redo(r):
            tag = next(t for t, m in meta.items() if m["link"] == r["link"])
            for url, want, label, tmo in RETRY:
                rr = subprocess.run(["curl", "-s", "-o", "/dev/null",
                                     "-w", "%{http_code} %{size_download} %{time_total}",
                                     "--max-time", str(tmo), "--socks5-hostname",
                                     f"127.0.0.1:{meta[tag]['port']}", url],
                                    capture_output=True, text=True)
                o = rr.stdout.split()
                code = o[0] if o else "000"
                size = float(o[1]) if len(o) > 2 else 0.0
                if code == "200" and "bytes=" in url and size < 15000:
                    continue
                if code in ("204", "200"):
                    return {"link": r["link"], "proto": r["proto"], "alive": True,
                            "delay": int(float(o[2]) * 1000) if len(o) > 2 else 1,
                            "speed_MBps": 0.0, "stage": label}
            return r
        with cf.ThreadPoolExecutor(max_workers=PAR) as ex:
            rows = list(ex.map(redo, rows))
    alive = [r for r in rows if r["alive"]]
    # Параллельный замер реальной скорости (Speed Gate) для лучших кандидатов
    speed_candidates = sorted(alive, key=lambda x: x["delay"])[:SPEED_TOP]

    def measure_speed(r):
        tag = next(t for t, m in meta.items() if m["link"] == r["link"])
        rr = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}",
                             "--max-time", "12", "--socks5-hostname", f"127.0.0.1:{meta[tag]['port']}", SPEED_URL],
                            capture_output=True, text=True)
        try:
            r["speed_MBps"] = round(float(rr.stdout.strip() or 0) / 1048576, 2)
        except ValueError:
            r["speed_MBps"] = 0.0
        return r

    if speed_candidates:
        with cf.ThreadPoolExecutor(max_workers=min(6, len(speed_candidates))) as ex:
            list(ex.map(measure_speed, speed_candidates))
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    for r in rows:
        print(json.dumps(r, ensure_ascii=False))
    print(f"# sing-box: {len(alive)} живых из {len(meta)}, {time.time()-t0:.1f} c", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
