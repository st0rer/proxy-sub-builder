#!/usr/bin/env python3
"""yota_fallback.py — временная замена мобильного профиля, пока малинка недоступна.

Берёт живые ноды, проверенные на N100 (домашний verified.json), и оставляет те,
которые в домашнюю подписку не попали (потолки, дедуп, приоритет скорости) —
то есть «отсеянные, но рабочие». Пишет JSON в формате mobile_results.json,
чтобы дальше его обрабатывал тот же publish_sub.py без отдельной ветки форматов.

Использование:
    python3 yota_fallback.py && SUB_FROM=... publish_sub.py

Ограничения: RU-выходы выбрасываются (для обхода они бесполезны), скорость
ниже MIN_SPEED_MBPS — тоже (0.0 МБ/с = «соединение есть, трафика нет»).
"""
import concurrent.futures
import json
import os
import re
import socket
import sys

import paths

CACHE = paths.CACHE
OUT = paths.OUT
SUB = os.path.join(OUT, "sub")
FALLBACK_JSON = os.path.join(OUT, "mobile_fallback.json")
MIN_SPEED_MBPS = float(os.environ.get("YOTA_FALLBACK_MIN_SPEED", "0.03"))
# TCP-протоколы проверяем на доступность порта: verified.json помнит вчерашнюю
# картину, а нода с закрытым портом бесполезна. UDP (hy2/tuic) так не проверить.
TCP_PROTOS = ("vless", "vmess", "trojan", "ss", "ssr", "anytls", "juicity")
TCP_CHECK = os.environ.get("YOTA_FALLBACK_TCPCHECK", "1") == "1"


def load_json(p, default):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return default


def published_home_links():
    p = os.path.join(SUB, "nodes.txt")
    if not os.path.exists(p):
        return set()
    return {l.strip() for l in open(p) if l.strip()}


def parse_dst(link):
    """host:port из ссылки — для дедупа по подключению на стороне publish_sub."""
    m = re.search(r"@\[?([0-9a-zA-Z\.\-:]+?)\]?:(\d+)", link)
    if m:
        return [m.group(1), int(m.group(2))]
    m = re.search(r"@([0-9a-zA-Z\.\-]+):(\d+)", link)
    if m:
        return [m.group(1), int(m.group(2))]
    # ss://base64@host:port и прочие без @
    m = re.search(r"://[^@/]*@?([0-9a-zA-Z\.\-]+):(\d+)", link)
    if m:
        return [m.group(1), int(m.group(2))]
    return []


def main():
    verified = load_json(os.path.join(CACHE, "verified.json"), [])
    if not verified:
        print("yota_fallback: нет verified.json — нечего публиковать", file=sys.stderr)
        return 1

    published = published_home_links()
    rows, skipped = [], {"RU": 0, "slow": 0, "published": 0, "dup": 0}
    seen = set()

    for i, v in enumerate(verified):
        link = (v.get("link") or "").strip()
        if not link:
            continue
        if (v.get("cc") or "").upper() == "RU":
            skipped["RU"] += 1
            continue
        speed = v.get("speed_MBps")
        speed = float(speed) if speed is not None else None
        if speed is not None and speed < MIN_SPEED_MBPS:
            skipped["slow"] += 1
            continue
        dst = parse_dst(link)
        key = tuple(dst) if dst else link
        if key in seen:
            skipped["dup"] += 1
            continue
        seen.add(key)
        cc = (v.get("cc") or "").upper()
        gemini = v.get("gemini")
        if not gemini:
            gemini = "geoblock" if cc in ("RU", "BY", "IR", "KP", "CN", "") else "ok"
        rows.append({
            "name": f"n100-{i:02d}-{v.get('cc') or '??'}",
            "link": link,
            "dst": dst,
            "delay": v.get("delay") or 0,
            "speed": speed,
            "speed_measured": speed is not None,
            "udp": True,
            "stage": "n100-fallback",
            "ip": v.get("ip") or "",
            "cc": cc,
            "gemini": gemini,
        })

    if TCP_CHECK:
        def alive(r):
            proto = r["link"].split("://")[0]
            if proto not in TCP_PROTOS:
                return r          # UDP-протокол: проверять нечем
            dst = r.get("dst") or []
            if len(dst) < 2:
                return r
            try:
                with socket.create_connection((dst[0], int(dst[1])), timeout=5):
                    return r
            except Exception:
                return None

        before = len(rows)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            rows = [r for r in ex.map(alive, rows) if r]
        skipped["tcp_dead"] = before - len(rows)

    rows.sort(key=lambda r: (r["speed"] or 0), reverse=True)
    with open(FALLBACK_JSON, "w") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)

    print(f"yota_fallback: {len(rows)} нод из {len(verified)} проверенных "
          f"(уже в домашней подписке: {skipped['published']}, RU: {skipped['RU']}, "
          f"медленных: {skipped['slow']}, дублей: {skipped['dup']})")
    print(f"yota_fallback: -> {FALLBACK_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
