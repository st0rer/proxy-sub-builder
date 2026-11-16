#!/usr/bin/env python3
"""Расширение списка телеграм-каналов без MTProto-аккаунта.

Источники (проверено 16.11.2026: 594 канала всего, 462 новых, 129 отдают конфиги):
  1. Списки каналов из репозиториев-сборщиков: Argh73/V2Ray-Vault,
     CattMurr/FREE-VPN-VIA-PLANET, 3yed82/TVC, vpnineh/TGC,
     chenweimin30-hue/-VPN (у каждого свой набор — пересечение всего 132 из 594).
  2. Поисковик (SearXNG) по запросам `site:t.me <слово>` — низкая точность
     (3 из 47), но 5 секунд на десяток запросов, поэтому идёт как добавка.

Каждый кандидат проверяется одной страницей t.me/s/: если в последних постах
есть конфиги, он попадает в tg_discovered.json и опрашивается дальше вместе с
основным списком. Ссылки сразу дописываются в web_links.txt.

Использование: discover_channels.py [--search]
"""
import concurrent.futures as cf
import importlib.util as iu
import json
import os
import re
import sys
import time
import urllib.request

CACHE_DIR = paths.CACHE
DISCOVERED = os.path.join(CACHE_DIR, "tg_discovered.json")
REJECTED = os.path.join(CACHE_DIR, "tg_rejected.json")   # проверены, конфигов нет
REJECT_TTL = 3 * 86400                                  # перепроверять раз в 3 дня
OUT = os.path.join(CACHE_DIR, "web_links.txt")
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0 Safari/537.36"}

spec = iu.spec_from_file_location("tgs", os.path.join(os.path.dirname(__file__), "tg_scrape.py"))
tgs = iu.module_from_spec(spec)
spec.loader.exec_module(tgs)

LISTS = [
    ("Argh73/V2Ray-Vault", "data/Extract/telegram_channels.json"),
    ("CattMurr/FREE-VPN-VIA-PLANET", "telegram-channels.json"),
    ("3yed82/TVC", "channels.json"),
    ("vpnineh/TGC", "telegramchannels.json"),
    ("chenweimin30-hue/-VPN", "telegramchannels.json"),
]
SEARCH_QUERIES = ["site:t.me vless", "site:t.me hysteria2", "site:t.me anytls",
                  "site:t.me конфиги vpn", "site:t.me vmess trojan", "site:t.me xray reality"]
UNAME = re.compile(r"^@?([A-Za-z0-9_]{4,32})$")
STOP = ("vless", "vmess", "trojan", "http", "config", "json", "shadowsocks",
        "hysteria", "tuic", "subscription", "telegram")


def raw(repo, path):
    url = f"https://raw.githubusercontent.com/{repo}/HEAD/{path}"
    try:
        return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=25).read().decode("utf-8", "ignore")
    except Exception:
        return ""


def strings(obj, acc):
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, list):
        for x in obj:
            strings(x, acc)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            strings(k, acc)
            strings(v, acc)


def from_repos():
    chans = set()
    for repo, path in LISTS:
        text = raw(repo, path)
        if not text:
            print(f"  пусто: {repo}/{path}", file=sys.stderr)
            continue
        acc = []
        try:
            strings(json.loads(text), acc)
        except Exception:
            acc = text.split()
        got = set()
        for s in acc:
            s = s.strip()
            if s.startswith("http") or "/" in s:
                m = re.search(r"t\.me/(?:s/)?([A-Za-z0-9_]{4,32})", s)
                if m:
                    got.add(m.group(1))
                continue
            m = UNAME.match(s)
            if m:
                got.add(m.group(1))
        got = {g for g in got if not any(w in g.lower() for w in STOP)}
        print(f"  {repo:<38} {path:<40} {len(got)}", file=sys.stderr)
        chans |= got
    return chans


def from_search():
    import urllib.parse
    chans = set()
    for q in SEARCH_QUERIES:
        url = "http://127.0.0.1:8180/search?" + urllib.parse.urlencode({"q": q, "format": "json", "pageno": 1})
        try:
            d = json.loads(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=25).read())
        except Exception:
            continue
        for r in d.get("results", []):
            m = re.search(r"t\.me/(?:s/)?([A-Za-z0-9_]{4,32})", r.get("url", ""))
            if m:
                chans.add(m.group(1))
    return chans


def main():
    use_search = "--search" in sys.argv
    discovered = tgs.load(DISCOVERED, {})
    rejected = tgs.load(REJECTED, {})
    now = int(time.time())
    rejected = {k: v for k, v in rejected.items() if now - v < REJECT_TTL}
    known = set(discovered) | set(tgs.load(tgs.STATE, {})) | set(rejected)
    candidates = from_repos()
    if use_search:
        candidates |= from_search()
    new = sorted(c for c in candidates if c.lower() not in {k.lower() for k in known})
    print(f"кандидатов: {len(candidates)}, новых: {len(new)}", file=sys.stderr)

    def probe(name):
        links, _c, _p, _m = tgs.scan_channel(name, None, 1)
        return name, links

    hits, links_all, t0 = {}, [], time.time()
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        for name, links in ex.map(probe, new):
            if links:
                hits[name] = len(links)
                links_all += links
    for name, n in hits.items():
        discovered[name] = {"links": n, "seen": now}
    for name in new:
        if name not in hits:
            rejected[name] = now
    tgs.save(DISCOVERED, discovered)
    tgs.save(REJECTED, rejected)

    have = {l.strip() for l in open(OUT)} if os.path.exists(OUT) else set()
    fresh = [l for l in dict.fromkeys(links_all) if l not in have]
    with open(OUT, "a") as f:
        for l in fresh:
            f.write(l + "\n")
    print(f"в отказе (проверены, пусто): {len(rejected)}")
    print(f"проверено {len(new)} за {time.time()-t0:.0f} c | с конфигами {len(hits)} "
          f"({100*len(hits)/max(1,len(new)):.0f}%) | новых ссылок {len(fresh)}")
    print("топ:", sorted(hits.items(), key=lambda kv: -kv[1])[:8])
    return 0


if __name__ == "__main__":
    sys.exit(main())
