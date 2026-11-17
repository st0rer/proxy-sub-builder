#!/usr/bin/env python3
"""Сбор прокси-ссылок с веб-страниц (не GitHub-списков).

Зачем: часть источников живёт только на сайтах — каталоги проверенных ключей,
дневные подборки нод. Они отдают ссылки в HTML, часто за JS или base64-блобом,
поэтому обычный curl видит пустоту. Берём Scrapling: сначала статичный Fetcher
(TLS-имперсонация), если ссылок нет — StealthyFetcher (реальный Chrome).

Результат: $PROXY_SUB_HOME/cache/web_links.txt (по одной ссылке в строке).
"""
import base64
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths

OUT = os.path.join(paths.CACHE, "web_links.txt")
CACHE = os.path.join(paths.CACHE, "web_pages.json")

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ssr|ss|hy2|hysteria2|hysteria|tuic|anytls|juicity)://[^\s\"'<>\\]{10,}")
B64_RE = re.compile(r"[A-Za-z0-9+/=\r\n]{200,}")


def decode_blobs(html):
    """Длинные base64-блобы на страницах — это подписки целиком."""
    out = []
    for blob in B64_RE.findall(html):
        s = re.sub(r"\s+", "", blob)
        try:
            txt = base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
        except Exception:
            continue
        out += LINK_RE.findall(txt)
    return out


def extract(html):
    links = LINK_RE.findall(html)
    links += decode_blobs(html)
    # html-энтити в query-параметрах ламают парсеры
    return [l.replace("&amp;", "&").rstrip(".,;)'") for l in links]


def fetch(url, stealth=False):
    from scrapling.fetchers import Fetcher, StealthyFetcher
    if stealth:
        page = StealthyFetcher.fetch(url, headless=True, network_idle=True,
                                     google_search=False, disable_resources=True,
                                     timeout=60000)
        return page.html_content
    page = Fetcher.get(url, stealthy_headers=True, timeout=30)
    return page.html_content


def harvest(urls):
    res, pages = {}, {}
    for u in urls:
        try:
            html = fetch(u)
        except Exception as e:
            res[u] = {"error": str(e)[:80]}
            continue
        links = extract(html)
        mode = "static"
        if len(links) < 3:
            try:
                html = fetch(u, stealth=True)
                links = extract(html)
                mode = "stealth"
            except Exception as e:
                res[u] = {"error": "stealth: " + str(e)[:60]}
                continue
        res[u] = {"mode": mode, "links": len(links)}
        pages[u] = links
    return res, pages


def main(urls):
    res, pages = harvest(urls)
    for u, r in res.items():
        print(f"{r.get('mode','-'):>8} {r.get('links',0):>4}  {u} {r.get('error','')}")
    all_links = sorted({l for v in pages.values() for l in v})
    have = set()
    if os.path.exists(OUT):
        have = {l.strip() for l in open(OUT) if l.strip()}
    new = [l for l in all_links if l not in have]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "a") as f:
        for l in new:
            f.write(l + "\n")
    json.dump({u: {"in_page": len(v)} for u, v in pages.items()},
              open(CACHE, "w"), indent=1, ensure_ascii=False)
    print(f"\nвсего со страниц: {len(all_links)}, новых: {len(new)}, в файле: {len(have) + len(new)}")


if __name__ == "__main__":
    main(sys.argv[1:])
