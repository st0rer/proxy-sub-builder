#!/usr/bin/env python3
"""Сбор прокси-ссылок с веб-страниц (не GitHub-списков).

Зачем: часть источников живёт только на сайтах — каталоги проверенных ключей,
дневные подборки нод. Они отдают ссылки в HTML, часто за JS или base64-блобом,
поэтому обычный curl видит пустоту. Берём Scrapling: сначала статичный Fetcher
(TLS-имперсонация), если ссылок нет — StealthyFetcher (реальный Chrome).

Результат: $PROXY_SUB_HOME/cache/web_links.txt (по одной ссылке в строке).
"""
import base64
import concurrent.futures as cf
import html
import json
import os
import re
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths
import find_free_vpn as ffv

OUT = os.path.join(paths.CACHE, "web_links.txt")
CACHE = os.path.join(paths.CACHE, "web_pages.json")

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ssr|ss|hy2|hysteria2|hysteria|tuic|anytls|juicity)://[^\s\"'<>\\]{10,}")
B64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/=]{36,}")

DEFAULT_URLS = [
    "https://vpnkeys.me/",
    "https://vpnkeys.me/klyuchi/vless/",
    "https://vpnkeys.me/klyuchi/hysteria2/",
    "https://vpnkeys.me/country/de/",
    "https://vpnkeys.me/country/nl/",
    "https://vpnkeys.me/country/fi/",
    "https://vpnkeys.me/country/se/",
    "https://vpnkeys.me/country/us/",
]


def decode_blobs(text):
    """Декодирует встроенные base64-блоки (от 36 символов) и извлекает ссылки."""
    out = []
    for blob in B64_BLOCK_RE.findall(text):
        s = re.sub(r"\s+", "", blob)
        if len(s) % 4 != 0:
            s += "=" * (-len(s) % 4)
        try:
            txt = base64.b64decode(s).decode("utf-8", "replace")
            out += LINK_RE.findall(txt)
            if "proxies:" in txt or "proxy-groups:" in txt:
                out += ffv.clash_to_links(txt)
        except Exception:
            continue
    return out


def extract(text):
    """Извлекает и нормализует все ссылки из HTML-страницы."""
    links = LINK_RE.findall(text)
    links += decode_blobs(text)
    if "proxies:" in text or "proxy-groups:" in text:
        links += ffv.clash_to_links(text)

    # Чистим сущности &amp; и хвостовые символы
    cleaned = []
    for l in links:
        l = html.unescape(l).rstrip(".,;)'\"<>")
        cleaned.append(l)
    return cleaned


def _setup_scrapling():
    try:
        from scrapling.fetchers import Fetcher
        return True
    except ImportError:
        for vpath in ("/home/claw/.hermes/venvs/scrapling/lib/python3.11/site-packages",
                      os.path.expanduser("~/.hermes/venvs/scrapling/lib/python3.11/site-packages")):
            if os.path.exists(vpath) and vpath not in sys.path:
                sys.path.insert(0, vpath)
                try:
                    from scrapling.fetchers import Fetcher
                    return True
                except ImportError:
                    pass
    return False


_HAS_SCRAPLING = _setup_scrapling()


def fetch(url, stealth=False):
    """Многоуровневый загрузчик: Scrapling (lib или :11236) -> HTTP с Chrome-заголовками."""
    # 1. Прямой Scrapling через Python библиотеку (curl_cffi / patchright)
    if _HAS_SCRAPLING:
        if stealth:
            try:
                from scrapling.fetchers import StealthyFetcher
                page = StealthyFetcher.fetch(url, headless=True, network_idle=True,
                                             google_search=False, disable_resources=True,
                                             timeout=30000)
                return page.html_content
            except Exception:
                pass
        try:
            from scrapling.fetchers import Fetcher
            page = Fetcher.get(url, impersonate="chrome", stealthy_headers=True, timeout=25)
            return page.html_content
        except Exception:
            pass

    # 2. Локальный микросервис Scrapling Fastfetch (127.0.0.1:11236)
    try:
        req_payload = json.dumps({"url": url, "f": "raw", "mode": "browser" if stealth else "static", "timeout": 20}).encode()
        req = urllib.request.Request("http://127.0.0.1:11236/md", data=req_payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode())
            if data.get("success") and data.get("markdown"):
                return data["markdown"]
    except Exception:
        pass

    # 3. Нативный HTTP-клиент с заголовками Chrome 131
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Sec-CH-UA": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
    }
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", "replace")


def harvest(urls):
    """Параллельный сбор ссылок со страниц."""
    res, pages = {}, {}

    def scrape_one(u):
        try:
            content = fetch(u)
            links = extract(content)
            mode = "static"
            if len(links) < 3:
                try:
                    content_st = fetch(u, stealth=True)
                    st_links = extract(content_st)
                    if len(st_links) > len(links):
                        links = st_links
                        mode = "stealth"
                except Exception:
                    pass
            return u, {"mode": mode, "links": len(links)}, links
        except Exception as e:
            return u, {"error": str(e)[:80]}, []

    workers = min(10, max(1, len(urls)))
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for u, r, links in ex.map(scrape_one, urls):
            res[u] = r
            pages[u] = links
    return res, pages


def main(urls=None):
    if not urls:
        urls = DEFAULT_URLS
    res, pages = harvest(urls)
    for u, r in res.items():
        print(f"{r.get('mode','-'):>8} {r.get('links',0):>4}  {u} {r.get('error','')}")
    all_links = sorted({l for v in pages.values() for l in v})
    have = set()
    if os.path.exists(OUT):
        have = {l.strip() for l in open(OUT) if l.strip()}
    new = [l for l in all_links if l not in have]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "a", encoding="utf-8") as f:
        for l in new:
            f.write(l + "\n")
    json.dump({u: {"in_page": len(v)} for u, v in pages.items()},
              open(CACHE, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"\nвсего со страниц: {len(all_links)}, новых: {len(new)}, в файле: {len(have) + len(new)}")


if __name__ == "__main__":
    main(sys.argv[1:])
