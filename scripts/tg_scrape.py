#!/usr/bin/env python3
"""Сбор конфигов из публичных телеграм-каналов через веб-превью t.me/s/.

Проверено замерами 16.11.2026:
  * пагинация работает (?before=<min_id>, 20 постов/страница, ~200 ссылок);
  * но глубина почти бесполезна: 30 страниц одного канала дали 5 990 ссылок и
    **0 живых** из 15 проверенных трафиком (TCP при этом открывался у 8 — «порт
    открыт» ничего не значит). Живое живёт в первых страницах, глубина 2;
  * поиск внутри канала (?q=vless) не помогает: те же последние посты, только
    отфильтрованные — 76 ссылок против 200 на обычной странице;
  * в списке TGParse 188 каналов, раньше опрашивали 120;
  * упоминания в постах (t.me/<name>, @name) — рабочий источник роста, 5–11 на
    страницу: кандидат проверяется одной страницей и попадает в tg_discovered.json.

Использование: tg_scrape.py [каналов=188] [глубина=2]
Пишет: web_links.txt, tg_state.json, tg_discovered.json, tg_stats.json.
"""
import base64
import concurrent.futures as cf
import json
import os
import random
import re
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths

subs_lock = threading.Lock()

CACHE_DIR = paths.CACHE
OUT = os.path.join(CACHE_DIR, "web_links.txt")
STATE = os.path.join(CACHE_DIR, "tg_state.json")
DISCOVERED = os.path.join(CACHE_DIR, "tg_discovered.json")
STATS = os.path.join(CACHE_DIR, "tg_stats.json")
REJECTED = os.path.join(CACHE_DIR, "tg_rejected.json")   # общий с discover_channels.py
FETCHED_SUBS = os.path.join(CACHE_DIR, "tg_fetched_subs.json")
LIST_URL = "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/HEAD/telegramchannels.json"
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"}
LINK_RE = re.compile(r"(?:vless|vmess|trojan|ssr|ss|hy2|hysteria2|hysteria|tuic|anytls|juicity)://[^\s\"'<>\\]{10,}")
B64_RE = re.compile(r"[A-Za-z0-9+/=\r\n]{200,}")
POST_ID_RE = re.compile(r'data-post="[^/]+/(\d+)"')
MENTION_RE = re.compile(r'(?:https?://)?t\.me/(?:s/)?([A-Za-z0-9_]{4,32})')
SUB_URL_RE = re.compile(r'https?://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_\-./?=&%#@+]+', re.IGNORECASE)
SUB_IGNORE_DOMAINS = (
    "t.me", "telegram.me", "telegram.org", "telegra.ph", "youtube.com", "youtu.be",
    "twitter.com", "x.com", "instagram.com", "facebook.com", "vk.com", "tiktok.com",
    "play.google.com", "apps.apple.com", "google.com", "yandex.ru"
)
SUB_KEYWORDS = (
    "/sub", "subscribe", "token=", "workers.dev", "pages.dev", "raw.githubusercontent.com",
    "/api/v1/client/subscribe", "gist.githubusercontent.com", "pastebin.com/raw", "rentry.co"
)
SUB_EXTS = (".txt", ".yaml", ".yml", ".json")
RARE = ("anytls://", "tuic://", "hysteria://", "juicity://")
THREADS = int(os.environ.get("TG_THREADS", "16"))
RETRIES = 3
FIRST_DEPTH = int(os.environ.get("TG_FIRST_DEPTH", "6"))
MENTION_PROBE = int(os.environ.get("TG_MENTION_PROBE", "60"))
DEAD_AFTER = int(os.environ.get("TG_DEAD_AFTER", "6"))     # столько пустых прогонов — и канал не опрашиваем
REJECT_TTL = 3 * 86400                                     # пустые каналы-кандидаты перепроверяем раз в 3 дня


def load(path, default):
    if os.path.exists(path):
        try:
            return json.load(open(path))
        except Exception:
            return default
    return default


def save(path, data):
    tmp = path + ".tmp"
    json.dump(data, open(tmp, "w"))
    os.replace(tmp, path)


def channels(limit, stats):
    raw = urllib.request.urlopen(urllib.request.Request(LIST_URL, headers=UA), timeout=30).read()
    data = json.loads(raw.decode("utf-8", "ignore"))
    names = []
    for item in (data if isinstance(data, list) else data.get("channels", [])):
        name = item if isinstance(item, str) else (item.get("username") or item.get("name") or "")
        name = str(name).strip().lstrip("@").split("/")[-1]
        if re.fullmatch(r"[A-Za-z0-9_]{4,32}", name):
            names.append(name)
    extra = list(load(DISCOVERED, {}).keys())
    names = sorted(set(names) | set(extra))
    # канал, который DEAD_AFTER прогонов подряд ничего не дал, не тратим время
    alive_names = [n for n in names if stats.get(n, {}).get("zero_runs", 0) < DEAD_AFTER]

    def priority(n):
        st = stats.get(n)
        if not st:
            return 50.0 + random.random()  # новый канал — даем шанс
        verified = st.get("verified_alive", 0)
        last_l = st.get("last_links", 0)
        zeros = st.get("zero_runs", 0)
        return (verified * 200.0) + min(last_l, 30) - (zeros * 8.0) + random.random()

    alive_names.sort(key=priority, reverse=True)
    return alive_names[:limit]


def fetch(url):
    last = 0
    for attempt in range(RETRIES):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=25)
            return r.read().decode("utf-8", "ignore"), r.status
        except Exception as e:
            last = getattr(e, "code", 0)
            if last in (429, 500, 502, 503):
                time.sleep(3 * (attempt + 1) + random.random() * 2)
                continue
            return "", last
    return "", last


def is_candidate_sub(url):
    u = url.lower()
    if any(d in u for d in SUB_IGNORE_DOMAINS):
        return False
    if any(k in u for k in SUB_KEYWORDS):
        return True
    if any(u.split("?")[0].endswith(ext) for ext in SUB_EXTS):
        return True
    return False


def fetch_sub_links(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(512 * 1024)
        text = raw.decode("utf-8", "ignore")
        found = LINK_RE.findall(text)
        if not found:
            s = re.sub(r"\s+", "", text)
            try:
                dec = base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
                found = LINK_RE.findall(dec)
            except Exception:
                pass
        return [l.replace("&amp;", "&").rstrip(".,;)'") for l in found]
    except Exception:
        return []


def extract(html):
    links = LINK_RE.findall(html)
    for blob in B64_RE.findall(html):
        s = re.sub(r"\s+", "", blob)
        try:
            txt = base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
            links += LINK_RE.findall(txt)
        except Exception:
            pass
    return [l.replace("&amp;", "&").rstrip(".,;)'") for l in links]


def scan_channel(name, cursor, depth, fetched_subs=None):
    """Возвращает (ссылки, новый курсор, страниц, упомянутые каналы)."""
    links, seen_ids, pages, mentions = [], [], 0, set()
    before = None
    first_status = None
    if fetched_subs is None:
        fetched_subs = {}
    while pages < depth:
        url = f"https://t.me/s/{name}" + (f"?before={before}" if before else "")
        html, _status = fetch(url)
        if first_status is None:
            first_status = _status
        pages += 1
        if not html:
            break
        ids = [int(i) for i in POST_ID_RE.findall(html)]
        if not ids:
            break
        new_ids = [i for i in ids if cursor is None or i > cursor]
        if cursor is not None and not new_ids:
            break
        links += extract(html)

        # Вытаскиваем и скачиваем внешние подписки (workers.dev, raw.github, /sub)
        sub_cand = [m.group(0).rstrip(".,;)'\"<>") for m in SUB_URL_RE.finditer(html)]
        to_fetch = []
        for su in dict.fromkeys(sub_cand):
            if is_candidate_sub(su):
                with subs_lock:
                    if su not in fetched_subs:
                        fetched_subs[su] = int(time.time())
                        to_fetch.append(su)
        for su in to_fetch:
            sub_links = fetch_sub_links(su)
            if sub_links:
                links += sub_links

        mentions |= {m.lower() for m in MENTION_RE.findall(html)}
        seen_ids += new_ids
        before = min(ids) - 1
        time.sleep(random.uniform(0.05, 0.2))
    if first_status == 404:
        mentions.add("__404__")
    new_cursor = max(seen_ids) if seen_ids else cursor
    return links, new_cursor, pages, mentions


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 400
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    state = load(STATE, {})
    stats = load(STATS, {})
    discovered = load(DISCOVERED, {})
    now = int(time.time())
    fetched_subs = load(FETCHED_SUBS, {})
    fetched_subs = {k: v for k, v in fetched_subs.items() if now - v < 12 * 3600}
    try:
        names = channels(limit, stats)
    except Exception as e:
        print("не получил список каналов:", e, file=sys.stderr)
        return 1
    print(f"каналов к опросу: {len(names)} (найдено ранее: {len(discovered)})", file=sys.stderr)

    def work(name):
        cursor = state.get(name)
        d = FIRST_DEPTH if cursor is None else depth
        return (name, *scan_channel(name, cursor, d, fetched_subs))

    all_links, rare, mentions_all, empty = [], [], set(), []
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for name, links, new_cursor, _pages, mentions in ex.map(work, names):
            if new_cursor is not None:
                state[name] = new_cursor
            st = stats.get(name, {"runs": 0, "links": 0, "zero_runs": 0})
            st["runs"] += 1
            st["links"] += len(links)
            st["last_links"] = len(links)          # урожай последнего прогона
            st["zero_runs"] = st["zero_runs"] + 1 if not links else 0
            if "__404__" in mentions:
                mentions.discard("__404__")
                rejected[name] = now + 30 * 86400  # удаленный канал отсекаем на месяц
                st["zero_runs"] = 999
            stats[name] = st
            if links:
                all_links += links
                rare += [l for l in links if l.startswith(RARE)]
            else:
                empty.append(name)
            mentions_all |= (mentions - {name.lower()})

    # рост охвата: каналы, упомянутые в постах, проверяем одной страницей
    known = {n.lower() for n in names}
    rejected = load(REJECTED, {})
    now = int(time.time())
    rejected = {k: v for k, v in rejected.items() if now - v < REJECT_TTL}
    fresh = [m for m in sorted(mentions_all - known - set(rejected))
             if re.fullmatch(r"[A-Za-z0-9_]{4,32}", m)][:MENTION_PROBE]

    def probe_mention(name):
        links, _c, _p, _m = scan_channel(name, None, 1)
        return name, len(links)

    added, added_links = 0, []
    if fresh:
        with cf.ThreadPoolExecutor(max_workers=THREADS) as ex:
            for name, n in ex.map(probe_mention, fresh):
                if n:
                    discovered[name] = {"links": n, "seen": int(time.time())}
                    added += 1
                else:
                    rejected[name] = now

    have = {l.strip() for l in open(OUT)} if os.path.exists(OUT) else set()
    new = [l for l in dict.fromkeys(all_links) if l not in have]
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(OUT, "a") as f:
        for l in new:
            f.write(l + "\n")
    save(STATE, state)
    save(STATS, stats)
    save(DISCOVERED, discovered)
    save(REJECTED, rejected)
    save(FETCHED_SUBS, fetched_subs)
    print(f"каналов: {len(names)} | с новым: {len(names)-len(empty)} | без нового: {len(empty)} | "
          f"новых каналов: {added} | {time.time()-t0:.1f} c", file=sys.stderr)
    print(f"ссылок: {len(all_links)}, новых: {len(new)}, редких: {len(rare)}")
    for l in list(dict.fromkeys(rare))[:10]:
        print("  ", l[:110])
    return 0


if __name__ == "__main__":
    sys.exit(main())
