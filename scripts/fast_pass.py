#!/usr/bin/env python3
"""Быстрый проход по самым урожайным каналам: свежие посты проверяются сразу.

Зачем: конфиг живёт часы, а полный отбор идёт раз в 6 часов — половина постов
умирает до проверки. Здесь берём только топ каналов из tg_stats.json, читаем
первую страницу (новые посты с прошлого раза), проверяем их тем же ядром
(sing-box) сразу и, если есть живые, перепубликовываем подписку.

Не заменяет полный прогон refresh_subs.sh — дополняет его между циклами.

Использование: fast_pass.py [каналов=15] [максимум_проверок=150]
"""
import json
import os
import subprocess
import sys
import time
import paths  # noqa: E402  (локальные пути проекта)

HOME = os.path.expanduser("~")
B = paths.SCRIPT_DIR
CACHE = paths.CACHE
SUB_DIR = os.path.join(HOME, "vpn_results/sub")

sys.path.insert(0, B)
import importlib.util as iu

spec = iu.spec_from_file_location("tgs", os.path.join(B, "tg_scrape.py"))
tgs = iu.module_from_spec(spec)
spec.loader.exec_module(tgs)


def load(path, default):
    if os.path.exists(path):
        try:
            return json.load(open(path))
        except Exception:
            return default
    return default


def save(path, data):
    tmp = path + ".tmp"
    json.dump(data, open(tmp, "w"), ensure_ascii=False)
    os.replace(tmp, path)


def top_channels(limit):
    stats = load(os.path.join(CACHE, "tg_stats.json"), {})
    rows = []
    for n, v in stats.items():
        if v.get("zero_runs", 0) >= 3:
            continue
        # Подтвержденные живые ноды дают максимальный приоритет
        alive = v.get("verified_alive", 0)
        recent = min(v.get("last_links", v.get("links", 0)), 50)
        score = (alive * 50) + recent
        if score > 0:
            rows.append((n, score))
    rows.sort(key=lambda kv: -kv[1])
    return [n for n, _ in rows[:limit]]


def fresh_links(channels):
    state = load(os.path.join(CACHE, "tg_state.json"), {})
    tested = set(load(os.path.join(CACHE, "tested.json"), []))
    alive = set(load(os.path.join(CACHE, "alive.json"), {}))
    published = {l.strip() for l in open(os.path.join(SUB_DIR, "nodes.txt")) if l.strip()} \
        if os.path.exists(os.path.join(SUB_DIR, "nodes.txt")) else set()
    out, scanned = [], 0
    link_origins = {}
    web = os.path.join(CACHE, "web_links.txt")
    have = {l.strip() for l in open(web)} if os.path.exists(web) else set()
    for name in channels:
        links, cursor, _pages, _m = tgs.scan_channel(name, state.get(name), 1)
        scanned += 1
        if cursor is not None:
            state[name] = cursor
        for l in dict.fromkeys(links):
            link_origins[l] = name
            if l in tested or l in alive or l in published:
                continue
            out.append(l)
            have.add(l)
    # кандидаты кладём и в общий пул: иначе посты, которые fast_pass не успел
    # проверить, теряются навсегда — курсор каналов уже сдвинут
    if out:
        with open(web, "a") as f:
            for l in dict.fromkeys(out):
                f.write(l + "\n")
    tgs.save(os.path.join(CACHE, "tg_state.json"), state)
    return out, scanned, link_origins


VERIFIABLE = ("vless://", "vmess://", "trojan://", "ss://", "anytls://", "tuic://",
              "hy2://", "hysteria2://")   # ровно то, что умеет sing-box в sb_verify


def verify(links, limit):
    # фильтр до обрезки по лимиту: иначе первые N могут оказаться ssr/hysteria v1,
    # которые ядро не умеет, и прогон закончится «нечего проверять»
    links = [l for l in links if l.startswith(VERIFIABLE)]
    path = os.path.join(paths.SCRATCH, "fast_pass_cand.txt")
    with open(path, "w") as f:
        for l in links[:limit]:
            f.write(l + "\n")
    env = dict(os.environ, SB_TIMEOUT="6", SB_PAR="16", SB_SPEED_TOP="6")
    r = subprocess.run([sys.executable, os.path.join(B, "sb_verify.py"), path, str(limit)],
                       capture_output=True, text=True, env=env, timeout=900)
    rows = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows, r.stderr[-300:]


def merge_and_publish(rows, alive_links, link_origins=None):
    tested = load(os.path.join(CACHE, "tested.json"), [])
    tested_set = set(tested)
    alive_map = load(os.path.join(CACHE, "alive.json"), {})
    verified = load(os.path.join(CACHE, "verified.json"), [])
    vf_by_link = {v["link"]: v for v in verified if isinstance(v, dict) and v.get("link")}
    stats = load(os.path.join(CACHE, "tg_stats.json"), {})
    stats_changed = False
    for r in rows:
        link = r["link"]
        tested_set.add(link)
        if r.get("alive"):
            alive_map[link] = r.get("delay", 0)
            vf_by_link[link] = {"link": link, "proto": r.get("proto", ""),
                                "delay": r.get("delay", 0),
                                "speed_MBps": float(r.get("speed_MBps") or 0)}
            if link_origins and link in link_origins:
                ch = link_origins[link]
                if ch in stats:
                    stats[ch]["verified_alive"] = stats[ch].get("verified_alive", 0) + 1
                    stats_changed = True
    if stats_changed:
        save(os.path.join(CACHE, "tg_stats.json"), stats)
    save(os.path.join(CACHE, "tested.json"), list(tested_set))
    save(os.path.join(CACHE, "alive.json"), alive_map)
    save(os.path.join(CACHE, "verified.json"), list(vf_by_link.values()))

    # строки для publish_sub: текущая подписка (без замера — не отсекается) + свежие живые
    current = [l.strip() for l in open(os.path.join(SUB_DIR, "nodes.txt")) if l.strip()]
    merged, seen = [], set()

    def row(link, speed=None):
        r = {"link": link, "delay": alive_map.get(link, 1)}
        if speed:                      # 0.0 — значит скорость не мерили;
            r["speed"] = float(speed)  # publish_sub выбрасывает 0.0, поэтому не пишем ключ
        return r

    for r in [row(l) for l in current] + [row(l, vf_by_link.get(l, {}).get("speed_MBps")) for l in alive_links]:
        if r["link"] in seen:
            continue
        seen.add(r["link"])
        merged.append(r)
    path = os.path.join(paths.SCRATCH, "fast_pass_merged.json")
    save(path, merged)
    return path, len(merged)


def main():
    n_chan = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    n_links = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    t0 = time.time()
    channels = top_channels(n_chan)
    if not channels:
        print("нет статистики каналов — сначала прогоните tg_scrape.py")
        return 1
    links, scanned, link_origins = fresh_links(channels)
    print(f"каналов: {scanned}, свежих ссылок: {len(links)}")
    pend_path = os.path.join(CACHE, "fast_pass_pending.json")
    pending = load(pend_path, [])
    # очередь идёт первой: если новых постов нет, всё равно доверяем прошлое
    links = [l for l in dict.fromkeys(pending + links)]
    if not links:
        print("новых постов нет и очередь пуста")
        return 0
    if pending:
        print(f"из очереди прошлого прогона: {len(pending)}")
    verifiable = [l for l in links if l.startswith(VERIFIABLE)]
    skipped = [l for l in links if not l.startswith(VERIFIABLE)]
    todo, rest = verifiable[:n_links], verifiable[n_links:]
    save(pend_path, rest[:3000])
    if rest:
        print(f"в очереди на следующий прогон: {len(rest)}")
    if skipped:
        print(f"не проверить ядром (ssr/hysteria v1/juicity): {len(skipped)}")
    rows, err = verify(todo, n_links)
    alive = [r["link"] for r in rows if r.get("alive")]
    print(f"проверено {len(rows)}, живых {len(alive)}" + (f" | {err.strip()[:80]}" if err else ""))
    if not alive:
        print("живых нет — подписку не трогаю")
        merge_and_publish(rows, [], link_origins)
        return 0
    merged_path, total = merge_and_publish(rows, alive, link_origins)
    env = dict(os.environ, SUB_FROM=merged_path)
    for script, extra, label in (("publish_sub.py", [], "сайт"), ("publish_pub.py", [], "репозиторий"),
                                 ("publish_pub.py", ["--gist"], "гист")):
        r = subprocess.run([sys.executable, os.path.join(B, script)] + extra,
                           capture_output=True, text=True, env=env, timeout=600)
        tail = (r.stdout.strip().splitlines() or [""])[-1]
        print(f"  {label}: rc={r.returncode} {tail[:100]}")
        if r.returncode not in (0, 2):
            print("   stderr:", r.stderr.strip()[-200:])
    print(f"готово за {time.time()-t0:.0f} c: {len(alive)} новых живых, в подписке {total} строк")
    return 0


if __name__ == "__main__":
    sys.exit(main())
