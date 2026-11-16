#!/usr/bin/env python3
"""gc_engine.py — сборка мусора движка и контроль памяти.

Что чистит:
  * рабочую папку скана (scan_*.yaml, batch_*.yaml, verify.*, livechk.*) старше N часов;
  * старые clean_*.txt в $PROXY_SUB_HOME/out (оставляет последние KEEP_CLEAN);
  * history.json — записи старше HISTORY_DAYS (иначе файл растёт вечно);
  * web_links.txt — дедуп и потолок строк;
  * refresh.log — ротация по размеру.

Ничего не удаляет из опубликованной подписки и из снимков good/ — это делает sub_snapshot.
"""
import glob
import json
import os
import shutil
import sys
import time
import paths  # noqa: E402  (локальные пути проекта)

HOME = os.path.expanduser("~")
SCRATCH = paths.SCRATCH
CACHE = paths.CACHE
RES = paths.OUT

KEEP_CLEAN = 8
HISTORY_DAYS = 30
WEB_MAX = 8000
LOG_MAX = 5 * 1024 * 1024
SCRATCH_HOURS = 2
PROTECT = {"geoip.metadb", "GeoSite.dat", "Country.mmdb", "mihomo", "_worker.js", "ha_worker.js"}


def mb(n):
    return f"{n / 1048576:.1f} МБ"


def rm(path):
    try:
        sz = os.path.getsize(path)
    except OSError:
        return 0
    try:
        os.remove(path)
        return sz
    except OSError:
        return 0


def gc_scratch(freed):
    if not os.path.isdir(SCRATCH):
        return
    cut = time.time() - SCRATCH_HOURS * 3600
    pats = ("scan_*.yaml", "scan_*.log", "batch_*.yaml", "batch_*.log",
            "verify.yaml", "verify.log", "livechk.yaml", "livechk.log",
            "_probe.yaml", "vlog.txt", "tr_test.*", "audit*.yaml",
            "mobile_candidates*.json", "test_out_*.json", "*.tmp")
    for pat in pats:
        for p in glob.glob(os.path.join(SCRATCH, pat)):
            if os.path.basename(p) in PROTECT:
                continue
            try:
                if os.path.getmtime(p) < cut:
                    freed["scratch"] += rm(p)
            except OSError:
                pass


def gc_clean(freed):
    files = sorted(glob.glob(os.path.join(RES, "clean_*.txt")))
    for p in files[:-KEEP_CLEAN] if len(files) > KEEP_CLEAN else []:
        freed["clean"] += rm(p)


def gc_history(freed):
    for fname in ("history.json", "mobile_history.json", "mobile_tested.json"):
        p = os.path.join(CACHE, fname)
        if not os.path.exists(p):
            continue
        try:
            h = json.load(open(p))
        except Exception:
            continue
        cut = time.time() - HISTORY_DAYS * 86400
        if isinstance(h, dict):
            new = {k: v for k, v in h.items() if (isinstance(v, (int, float)) and v >= cut) or (isinstance(v, dict) and v.get("ts", cut) >= cut)}
            if len(new) != len(h):
                tmp = p + ".tmp"
                json.dump(new, open(tmp, "w"))
                os.replace(tmp, p)
                freed["history"] += len(h) - len(new)


def gc_web(freed):
    p = os.path.join(CACHE, "web_links.txt")
    if not os.path.exists(p):
        return
    lines = [l.strip() for l in open(p) if l.strip().startswith(("ss://", "vless://", "vmess://",
                                                               "trojan://", "hy2://", "hysteria2://",
                                                               "tuic://", "anytls://"))]
    uniq = list(dict.fromkeys(reversed(lines)))      # свежие в конце файла -> они первыми
    uniq = list(reversed(uniq))[:WEB_MAX]
    if len(uniq) != len(lines):
        tmp = p + ".tmp"
        open(tmp, "w").write("\n".join(uniq) + "\n")
        os.replace(tmp, p)
        freed["web_dedup"] = len(lines) - len(uniq)


def gc_logs(freed):
    log_candidates = glob.glob(os.path.join(RES, "*.log"))
    for p in log_candidates:
        try:
            if os.path.exists(p) and os.path.getsize(p) > LOG_MAX:
                old = p + ".1"
                if os.path.exists(old):
                    os.remove(old)
                shutil.move(p, old)
                freed["log"] += 1
        except OSError:
            pass


def mem_state():
    info = {}
    try:
        for line in open("/proc/meminfo"):
            k, v = line.split(":", 1)
            info[k] = int(v.split()[0]) // 1024
    except Exception:
        return None
    try:
        ps = os.popen("ps -eo rss,args --sort=-rss | head -6").read().strip().splitlines()
    except Exception:
        ps = []
    return info, ps




def entry_size(p):
    if os.path.isfile(p):
        return os.path.getsize(p)
    total = 0
    for root, _dirs, files in os.walk(p):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def big_items(min_mb=50, days=3):
    """Крупные остатки в рабочей папке: чужие venv, старые сборки, дампы.
    Удаляются только при --aggressive и только если не менялись `days` дней."""
    out = []
    if not os.path.isdir(SCRATCH):
        return out
    cut = time.time() - days * 86400
    for name in os.listdir(SCRATCH):
        p = os.path.join(SCRATCH, name)
        if name in PROTECT:
            continue
        try:
            sz = entry_size(p)
            mt = os.path.getmtime(p)
        except OSError:
            continue
        if sz > min_mb * 1048576:
            out.append((sz, p, mt < cut))
    return sorted(out, reverse=True)


def free_gb(path="/"):
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize / 1073741824
    except Exception:
        return 99.0



def main():
    freed = {"scratch": 0, "clean": 0, "history": 0, "web_dedup": 0, "log": 0}
    gc_scratch(freed)
    gc_clean(freed)
    gc_history(freed)
    gc_web(freed)
    gc_logs(freed)

    aggressive = "--aggressive" in sys.argv or free_gb() < 3.0
    for sz, p, old in big_items():
        if aggressive and old:
            shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else rm(p)
            print(f"крупный остаток удалён: {os.path.basename(p)} ({mb(sz)})")
            freed["scratch"] += sz
        else:
            print(f"крупный остаток: {os.path.basename(p)} — {mb(sz)} (удалю при --aggressive/малом диске)")

    total = sum(v for k, v in freed.items() if k in ("scratch", "clean"))
    geo = 0
    for f in ("geoip.metadb", "GeoSite.dat", "Country.mmdb"):
        p = os.path.join(SCRATCH, f)
        if os.path.exists(p):
            geo += os.path.getsize(p)
    print(f"gc: освобождено {mb(total)} (гео-базы в работе {mb(geo)}, диск {free_gb():.1f} ГБ свободно)"
          f"{' + history -' + str(freed['history']) if freed['history'] else ''}"
          f"{' + web -' + str(freed['web_dedup']) if freed['web_dedup'] else ''}")
    ms = mem_state()
    if ms:
        info, ps = ms
        avail = info.get("MemAvailable", 0)
        print(f"память: свободно {avail} МБ, всего {info.get('MemTotal', 0)} МБ")
        for l in ps[:4]:
            print("   ", l[:100])
        if avail < 900:
            print("!! мало памяти (<900 МБ) — следующий прогон пойдёт с урезанной параллельностью")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
