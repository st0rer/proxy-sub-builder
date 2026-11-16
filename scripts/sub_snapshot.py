#!/usr/bin/env python3
"""sub_snapshot.py — снимки рабочей подписки и восстановление после сбоя.

Зачем: при пропаже интернета, выключении света или падении диска посреди прогона
можно остаться с обрезанным nodes.txt. Скрипт держит последние KEEP полных снимков
опубликованной подписки и умеет восстановить из самого свежего целого.

  save      — снять снимок текущей $PROXY_SUB_HOME/out/sub (после успешной публикации)
  check     — проверить, что текущая подписка цела (файлы есть, счётчики сходятся)
  restore   — вернуть последний целый снимок, если текущая битая
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import time
import paths  # noqa: E402  (локальные пути проекта)

HOME = os.path.expanduser("~")
SUB = os.environ.get("SUB_DIR") or os.path.join(paths.OUT, "sub")
GOOD = os.environ.get("SUB_GOOD") or os.path.join(HOME, "vpn_results", "good")
FILES = tuple(os.environ.get("SUB_FILES", "nodes.txt,v2ray.txt,clash.yaml,hy2.txt,hy2_nodes.txt,index.json,nodes-yota.txt").split(","))
KEEP = 6
MIN_NODES = int(os.environ.get("SUB_MIN_NODES", "40"))
MIHOMO = paths.binary("mihomo")


def nodes_count(path):
    try:
        # anytls/tuic/ssr тоже кладём в подписку — их надо считать, иначе счёт
        # расходится с index.json и снимок не снимается (16.11.2026: 13 в файле
        # против 11 посчитанных, два anytls выпали)
        return sum(1 for l in open(path) if l.strip().startswith(
            ("ss://", "ssr://", "vless://", "vmess://", "trojan://", "hy2://",
             "hysteria2://", "hysteria://", "anytls://", "tuic://", "juicity://")))
    except Exception:
        return 0


def check(quiet=False):
    """Возвращает (ok, причина)."""
    nodes_name = os.environ.get("SUB_NODES_FILE") or FILES[0]
    nodes = os.path.join(SUB, nodes_name)
    if not os.path.exists(nodes):
        return False, f"{nodes_name} отсутствует"
    n = nodes_count(nodes)
    if n < MIN_NODES:
        return False, f"в {nodes_name} только {n} нод"
    try:
        idx = json.load(open(os.path.join(SUB, "index.json")))
        if int(idx.get("count", 0)) != n:
            return False, f"index.json говорит {idx.get('count')}, а в файле {n}"
    except Exception as e:
        if not quiet:
            print(f"  (index.json не прочитан: {e})")
    clash = os.path.join(SUB, "clash.yaml")
    if not os.path.exists(clash):
        return False, "clash.yaml отсутствует"
    r = subprocess.run([MIHOMO, "-t", "-d", "/tmp", "-f", clash], capture_output=True, text=True)
    if r.returncode != 0:
        return False, "clash.yaml не проходит mihomo -t"
    return True, f"{n} нод"


def save():
    ok, why = check()
    if not ok:
        print(f"снимок НЕ снят: {why}")
        return 1
    stamp = time.strftime("%Y%m%d-%H%M%S")
    d = os.path.join(GOOD, stamp)
    os.makedirs(d, exist_ok=True)
    for f in FILES:
        src = os.path.join(SUB, f)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(d, f))
    with open(os.path.join(GOOD, "LAST"), "w") as fh:
        fh.write(stamp)
    snaps = sorted(glob.glob(os.path.join(GOOD, "2*")))
    for old in snaps[:-KEEP]:
        shutil.rmtree(old, ignore_errors=True)
    print(f"снимок {stamp}: {why}, хранится {len(snaps[-KEEP:])}")
    return 0


def last_good():
    p = os.path.join(GOOD, "LAST")
    if os.path.exists(p):
        d = os.path.join(GOOD, open(p).read().strip())
        if os.path.isdir(d):
            return d
    snaps = sorted(glob.glob(os.path.join(GOOD, "2*")))
    return snaps[-1] if snaps else None


def restore():
    d = last_good()
    if not d:
        print("восстановить нечем: снимков нет")
        return 1
    os.makedirs(SUB, exist_ok=True)
    for f in FILES:
        src = os.path.join(d, f)
        if os.path.exists(src):
            tmp = os.path.join(SUB, f + ".tmp")
            shutil.copy2(src, tmp)
            os.replace(tmp, os.path.join(SUB, f))
    ok, why = check()
    print(f"восстановлено из {os.path.basename(d)}: {why}")
    return 0 if ok else 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "save":
        return save()
    if cmd == "restore":
        return restore()
    ok, why = check()
    print(("подписка цела: " if ok else "подписка БИТАЯ: ") + why)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
