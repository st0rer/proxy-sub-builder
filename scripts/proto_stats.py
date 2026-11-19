#!/usr/bin/env python3
"""Отдача по протоколам: сколько нод отправлено, сколько прошло TCP, сколько живых.

Читает снимки прогонов из ~/.cache/vpn-search/runs/*/run.json (их пишет
mobile_push.py) и, если снимков ещё нет, разовый прогон из /tmp/pian/.

Зачем: квоты в mobile_push задаются наугад — vless получает 220 слотов,
anytls 30. По факту vless даёт 1.3 % живых, а anytls в пуле просто нет.
Скрипт показывает реальную отдачу, чтобы квоты ставить по данным.
"""
import glob
import json
import os
import sys

CACHE = os.path.expanduser("~/.cache/vpn-search")


def fam(link):
    p = link.split("://")[0]
    return "hy2" if p in ("hy2", "hysteria2", "hysteria") else p


def load_runs():
    runs = []
    for f in sorted(glob.glob(os.path.join(CACHE, "runs", "*", "run.json"))):
        try:
            runs.append(json.load(open(f, encoding="utf-8")))
        except Exception:
            continue
    if not runs:
        sent_f, out_f = "/tmp/pian/sb_nodes.json", "/tmp/pian/out.json"
        if os.path.exists(sent_f) and os.path.exists(out_f):
            runs.append({"sent": json.load(open(sent_f)), "out": json.load(open(out_f))})
    return runs


def main():
    runs = load_runs()
    if not runs:
        print("нет данных: ни снимков прогонов, ни /tmp/pian/")
        return 1

    sent, checked, alive, gem = {}, {}, {}, {}
    for r in runs:
        for n in r["sent"]:
            f = fam(n["link"])
            sent[f] = sent.get(f, 0) + 1
        for x in r["out"]:
            f = fam(x["link"])
            checked[f] = checked.get(f, 0) + 1
            if x.get("delay"):
                alive[f] = alive.get(f, 0) + 1
            if x.get("gemini") == "ok":
                gem[f] = gem.get(f, 0) + 1

    print(f"прогонов учтено: {len(runs)}\n")
    print(f"{'протокол':<10}{'отправр':>9}{'провер.':>9}{'живых':>8}{'gemini':>8}"
          f"{'жив/пров':>10}{'gem/пров':>9}")
    for f in sorted(sent, key=lambda x: -checked.get(x, 0)):
        c, a, g = checked.get(f, 0), alive.get(f, 0), gem.get(f, 0)
        ra = f"{100*a/c:.1f}%" if c else "—"
        rg = f"{100*g/c:.1f}%" if c else "—"
        print(f"{f:<10}{sent.get(f,0):>9}{c:>9}{a:>8}{g:>8}{ra:>10}{rg:>9}")

    tc, ta, tg = sum(checked.values()), sum(alive.values()), sum(gem.values())
    print(f"\nвсего: проверено {tc}, живых {ta}, gemini=ok {tg}"
          f"  (живых {100*ta/tc:.1f} %, gemini {100*tg/tc:.1f} %)" if tc else "")

    print("\nсколько проверок стоит одна живая нода:")
    for f in sorted(checked, key=lambda x: -checked.get(x, 0)):
        a = alive.get(f, 0)
        print(f"  {f:<10} {checked[f]/a:>6.1f} проверок на живую" if a else
              f"  {f:<10}     — живых нет ({checked[f]} проверок впустую)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
