#!/usr/bin/env python3
"""make_sr.py — подписка, которую гарантированно съедает Shadowrocket (iOS).

Почему отдельный файл: Shadowrocket разбирает подписку строго, и одна строка с
незнакомой схемой может сломать импорт целиком. В нашей мобильной подписке таких
две: `hy2://` (нестандартное сокращение, стандарт — `hysteria2://`) и `anytls://`
(поддержка появилась поздно и не во всех сборках).

Делает два файла в каталоге подписки:
  yota-sr.txt        — base64 (то, что вставляют в Shadowrocket «Subscribe»)
  yota-sr-nodes.txt  — тот же список открытым текстом (для отладки и других клиентов)

Использование: make_sr.py <каталог подписки> [nodes-yota.txt]
"""
import base64
import os
import sys

# Shadowrocket стабильно понимает: ss, ssr, vmess, vless, trojan, hysteria2, tuic, socks
SR_KEEP = {"vless", "vmess", "trojan", "ss", "ssr", "tuic", "socks"}
SCHEME_FIX = {"hy2": "hysteria2"}


def convert(link: str):
    scheme, _, rest = link.partition("://")
    scheme = scheme.lower()
    if scheme in SCHEME_FIX:
        scheme = SCHEME_FIX[scheme]
    if scheme not in SR_KEEP:
        return None
    return f"{scheme}://{rest}"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    sub = sys.argv[1]
    src = os.path.join(sub, sys.argv[2] if len(sys.argv) > 2 else "nodes-yota.txt")
    links = [l.strip() for l in open(src) if "://" in l]
    out, dropped = [], {}
    for l in links:
        c = convert(l)
        if c:
            out.append(c)
        else:
            s = l.split("://")[0]
            dropped[s] = dropped.get(s, 0) + 1
    if not out:
        print("нечего публиковать: ни одна нода не подходит для Shadowrocket", file=sys.stderr)
        return 1
    plain = "\n".join(out) + "\n"
    with open(os.path.join(sub, "yota-sr-nodes.txt"), "w") as f:
        f.write(plain)
    with open(os.path.join(sub, "yota-sr.txt"), "w") as f:
        f.write(base64.b64encode(plain.encode()).decode())
    print(f"Shadowrocket-подписка: {len(out)} нод"
          + (f", отброшено {dropped}" if dropped else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
