#!/usr/bin/env python3
"""xray_gate.py — второй фильтр настоящим Xray-core перед публикацией.

Зачем: движок проверяет ноды через mihomo (Clash Meta). Клиент пользователя — yptun
на Xray-core, и ядра расходятся: mihomo умеет PROXY-protocol, иначе кодирует uTLS,
по-разному поддерживает свежие транспорты. Нода, прошедшая mihomo, может не завестись
в Xray — и наоборот. Замер на 44 нодах: 3 расхождения (7 %), из них одно — TLS-timeout
при живом HTTP (наш HTTP-тест 204 такой провал не видит).

Пропускаем через Xray только кандидатов на публикацию (десятки, не десятки тысяч) —
это 10-60 секунд.

  xray_gate.py <файл со ссылками> [выходной файл]     # без второго аргумента — фильтр на месте
"""
import json
import os
import subprocess
import sys
import tempfile
import paths  # noqa: E402  (локальные пути проекта)

KNIFE = paths.binary("xray-knife")
MDELAY = os.environ.get("XRAY_GATE_DELAY", "6000")
THREADS = os.environ.get("XRAY_GATE_THREADS", "20")
ORDER = {"ss": 0, "vless": 1, "vmess": 2, "trojan": 3, "hy2": 4, "hysteria2": 4}


def gate(links):
    """Возвращает (прошли, провалились с причинами)."""
    if not links or not os.path.exists(KNIFE):
        return links, []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(links) + "\n")
        src = f.name
    out = src + ".json"
    try:
        subprocess.run([KNIFE, "http", "-f", src, "--mdelay", MDELAY,
                        "-t", THREADS, "--diagnose", "-x", "json", "-o", out],
                       capture_output=True, text=True, timeout=900)
        data = json.load(open(out))
    except Exception as e:
        print(f"xray-фильтр пропущен ({type(e).__name__}: {str(e)[:60]}) — публикую как есть")
        return links, []
    finally:
        for p in (src, out):
            try:
                os.unlink(p)
            except OSError:
                pass

    ok, bad = [], []
    status = {x.get("link"): x for x in data if isinstance(x, dict)}
    for l in links:
        x = status.get(l)
        if x is None or x.get("status") == "passed":
            ok.append(l)          # фильтр не знает про ноду — не наказываем
        else:
            bad.append((l, x.get("reason", "")[:70]))
    return ok, bad


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src = sys.argv[1]
    links = [l.strip() for l in open(src) if l.strip() and not l.startswith("#")]
    ok, bad = gate(links)
    for l, why in bad:
        print(f"  XRAY-FAIL {l[:60]} — {why}")
    dst = sys.argv[2] if len(sys.argv) > 2 else src
    tmp = dst + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(ok) + "\n")
    os.replace(tmp, dst)
    print(f"xray-фильтр: {len(links)} -> {len(ok)} (отброшено {len(bad)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
