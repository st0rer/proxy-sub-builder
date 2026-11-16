#!/usr/bin/env python3
"""Добавляет проверенные вручную ноды в последний clean-файл перед публикацией.

Зачем: автоматический отбор отдаёт бюджет vless/hy2, а редкие протоколы
(anytls и пр.) до публикации не доходят. Скрипт берёт JSON от verify_batch
и дописывает живые ссылки в clean_YYYY-MM-DD.txt.

Использование: add_verified.py /tmp/rare_verified.json
"""
import glob
import json
import os
import sys
import paths  # noqa: E402

f_files = sorted(glob.glob(os.path.join(paths.OUT, "clean_*.txt")))
if not f_files:
    print("нет clean-файлов")
    raise SystemExit(1)
target = f_files[-1]
have = {l.strip() for l in open(target)}
rows = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else []
add = [r["link"] for r in rows if r.get("link") and r["link"] not in have]
if add:
    with open(target, "a") as fh:
        fh.write("\n".join(add) + "\n")
print(f"{os.path.basename(target)}: добавлено {len(add)}")
