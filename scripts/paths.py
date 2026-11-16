#!/usr/bin/env python3
"""paths.py — единственное место, где проект знает про расположение файлов.

Ничего личного: всё берётся из окружения, значения по умолчанию годятся для
обычной машины. Скрипты импортируют этот модуль и больше не содержат
абсолютных путей.
"""
import os
import shutil

HOME = os.path.expanduser("~")

# корень проекта: ~/.proxy-sub (переопределяется)
BASE = os.environ.get("PROXY_SUB_HOME", os.path.join(HOME, ".proxy-sub"))

# где лежат исполняемые sing-box / mihomo / xray-knife
BIN = os.environ.get("PROXY_SUB_BIN", os.path.join(HOME, "bin"))

# сам код (скрипты лежат рядом)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

CACHE = os.environ.get("PROXY_SUB_CACHE", os.path.join(BASE, "cache"))
OUT = os.environ.get("PROXY_SUB_OUT", os.path.join(BASE, "out"))
SCRATCH = os.environ.get("PROXY_SUB_SCRATCH", os.path.join(BASE, "scratch"))
SECRETS = os.environ.get("PROXY_SUB_SECRETS", os.path.join(BASE, "secrets"))

for _d in (BASE, CACHE, OUT, SCRATCH, SECRETS):
    os.makedirs(_d, exist_ok=True)


def binary(name):
    """Путь к движку: PROXY_SUB_BIN → PATH → имя как есть."""
    candidates = [name]
    if os.name == "nt" and not name.endswith(".exe"):
        candidates.append(name + ".exe")
    for cand in candidates:
        p = os.path.join(BIN, cand)
        if os.path.exists(p):
            return p
        w = shutil.which(cand)
        if w:
            return w
    return name


def secret(name, default=""):
    """Секрет из файла PROXY_SUB_SECRETS/<name> или из одноимённой переменной."""
    env = os.environ.get(name.upper())
    if env:
        return env
    p = os.path.join(SECRETS, name)
    if os.path.exists(p):
        with open(p) as f:
            return f.read().strip()
    return default
