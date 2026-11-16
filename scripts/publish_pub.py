#!/usr/bin/env python3
"""publish_pub.py — выложить подписку в публичный GitHub (repo или gist).

Цель: публичный репозиторий из GITHUB_REPO (raw.githubusercontent.com
доступен из РФ даже когда IP твоего VDS в бане).
Gist используется, если у токена есть scope `gist` (у fine-grained PAT его обычно нет).

Запуск: python3 publish_pub.py [--gist]
Состояние: $PROXY_SUB_HOME/secrets/pub_target.json
"""
import base64, json, os, subprocess, sys, time, urllib.error, urllib.request
import paths  # noqa: E402  (локальные пути проекта)

SUB = os.path.join(paths.OUT, "sub")
STATE = os.path.join(paths.SECRETS, "pub_target.json")
FILES = ["v2ray.txt", "clash.yaml", "nodes.txt", "hy2.txt", "hy2_nodes.txt"]


GIST_TOKEN_FILE = os.path.join(paths.SECRETS, "gist_token")


def gh_token():
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return os.environ.get("GITHUB_TOKEN", "")


def gist_token():
    """Отдельный токен только для gist (classic PAT со scope gist): gh-токен обычно без прав на gist."""
    if os.path.exists(GIST_TOKEN_FILE):
        t = open(GIST_TOKEN_FILE).read().strip()
        if t:
            return t
    return os.environ.get("GIST_TOKEN") or gh_token()


def token(kind="repo"):
    return gist_token() if kind == "gist" else gh_token()


def api(method, path, body=None, raw=False, kind="repo"):
    kw = {"method": method,
          "headers": {"Authorization": "Bearer " + token(kind),
                      "Accept": "application/vnd.github+json",
                      "User-Agent": "hermes-agent"}}
    if body is not None:
        kw["data"] = json.dumps(body).encode()
    # GitHub изредка отдаёт 401/5xx на валидный токен (наблюдалось 16.11.2026:
    # repo publish упал с 401, через минуту тот же токен работал). Одна попытка
    # на этом месте оставляла клиента со старым файлом, поэтому ретраим.
    last = None
    for attempt in range(3):
        req = urllib.request.Request("https://api.github.com" + path, **kw)
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                data = r.read()
                return data if raw else json.loads(data or b"{}")
        except urllib.error.HTTPError as e:
            body = e.read()[:200].decode("utf-8", "replace")
            last = f"{e.code} {body}"
            if e.code in (401, 403, 429, 500, 502, 503) and attempt < 2:
                time.sleep(4 * (attempt + 1))
                continue
            raise RuntimeError(last)
        except Exception as e:                      # таймауты/обрывы
            last = f"{type(e).__name__} {e}"
            if attempt < 2:
                time.sleep(3 * (attempt + 1))
                continue
            raise RuntimeError(last)
    raise RuntimeError(last or "unknown")


def payload():
    out = {}
    for f in FILES:
        p = os.path.join(SUB, f)
        if os.path.exists(p):
            out[f] = open(p, encoding="utf-8").read()
    # мобильная подписка (проверена с сети Yota) — отдельными файлами с префиксом,
    # чтобы клиент мог держать два профиля и не путать домашние ноды с мобильными
    yota = os.path.join(os.path.dirname(SUB.rstrip("/")), "sub-yota")
    for src, dst in (("nodes-yota.txt", "yota-nodes.txt"), ("yota.txt", "yota.txt"),
                     ("clash.yaml", "yota-clash.yaml")):
        p = os.path.join(yota, src)
        if os.path.exists(p):
            out[dst] = open(p, encoding="utf-8").read()
    return out


def to_repo(repo, branch="main", readme=None):
    """Один коммит на прогон (blobs -> tree -> commit -> ref), без трёх отдельных коммитов."""
    files = payload()
    if not files:
        raise RuntimeError("нечего публиковать: $PROXY_SUB_HOME/out/sub пуста")
    if readme:
        files["README.md"] = readme
    blobs = {}
    for name, content in files.items():
        r = api("POST", f"/repos/{repo}/git/blobs", {"content": content, "encoding": "utf-8"})
        blobs[name] = r["sha"]

    try:
        head = api("GET", f"/repos/{repo}/git/ref/heads/{branch}")["object"]["sha"]
    except Exception:
        head = None
    base_tree = None
    if head:
        base_tree = api("GET", f"/repos/{repo}/git/commits/{head}")["tree"]["sha"]

    tree_body = {"tree": [{"path": n, "mode": "100644", "type": "blob", "sha": s} for n, s in blobs.items()]}
    if base_tree:
        tree_body["base_tree"] = base_tree
    tree = api("POST", f"/repos/{repo}/git/trees", tree_body)["sha"]

    commit_body = {"message": "auto: обновление подписки " + time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
                   "tree": tree, "parents": [head] if head else []}
    commit = api("POST", f"/repos/{repo}/git/commits", commit_body)["sha"]

    if head:
        api("PATCH", f"/repos/{repo}/git/refs/heads/{branch}", {"sha": commit, "force": False})
    else:
        api("POST", f"/repos/{repo}/git/refs", {"ref": f"refs/heads/{branch}", "sha": commit})
    # read-back: успешный ответ GitHub ещё не значит, что ветка сдвинулась на наш коммит
    got = api("GET", f"/repos/{repo}/git/ref/heads/{branch}")["object"]["sha"]
    if got != commit:
        raise RuntimeError(f"ветка {branch} указывает на {got[:8]}, а не на наш {commit[:8]}")
    return [f"https://raw.githubusercontent.com/{repo}/{branch}/{n}" for n in files if n != "README.md"]


def to_gist():
    st = json.load(open(STATE)) if os.path.exists(STATE) else {}
    gid = st.get("gist_id", "")
    body = {"description": "Free proxy subscription (auto-refreshed daily)",
            "files": {k: {"content": v} for k, v in payload().items()}}
    if gid:
        api("PATCH", f"/gists/{gid}", body, kind="gist")
    else:
        body["public"] = True
        gid = api("POST", "/gists", body, kind="gist")["id"]
        st["gist_id"] = gid
    # read-back: raw.githubusercontent кэшируется, поэтому сверяем через API
    # сверяем все файлы: успешный PATCH ещё не значит, что гист принял каждый
    sent_all = payload()
    got_files = api("GET", f"/gists/{gid}", kind="gist")["files"]
    bad = [n for n, c in sent_all.items() if (got_files.get(n) or {}).get("content") != c]
    if bad:
        raise RuntimeError("gist не принял файлы: " + ", ".join(bad))
    user = api("GET", "/user", kind="gist")["login"]
    st["user"] = user
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(st, open(STATE, "w"), indent=1)
    os.chmod(STATE, 0o600)
    return [f"https://gist.githubusercontent.com/{user}/{gid}/raw/{n}" for n in payload()]


def main():
    if not payload():
        print("нет файлов подписки — сначала publish_sub.py")
        return 1
    use_gist = "--gist" in sys.argv
    try:
        urls = to_gist() if use_gist else to_repo(os.environ.get("GITHUB_REPO", ""))
    except Exception as e:
        msg = str(e)
        print(f"ошибка публикации: {msg}")
        if use_gist and "403" in msg:
            print("  → токену не хватает прав на gist. Создай classic PAT со scope gist:")
            print("    https://github.com/settings/tokens/new?scopes=gist&description=hermes-sub-gist")
            print("    затем: echo '<token>' > $PROXY_SUB_HOME/secrets/gist_token && chmod 600 $PROXY_SUB_HOME/secrets/gist_token")
        return 1
    print("подписка доступна:")
    for u in urls:
        print("  " + u)
    return 0


if __name__ == "__main__":
    sys.exit(main())
