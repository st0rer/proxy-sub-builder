#!/usr/bin/env python3
"""Генератор sing-box конфига из подписки st0rer/proxy-sub (v2ray.txt base64 или nodes.txt).

Использование:
    sbgen.py                          # все ноды
    sbgen.py --geo /tmp/sb-geo.json   # фильтр по стране выхода (исключить RU)
    sbgen.py --exclude RU,BY --strict  # строгий режим: выкинуть и непроверенные ноды
"""
import base64, json, os, sys, urllib.parse as up

SRC = os.environ.get("SINGBOX_SOURCE", "/tmp/ps_nodes.txt")
OUT = os.environ.get("SINGBOX_CONFIG", "/tmp/sb-config.json")

# РФ исключаем всегда: для обхода бесполезно, а Google/Gemini отдают геоблок
DEFAULT_EXCLUDE = {"RU"}


def parse_vless(u):
    p = up.urlparse(u)
    q = dict(up.parse_qsl(p.query))
    ob = {"type": "vless", "server": p.hostname, "server_port": p.port, "uuid": p.username}
    if q.get("flow"):
        ob["flow"] = q["flow"]
    sec = q.get("security", "none")
    if sec in ("tls", "reality"):
        tls = {"enabled": True}
        if q.get("sni"):
            tls["server_name"] = q["sni"]
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        if q.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}
        if q.get("allowInsecure") in ("1", "true"):
            tls["insecure"] = True
        if sec == "reality":
            tls["reality"] = {"enabled": True, "public_key": q.get("pbk", ""),
                              "short_id": q.get("sid", "")}
            if "utls" not in tls:  # reality требует uTLS, иначе "uTLS is required by reality client"
                tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
        ob["tls"] = tls
    t = q.get("type", "tcp")
    if t == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
    elif t == "ws":
        tr = {"type": "ws", "path": q.get("path", "/")}
        if q.get("host"):
            tr["headers"] = {"Host": q["host"]}
        ob["transport"] = tr
    elif t == "http":
        ob["transport"] = {"type": "http", "path": q.get("path", "/")}
    return ob


def parse_hy2(u):
    p = up.urlparse(u)
    q = dict(up.parse_qsl(p.query))
    ob = {"type": "hysteria2", "server": p.hostname, "server_port": p.port,
          "password": p.username or "",
          "tls": {"enabled": True, "insecure": q.get("insecure") in ("1", "true")}}
    if q.get("sni"):
        ob["tls"]["server_name"] = q["sni"]
    if q.get("obfs"):
        ob["obfs"] = {"type": q["obfs"], "password": q.get("obfs-password", "")}
    return ob


def parse_ss(u):
    raw = u[5:]
    if "@" not in raw:
        return None
    userinfo, hostpart = raw.rsplit("@", 1)
    # userinfo: либо base64(method:password), либо method:password (может быть %-encoded)
    dec = up.unquote(userinfo)
    if ":" not in dec:
        try:
            dec = base64.b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
        except Exception:
            return None
    method, password = dec.split(":", 1)
    hp = hostpart.split("/")[0].split("?")[0]
    host, _, port = hp.rpartition(":")
    return {"type": "shadowsocks", "server": host, "server_port": int(port),
            "method": method, "password": password}


def load_lines(path):
    raw = open(path, encoding="utf-8", errors="ignore").read()
    if "://" not in raw.strip()[:200]:
        raw = base64.b64decode(raw + "=" * (-len(raw.strip()) % 4)).decode("utf-8", "ignore")
    return [l.strip() for l in raw.splitlines() if l.strip()]


def key_of(ob):
    return f"{ob['type']}|{ob['server']}|{ob['server_port']}"


def sni_score(ob):
    """Пустой / 127.0.0.1 / голый IP хуже осмысленного домена — при дедупе берём лучший вариант."""
    sni = (ob.get("tls") or {}).get("server_name") or ""
    if not sni:
        return 0
    if sni in ("127.0.0.1", "localhost"):
        return 1
    if sni.replace(".", "").isdigit():
        return 1
    return 2


def main():
    args = sys.argv[1:]
    geo_path, strict, exclude, req_gemini = None, False, set(DEFAULT_EXCLUDE), False
    for i, a in enumerate(args):
        if a == "--geo" and i + 1 < len(args):
            geo_path = args[i + 1]
        elif a == "--exclude" and i + 1 < len(args):
            exclude = {c.strip().upper() for c in args[i + 1].split(",") if c.strip()}
        elif a == "--strict":
            strict = True
        elif a == "--require-gemini":
            req_gemini = True

    geo = {}
    if geo_path and os.path.exists(geo_path):
        geo = json.load(open(geo_path))

    out, tags, by_key = [], [], {}
    dropped = {"dup": 0, "geo": 0, "dead": 0, "parse": 0, "gemini": 0}
    for line in load_lines(SRC):
        scheme = line.split("://", 1)[0].lower()
        try:
            if scheme == "vless":
                ob = parse_vless(line)
            elif scheme in ("hy2", "hysteria2"):
                ob = parse_hy2(line)
            elif scheme == "ss":
                ob = parse_ss(line)
            else:
                continue
        except Exception:
            dropped["parse"] += 1
            continue
        if not ob or not ob.get("server"):
            dropped["parse"] += 1
            continue

        k = key_of(ob)
        if k in by_key:
            prev = by_key[k]
            if sni_score(ob) > sni_score(prev):
                t = prev.get("tag")
                prev.clear()
                prev.update(ob)
                prev["tag"] = t  # тег сохраняем, иначе рвутся member-ы urltest/selector
            dropped["dup"] += 1
            continue

        if geo_path:
            g = geo.get(k) or {}
            cc = (g.get("cc") or "").upper()
            if cc and cc in exclude:
                dropped["geo"] += 1
                continue
            if not cc and strict:
                dropped["dead"] += 1
                continue
            # ноды, которые Google/Gemini реально не отдают (403 = страна не поддерживается,
            # sorry = анти-бот по датацентровому IP), в пул не берём
            if req_gemini and g.get("gemini") != "ok":
                dropped["gemini"] = dropped.get("gemini", 0) + 1
                continue

        ob["tag"] = f"{ob['type'][:4]}-{len(out)}"
        tags.append(ob["tag"])
        out.append(ob)
        by_key[k] = ob

    # --- своя Cloudflare-нода (VLESS+WS+TLS через Workers) ---
    # Держим отдельно от подписки: её не фильтруем и ставим первой, потому что Google
    # принимает выход Cloudflare (доверенный CDN), а датацентровые IP free-нод часто
    # помечает как VPN/не ту страну. Если файла нет — просто пропускаем.
    own = []
    cfp = os.environ.get("SINGBOX_CF_NODE",
                         os.path.join(os.environ.get("VPN_SECRETS", os.path.expanduser("~/.hermes/secrets")),
                                      "cf_node.json"))
    if os.path.exists(cfp):
        try:
            c = json.load(open(cfp))
            own.append({"type": "vless", "tag": "cf",
                        "server": c.get("fast_ip", "8.47.69.7"), "server_port": 443,
                        "uuid": c["uuid"],
                        "tls": {"enabled": True, "server_name": c["host"],
                                "utls": {"enabled": True, "fingerprint": "chrome"}},
                        "transport": {"type": "ws", "path": c["ws_path"],
                                      "headers": {"Host": c["host"]}}})
        except Exception as e:
            print(f"own node skipped: {e}")

    # домены, которым нужен именно выход Cloudflare (Google отвергает VPS-ноды),
    # и которые при этом не тянут за собой видео-трафик YouTube
    GCP_DOMAINS = [
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
        "google.dev", "recaptcha.net",
    ]
    # фоновые опросы устройств и Chrome: через воркер им не нужно, Gemini они не обслуживают,
    # а квоту жгут постоянно (пуш, проверка связи, автофилл, апдейтер, Play)
    GCP_BYPASS = [
        "mtalk.google.com", "connectivitycheck.gstatic.com",
        "content-autofill.googleapis.com", "optimizationguide-pa.googleapis.com",
        "update.googleapis.com", "playstoregatewayadapter-pa.googleapis.com",
        "ssl.gstatic.com",
    ]

    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080},
            {"type": "tun", "tag": "tun-in", "interface_name": "sb0",
             "address": ["172.19.0.1/30"], "mtu": 1200,
             "auto_route": False, "strict_route": False, "stack": "gvisor"},
        ],
        "outbounds": own + out + [
            {"type": "urltest", "tag": "auto", "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204",
             "interval": "1m", "tolerance": 30},
            # gcp — «гугловый» путь: свой Cloudflare-выход, при падении уходит на пул free-нод
            {"type": "selector", "tag": "gcp",
             "outbounds": ["cf", "auto"] if own else ["auto"],
             "default": "cf" if own else "auto"},
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + tags, "default": "auto"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                # без sniff правила по домену не сработают: из tun приходит только IP
                {"inbound": ["tun-in"], "action": "sniff"},
                # исключения идут ПЕРВЫМИ: в правилах побеждает первое совпадение
                {"domain_suffix": GCP_BYPASS, "outbound": "proxy"},
                {"domain_suffix": GCP_DOMAINS, "outbound": "gcp"},
            ],
            "final": "proxy",
            "auto_detect_interface": True,
        },
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
    }
    json.dump(cfg, open(OUT, "w"), indent=2)
    print(f"nodes: {len(out)} ({', '.join(sorted({o['type'] for o in out}))})"
          f"{' + own: ' + ','.join(o['tag'] for o in own) if own else ''} -> {OUT}")
    print(f"google-set -> gcp ({len(GCP_DOMAINS)} доменов), "
          f"фон Google минус воркер ({len(GCP_BYPASS)}), остальное -> proxy(auto)")
    print(f"dropped: dup={dropped['dup']} geo={dropped['geo']} dead={dropped['dead']} "
          f"gemini={dropped['gemini']} parse={dropped['parse']}")


if __name__ == "__main__":
    main()
