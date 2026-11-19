#!/usr/bin/env python3
"""
find_free_vpn.py — поиск рабочих бесплатных VLESS/Hysteria2 конфигов для страны.

Usage:
  python3 find_free_vpn.py TR [--proto vless,hy2] [--top 10] [--no-cache] [--keep-mihomo]

Что делает:
  1. Собирает ссылки из агрегаторов (igareck, 0xRadikal, v2rayfree)
  2. Фильтрует по стране (флаг/название/код/китайский)
  3. Генерирует mihomo YAML (валидация sid, поддержка xhttp/ws/grpc)
  4. url-test всех прокси параллельно через mihomo
  5. Переключает группу на каждый живой прокси и проверяет РЕАЛЬНЫЙ выход (ip-api)
  6. Сохраняет: $PROXY_SUB_HOME/out/<CC>_working.txt, <CC>_topN.txt, <CC>_report.json

Зависимости: ~/bin/mihomo (качается сам при отсутствии). Требует Python 3.8+.
"""
import argparse, base64, gzip, html, json, os, re, shutil, subprocess, sys, time, urllib.parse, urllib.request, zlib

# ---------------------------------------------------------------- конфиг
HOME = os.path.expanduser('~')
BIN_DIR = os.path.join(HOME, 'bin')
MIHOMO = os.path.join(BIN_DIR, 'mihomo')
RESULT_DIR = os.path.join(HOME, 'vpn_results')
CACHE_DIR = os.path.join(HOME, '.cache', 'vpn-search')
CACHE_TTL = 30 * 60  # 30 мин

MIXED_PORT = 7890
API_PORT = 9097
GROUP = 'CC-TEST'
TEST_URL = 'http://www.gstatic.com/generate_204'

SOURCES = [
    # (name, url, format) format: 'plain' | 'base64'
    ('igareck', 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt', 'plain'),
    ('igareck_ss', 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt', 'plain'),
    ('radikal', 'https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt', 'plain'),
    ('mhdi', 'https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix', 'plain'),
    ('nyein', 'https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/All_Configs_Sub.txt', 'plain'),
    ('awesome_vpn', 'https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all', 'base64'),
    ('proxypool', 'https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt', 'base64'),
    ('matin', 'https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt', 'plain'),
    ('mahan', 'https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt', 'plain'),
    ('alirewa', 'https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt', 'plain'),
    # Новые высокодоходные источники (13k+ проверенных нод: hy2/tuic/vless/ss)
    ('coldwater_hy2', 'https://raw.githubusercontent.com/coldwater-10/V2ray-Config-Lite/main/Splitted-By-Protocol/hysteria2.txt', 'base64'),
    ('coldwater_vl', 'https://raw.githubusercontent.com/coldwater-10/V2ray-Config-Lite/main/Splitted-By-Protocol/vless.txt', 'base64'),
    ('coldwater_tuic', 'https://raw.githubusercontent.com/coldwater-10/V2ray-Config-Lite/main/Splitted-By-Protocol/tuic.txt', 'base64'),
    ('au1rxx', 'https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt', 'base64'),
    ('barry_vl', 'https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt', 'plain'),
    ('barry_ss', 'https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt', 'plain'),
    ('freenodes', 'https://raw.githubusercontent.com/Barabama/FreeNodes/master/nodes/merged.txt', 'plain'),
    # Проверено 2026-11-19: крупнейшие свежие пулы (33k+ нод, 8.7k Reality, 4.7k SS, 790 Hy2)
    ('nikita_1', 'https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt', 'plain'),
    ('nikita_3', 'https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/3.txt', 'plain'),
    ('byewhitelists', 'https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/main/ByeWhiteLists2.txt', 'plain'),
    ('yitong', 'https://raw.githubusercontent.com/yitong2333/proxy-minging/main/v2ray.txt', 'plain'),
    ('delta_all', 'https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/all_configs.txt', 'plain'),
    ('nomorewalls', 'https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt', 'base64'),
    ('flat447_white', 'https://raw.githubusercontent.com/FLAT447/v2ray-lists/main/WHITE_FULL.txt', 'plain'),
    ('acymz', 'https://raw.githubusercontent.com/acymz/AutoVPN/main/data/V2.txt', 'base64'),
    ('youfoundamin', 'https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt', 'plain'),
    ('cidvpn', 'https://raw.githubusercontent.com/CidVpn/cid-vpn-config/main/general.txt', 'plain'),
    # Свежие репозитории (ноябрь 2026): Mahdi0024, tahmaseb, nyeinkokoaung, anaer, ermaozi
    ('mahdi0024', 'https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt', 'plain'),
    ('tahmaseb_ss', 'https://raw.githubusercontent.com/tahmaseb73/configs-collector-v2ray/main/data/sub/protocols/shadowsocks.txt', 'plain'),
    ('coldwater_ss', 'https://raw.githubusercontent.com/coldwater-10/V2ray-Config-Lite/main/Splitted-By-Protocol/ss.txt', 'plain'),
    ('nyeinkoko_all', 'https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/All_Configs_Sub.txt', 'plain'),
    ('nyeinkoko_vl', 'https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/Splitted-By-Protocol/vless.txt', 'plain'),
    ('anaer_clash', 'https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml', 'plain'),
    ('ermaozi_v2', 'https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt', 'plain'),
    ('ermaozi_clash', 'https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml', 'plain'),
]

# Прямые файлы по стране (если есть в этих репо) — проверяются до общего сбора.
# Формат: (репо, путь-шаблон, названия-файлов или None если код-страны)
COUNTRY_SOURCES = [
    # F0rc3Run: splitted-by-country/<CountryName>.txt (словами)
    ('F0rc3Run', 'https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-country/{name}.txt', 'name'),
    # v2go: Splitted-By-Country/<CC>.txt (код страны)
    ('v2go', 'https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Country/{cc}.txt', 'cc'),
    # Au1rxx: output/by-country/v2ray-base64-<CC>.txt (verified, base64)
    ('au1rxx', 'https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/v2ray-base64-{cc}.txt', 'cc'),
]

# Полные имена стран для F0rc3Run (словами)
COUNTRY_NAMES = {
    'TR': ['Turkey', 'Türkiye'], 'DE': ['Germany'], 'FR': ['France'], 'US': ['United_States'],
    'GB': ['United_Kingdom'], 'JP': ['Japan'], 'NL': ['The_Netherlands'], 'SG': ['Singapore'],
    'KR': ['South_Korea'], 'RU': ['Russia'], 'UA': ['Ukraine'], 'KZ': ['Kazakhstan'],
    'PL': ['Poland'], 'SE': ['Sweden'], 'FI': ['Finland'], 'ES': ['Spain'], 'IT': ['Italy'],
    'CA': ['Canada'], 'AU': ['Australia'], 'IN': ['India'], 'BR': ['Brazil'], 'TH': ['Thailand'],
    'MY': ['Malaysia'], 'ID': ['Indonesia'], 'VN': ['Vietnam'], 'AE': ['UAE'], 'SA': ['Saudi_Arabia'],
    'IL': ['Israel'], 'RO': ['Romania'], 'BG': ['Bulgaria'], 'CZ': ['Czechia'], 'HU': ['Hungary'],
    'AT': ['Austria'], 'CH': ['Switzerland'], 'BE': ['Belgium'], 'DK': ['Denmark'], 'NO': ['Norway'],
    'PT': ['Portugal'], 'GR': ['Greece'], 'IE': ['Ireland'], 'NZ': ['New_Zealand'], 'MX': ['Mexico'],
    'AR': ['Argentina'], 'CL': ['Chile'], 'CO': ['Colombia'], 'ZA': ['South_Africa'], 'EG': ['Egypt'],
    'LT': ['Lithuania'], 'LV': ['Latvia'], 'EE': ['Estonia'], 'MD': ['Moldova'], 'GE': ['Georgia'],
    'AM': ['Armenia'], 'AZ': ['Azerbaijan'], 'HK': ['Hong_Kong'], 'TW': ['Taiwan'], 'PK': ['Pakistan'],
}

# Страна: коды для фильтра. Флаг ищется по эмодзи/названию/коду/китайскому.
# Китайские названия для поиска в агрегаторах.
CN_NAMES = {
    'TR': '土耳其', 'DE': '德国', 'FR': '法国', 'US': '美国', 'GB': '英国',
    'JP': '日本', 'NL': '荷兰', 'SG': '新加坡', 'KR': '韩国', 'RU': '俄罗斯',
    'UA': '乌克兰', 'KZ': '哈萨克斯坦', 'PL': '波兰', 'SE': '瑞典', 'FI': '芬兰',
}

# ---------------------------------------------------------------- helpers
def log(msg):
    print(msg, flush=True)

def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def b64_decode(raw: bytes) -> str:
    s = raw.strip()
    try:
        dec = base64.b64decode(s + b'=' * (-len(s) % 4)).decode(errors='ignore')
        return dec
    except Exception:
        return ''

def decode_sn(link: str) -> str:
    """Декодирует sn://subscription?<base64-zlib> → найденный http URL."""
    if not link.startswith('sn://'):
        return None
    b64 = link.split('?', 1)[1].replace('-', '+').replace('_', '/')
    b64 += '=' * (-len(b64) % 4)
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return None
    for wbits in (47, 31, 15, -15):
        try:
            dec = zlib.decompress(raw, wbits)
            m = re.search(rb'https?://[^\x00-\x1f\s]+', dec)
            if m:
                return m.group(0).decode()
        except Exception:
            pass
    return None

def country_match(link: str, cc: str) -> bool:
    """Проверяет, помечена ли ссылка нужной страной (флаг/название/код/китайский)."""
    remark = link.split('#')[-1] if '#' in link else ''
    try:
        remark_dec = urllib.parse.unquote(remark)
    except Exception:
        remark_dec = remark
    full = link + ' ' + remark_dec
    # флаг страны из эмодзи: 🇹🇷 = U+1F1F9 U+1F1F7
    a, b = ord('🇦') + (ord(cc[0]) - ord('A')), ord('🇦') + (ord(cc[1]) - ord('A'))
    flag = chr(a) + chr(b)
    if flag in full:
        return True
    # URL-encoded флаг
    fa = '%F0%9F%87%' + hex(0x90 + (ord(cc[0]) - ord('A')))[2:].upper()
    fb = '%F0%9F%87%' + hex(0x90 + (ord(cc[1]) - ord('A')))[2:].upper()
    if fa in link and fb in link:
        return True
    # код страны в ремарке (границы: пробел, |, [, конец)
    if re.search(r'(^|[|\[( ])' + re.escape(cc) + r'($|[|\])\- ])', remark_dec):
        return True
    # китайское название
    if cc in CN_NAMES and CN_NAMES[cc] in full:
        return True
    return False

# Только vless-специфичные маркеры: "type=ws"/"type=grpc" есть и у trojan, и у vmess,
# из-за них trojan переписывался в vless (и наоборот) и ноды терялись.
VLESS_MARKERS = ("security=", "encryption=", "pbk=", "reality", "flow=", "type=xhttp")
UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')


def normalize_link(l):
    """Чинит перепутанные схемы: в бесплатных списках vless-ссылки массово
    лежат под vmess://, ss:// и trojan://. Признак — uuid@host:port?с-параметрами."""
    for bad in ("vmess://", "ss://", "trojan://"):
        if l.startswith(bad):
            body = l[len(bad):]
            head = body.split("#", 1)[0]
            userinfo = head.split("@", 1)[0]
            looks_vless = bool(UUID_RE.match(urllib.parse.unquote(userinfo)))
            if "@" in head and "?" in head and (looks_vless or any(k in head for k in VLESS_MARKERS)):
                return "vless://" + body
    return l


def clash_to_links(text: str):
    """Извлекает URI-ссылки из Clash YAML подписки/файла."""
    links = []
    data = None
    try:
        import yaml
        data = yaml.safe_load(text)
    except Exception:
        pass

    if isinstance(data, dict) and isinstance(data.get("proxies"), list):
        for p in data["proxies"]:
            if not isinstance(p, dict):
                continue
            t = str(p.get("type", "")).lower()
            server = str(p.get("server", "")).strip()
            port = p.get("port")
            name = str(p.get("name", "")).strip()
            if not server or not port:
                continue
            try:
                port = int(port)
                if not (1 <= port <= 65535):
                    continue
            except Exception:
                continue

            if t == "vless" and p.get("uuid"):
                q = []
                if p.get("tls"):
                    if p.get("reality-opts"):
                        q.append("security=reality")
                        ro = p["reality-opts"]
                        if ro.get("public-key"):
                            q.append(f"pbk={ro['public-key']}")
                        if ro.get("short-id"):
                            q.append(f"sid={ro['short-id']}")
                    else:
                        q.append("security=tls")
                sni = p.get("servername") or p.get("sni")
                if sni:
                    q.append(f"sni={sni}")
                net = p.get("network") or "tcp"
                q.append(f"type={net}")
                ws_opts = p.get("ws-opts") or {}
                if net == "ws" and ws_opts.get("path"):
                    q.append(f"path={ws_opts['path']}")
                if p.get("flow") and p["flow"] == "xtls-rprx-vision":
                    q.append("flow=xtls-rprx-vision")
                query = ("?" + "&".join(q)) if q else ""
                links.append(f"vless://{p['uuid']}@{server}:{port}{query}#{name}")
            elif t in ("hy2", "hysteria2") and p.get("password"):
                sni = p.get("sni") or p.get("servername", "")
                q = f"?sni={sni}" if sni else ""
                links.append(f"hysteria2://{p['password']}@{server}:{port}/{q}#{name}")
            elif t in ("ss", "shadowsocks") and p.get("password") and p.get("cipher"):
                userinfo = base64.b64encode(f"{p['cipher']}:{p['password']}".encode()).decode()
                links.append(f"ss://{userinfo}@{server}:{port}#{name}")
            elif t == "trojan" and p.get("password"):
                sni = p.get("sni") or p.get("servername", "")
                q = f"?sni={sni}" if sni else ""
                links.append(f"trojan://{p['password']}@{server}:{port}{q}#{name}")
            elif t == "tuic" and p.get("uuid") and p.get("password"):
                links.append(f"tuic://{p['uuid']}:{p['password']}@{server}:{port}#{name}")
    return links


def extract_links(text: str):
    """Достаёт vless/hy2/hysteria2 ссылки из текста (plain, base64 или clash yaml)."""
    links = []
    for m in re.finditer(r'(?:vless|vmess|hy2|hysteria2|hysteria|ss|ssr|trojan|tuic|anytls|juicity)://[^\s<>"\'\\]+', text):
        links.append(html.unescape(m.group(0)))
    if "proxies:" in text or "proxy-groups:" in text:
        links.extend(clash_to_links(text))
    return links

def parse_vless(url):
    if '#' in url:
        url, remark = url.split('#', 1)
    else:
        remark = ''
    m = re.match(r'vless://([^@]+)@(\[[0-9a-fA-F:]+\]|[^:/?#]+):(\d+)(\?.*)?', url)
    if not m:
        return None
    uuid, host, port = m.group(1), m.group(2).strip('[]'), int(m.group(3))
    q = urllib.parse.parse_qs((m.group(4) or '?').lstrip('?'))
    def g(k, d=None): return (q.get(k) or [d])[0]
    sid = g('sid', '')
    # sid должен быть hex ЧЁТНОЙ длины (mihomo: 2/4/6/8/10/12/14/16 символов)
    if sid and (not re.fullmatch(r'[0-9a-fA-F]+', sid) or len(sid) % 2 != 0 or len(sid) > 16):
        sid = ''
    return {
        'uuid': uuid, 'host': host, 'port': port,
        'type': g('type', 'tcp'), 'security': g('security', 'none'),
        'flow': g('flow', ''), 'sni': g('sni', ''),
        'fp': g('fp', 'chrome'), 'pbk': g('pbk', ''),
        'sid': sid, 'serviceName': g('serviceName', ''),
        'path': g('path', ''), 'hosthdr': g('host', ''),
        'alpn': g('alpn', ''), 'mode': g('mode', ''), 'remark': remark.strip(),
    }

def parse_hy2(url):
    if '#' in url:
        url, remark = url.split('#', 1)
    else:
        remark = ''
    m = re.match(r'(?:hy2|hysteria2|hysteria)://(.+)@([^:@/]+|\[[0-9a-fA-F:]+\]):(\d+)/?(?:\?(.*))?$', url)
    if not m:
        # пароль может содержать '@' — делим по последнему
        m = re.match(r'(?:hy2|hysteria2|hysteria)://(.+)@(.+):(\d+)/?(?:\?(.*))?$', url)
        if not m:
            return None
    auth, host, port = m.group(1), m.group(2).strip('[]'), int(m.group(3))
    q = urllib.parse.parse_qs(m.group(4) or '')
    def g(k, d=None): return (q.get(k) or [d])[0]
    return {
        'auth': auth, 'host': host, 'port': port,
        'sni': g('sni', host), 'insecure': g('insecure', '0') in ('1', 'true', 'yes'),
        'obfs': g('obfs', ''), 'obfs_pass': g('obfs-password', ''),
        'remark': remark.strip(),
    }

def _split_hostport(hp):
    """host:port с поддержкой [IPv6]:port."""
    m = re.match(r'^(\[[0-9a-fA-F:]+\]|[^:]+):(\d+)$', hp.strip())
    if not m:
        return None, None
    host = m.group(1)
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    return host, int(m.group(2))


SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "chacha20-poly1305", "rc4-md5", "aes-128-cfb",
    "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "none", "plain", "rc4", "bf-cfb", "camellia-256-cfb",
}


def _b64_any(txt):
    """base64 в любом виде: с паддингом и без, стандартный и urlsafe."""
    txt = txt.strip()
    if not txt:
        return None
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return dec(txt + "=" * (-len(txt) % 4)).decode("utf-8")
        except Exception:
            continue
    return None


def parse_vmess(url):
    """vmess://base64(JSON). Источники часто ломают JSON (неэкранированная кавычка
    в поле ps) — тогда поля достаём регуляркой."""
    raw = url.split("://", 1)[1]
    if "#" in raw:
        raw = raw.split("#", 1)[0]
    txt = _b64_any(raw)
    if not txt or '"add"' not in txt:
        txt = b64_decode(raw.encode())
    if not txt or '"add"' not in txt:
        return None
    d = None
    try:
        d = json.loads(txt)
    except Exception:
        d = {}
        for key, pat in (("add", r'"add"\s*:\s*"([^"]+)"'), ("port", r'"port"\s*:\s*"?([0-9]+)'),
                         ("id", r'"id"\s*:\s*"([^"]+)"'), ("aid", r'"aid"\s*:\s*"?([0-9]+)'),
                         ("net", r'"net"\s*:\s*"([^"]+)"'), ("tls", r'"tls"\s*:\s*"([^"]+)"'),
                         ("sni", r'"sni"\s*:\s*"([^"]+)"'), ("host", r'"host"\s*:\s*"([^"]+)"'),
                         ("path", r'"path"\s*:\s*"([^"]*)"'), ("scy", r'"scy"\s*:\s*"([^"]+)"'),
                         ("ps", r'"ps"\s*:\s*"([^"]*)"')):
            m = re.search(pat, txt)
            if m:
                d[key] = m.group(1)
    if not d.get("add") or not d.get("id"):
        return None
    try:
        port = int(str(d.get("port") or 0).strip('"'))
    except Exception:
        return None
    if not port:
        return None
    try:
        aid = int(str(d.get("aid") or 0).strip('"'))
    except Exception:
        aid = 0
    return {
        "ps": (d.get("ps") or "").strip(), "host": d["add"], "port": port,
        "uuid": d["id"], "aid": aid, "cipher": d.get("scy") or "auto",
        "net": (str(d.get("net") or "tcp")).lower(),
        "tls": str(d.get("tls") or "").lower() in ("tls", "reality"),
        "sni": d.get("sni") or "", "hosthdr": d.get("host") or "",
        "path": d.get("path") or "", "alpn": d.get("alpn") or "",
        "fp": d.get("fp") or "chrome",
    }


def parse_trojan(url):
    if '#' in url:
        url, remark = url.split('#', 1)
    else:
        remark = ''
    m = re.match(r'trojan://(.+)$', url)
    if not m or '@' not in m.group(1):
        return None
    # пароль бывает с '@' внутри (trojan://pass@word@host:443) -> делим по последнему
    userinfo, rest = m.group(1).rsplit('@', 1)
    password = urllib.parse.unquote(userinfo)
    q = {}
    if '?' in rest:
        rest, qs = rest.split('?', 1)
        q = urllib.parse.parse_qs(qs)
    def g(k, d=None):
        return (q.get(k) or [d])[0]
    host, port = _split_hostport(rest)
    if not host or not port:
        return None
    return {
        "password": password, "host": host, "port": port,
        "sni": g('sni', '') or '', "type": (g('type', 'tcp') or 'tcp').lower(),
        "path": g('path', '') or '', "hosthdr": g('host', '') or '',
        "serviceName": g('serviceName', '') or '', "alpn": g('alpn', '') or '',
        "insecure": (g('allowInsecure', '1') in ('1', 'true')),
        "remark": remark.strip(),
    }


def parse_ss(url):
    """ss://b64(method:pass)@host:port | ss://method:pass@host:port | legacy b64(всё)."""
    body = url.split("://", 1)[1]
    remark = ''
    if '#' in body:
        body, remark = body.split('#', 1)
        remark = urllib.parse.unquote(remark)
    plugin, popts = '', {}
    if '?' in body:
        body, qs = body.split('?', 1)
        q = urllib.parse.parse_qs(qs)
        plugin = (q.get('plugin') or [''])[0]
    if '@' not in body:
        dec = _b64_any(body)
        if not dec or '@' not in dec:
            return None
        body = dec
    userinfo, hostpart = body.rsplit('@', 1)
    hostpart = urllib.parse.unquote(hostpart)

    candidates = []
    dec = _b64_any(userinfo)
    if dec and ':' in dec:
        candidates.append(dec)
    candidates.append(urllib.parse.unquote(userinfo))   # SIP002 без base64
    method = password = None
    for cand in candidates:
        if ':' not in cand:
            continue
        m_, p_ = cand.split(':', 1)
        if m_.lower() == "2022-blake3-chacha20-ietf-poly1305":
            m_ = "2022-blake3-chacha20-poly1305"   # синоним из списков, mihomo знает короткое имя
        if m_.lower() in SS_CIPHERS:
            method, password = m_.lower(), p_
            break
    if not method or method in ("none", "plain"):
        return None   # шифр none в бесплатных списках = мёртвый мусор
    host, port = _split_hostport(hostpart)
    if not host or not port:
        return None
    if plugin.startswith('obfs-local') or plugin.startswith('simple-obfs'):
        for kv in plugin.split(';')[1:]:
            if '=' in kv:
                k, v = kv.split('=', 1)
                popts[k] = v
    return {"method": method, "password": password, "host": host, "port": port,
            "plugin": plugin, "plugin_opts": popts, "remark": remark.strip()}


def yaml_str(s):
    # кавычим всё, что YAML может резолвить как число/булево/null (напр. sid "11e9" — научная нотация!)
    s = str(s)
    if any(c in s for c in ':#{}[]&*!|>%@`"\'\\, \n'):
        return json.dumps(s)
    low = s.lower()
    if low in ('true', 'false', 'null', '~', 'yes', 'no', 'on', 'off', '.nan', '.inf', '-.inf'):
        return json.dumps(s)
    try:
        float(s)
        return json.dumps(s)
    except ValueError:
        pass
    return s

def dump_yaml_value(v, indent):
    """Рекурсивный рендер YAML-значения (поддержка вложенных dict/list)."""
    pad = ' ' * indent
    if isinstance(v, dict):
        lines = []
        for k, val in v.items():
            if isinstance(val, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines.append(dump_yaml_value(val, indent + 2))
            elif isinstance(val, bool):
                lines.append(f"{pad}{k}: {'true' if val else 'false'}")
            else:
                lines.append(f"{pad}{k}: {yaml_str(val)}")
        return '\n'.join(lines)
    if isinstance(v, list):
        return '\n'.join(f"{pad}- {yaml_str(item)}" for item in v)
    return f"{pad}{yaml_str(v)}"

def gen_mihomo_yaml(proxies, names):
    out = [f"mixed-port: {MIXED_PORT}", "allow-lan: false", "mode: rule",
           "log-level: warning", "ipv6: false",
           f"external-controller: 127.0.0.1:{API_PORT}", ""]
    out.append("proxies:")
    for pr in proxies:
        out.append("  - name: " + yaml_str(pr['name']))
        for k, v in pr.items():
            if k == 'name':
                continue
            if isinstance(v, (dict, list)):
                out.append(f"    {k}:")
                out.append(dump_yaml_value(v, 6))
            elif isinstance(v, bool):
                out.append(f"    {k}: {'true' if v else 'false'}")
            else:
                out.append(f"    {k}: {yaml_str(v)}")
    out.append("")
    out.append("proxy-groups:")
    out.append(f"  - name: {GROUP}")
    out.append("    type: url-test")
    out.append(f"    url: '{TEST_URL}'")
    out.append("    interval: 30")
    out.append("    tolerance: 50")
    out.append("    proxies:")
    for n in names:
        out.append("      - " + yaml_str(n))
    out.append("")
    out.append("rules:")
    out.append(f"  - MATCH,{GROUP}")
    return '\n'.join(out)

TRAIL_SLASH_RE = re.compile(r"(?::\d+)/+(?=[?#]|$)")



def _split_link(link):
    """userinfo@host:port?query#remark для схем без base64-обёртки (tuic/anytls/juicity/hysteria)."""
    body = link.split("://", 1)[1]
    remark = ""
    if "#" in body:
        body, remark = body.split("#", 1)
    qs = ""
    if "?" in body:
        body, qs = body.split("?", 1)
    userinfo = ""
    if "@" in body:
        userinfo, body = body.rsplit("@", 1)
    if body.startswith("["):
        host, _, port = body.partition("]:")
        host = host.lstrip("[")
    else:
        host, _, port = body.rpartition(":")
    port = port.strip("/")
    q = urllib.parse.parse_qs(qs)
    return userinfo, host, int(port) if port.isdigit() else 0, q, urllib.parse.unquote(remark)


def _q(q, *keys, default=""):
    for k in keys:
        if q.get(k):
            return q[k][0]
    return default


def _bool(q, *keys):
    return _q(q, *keys, default="").lower() in ("1", "true", "yes")


def parse_ssr(link):
    """ShadowsocksR: ssr://b64(host:port:protocol:method:obfs:b64pass/?obfsparam=&remarks=)."""
    try:
        raw = link.split("://", 1)[1].strip()
        body = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "ignore")
        main, _, qs = body.partition("/?")
        host, port, protocol, method, obfs, pwd = main.split(":", 5)
        q = urllib.parse.parse_qs(qs)
        pw = base64.urlsafe_b64decode(pwd + "=" * (-len(pwd) % 4)).decode("utf-8", "ignore")
        obfsp = ""
        if q.get("obfsparam"):
            obfsp = base64.urlsafe_b64decode(q["obfsparam"][0] + "=" * (-len(q["obfsparam"][0]) % 4)).decode("utf-8", "ignore")
        proto_p = ""
        if q.get("protoparam"):
            proto_p = base64.urlsafe_b64decode(q["protoparam"][0] + "=" * (-len(q["protoparam"][0]) % 4)).decode("utf-8", "ignore")
        return {"host": host, "port": int(port), "protocol": protocol or "origin",
                "cipher": method, "obfs": obfs or "plain", "password": pw,
                "obfs_param": obfsp, "protocol_param": proto_p}
    except Exception:
        return None


def link_to_proxy(link, name):
    link = re.sub(TRAIL_SLASH_RE, lambda m: m.group(0).rstrip("/"), str(link).strip())
    link = normalize_link(html.unescape(link))
    if link.startswith('vless://'):
        p = parse_vless(link)
        if not p:
            return None
        proxy = {"name": name, "type": "vless", "server": p['host'], "port": p['port'],
                 "uuid": p['uuid'], "network": p['type'], "tls": p['security'] != 'none', "udp": True}
        if p['flow']:
            proxy["flow"] = p['flow']
        if p['security'] == 'reality':
            ro = {"public-key": p['pbk']}
            if p['sid']:
                ro["short-id"] = p['sid']
            proxy["reality-opts"] = ro
            proxy["servername"] = p['sni'] or p['host']
            proxy["client-fingerprint"] = p['fp'] or 'chrome'
        elif p['security'] == 'tls':
            proxy["servername"] = p['sni'] or p['host']
            proxy["skip-cert-verify"] = True
            proxy["client-fingerprint"] = p['fp'] or 'chrome'
        if p.get('alpn'):
            proxy["alpn"] = [a for a in p['alpn'].split(',') if a]
        if p['type'] == 'ws':
            ws = {"path": p['path'] or '/'}
            if p['hosthdr']:
                ws["headers"] = {"Host": p['hosthdr']}
            proxy["ws-opts"] = ws
        elif p['type'] == 'grpc':
            proxy["grpc-opts"] = {"grpc-service-name": p['serviceName'] or ''}
        elif p['type'] == 'xhttp':
            proxy["network"] = "xhttp"
            xo = {"path": p['path'] or '/'}
            if p['hosthdr']:
                xo["host"] = p['hosthdr']
            if p.get('mode'):
                xo["mode"] = p['mode']   # auto / packet-up / stream-up — без него xhttp часто не встаёт
            proxy["xhttp-opts"] = xo
        elif p['type'] == 'httpupgrade':
            proxy["network"] = "httpupgrade"
            proxy["httpupgrade-opts"] = {"path": p['path'] or '/'}
        return proxy
    elif link.startswith('tuic://'):
        ui, host, port, q, _ = _split_link(link)
        uuid, _, pwd = ui.partition(":")
        if not (host and port and uuid):
            return None
        proxy = {"name": name, "type": "tuic", "server": host, "port": port,
                 "uuid": uuid, "password": pwd,
                 "sni": _q(q, "sni", "peer", "servername") or host,
                 "skip-cert-verify": _bool(q, "allow_insecure", "insecure", "allowInsecure"),
                 "udp": True}
        alpn = _q(q, "alpn")
        if alpn:
            proxy["alpn"] = [a for a in re.split(r'[,\s]+', alpn) if a]
        cc = _q(q, "congestion_control", "congestion-controller", "congestion")
        if cc:
            proxy["congestion-controller"] = cc
        urm = _q(q, "udp_relay_mode", "udp-relay-mode")
        if urm:
            proxy["udp-relay-mode"] = urm
        return proxy
    elif link.startswith('anytls://'):
        ui, host, port, q, _ = _split_link(link)
        if not (host and port and ui):
            return None
        return {"name": name, "type": "anytls", "server": host, "port": port,
                "password": ui, "sni": _q(q, "sni", "peer", "servername") or host,
                "skip-cert-verify": _bool(q, "insecure", "allowInsecure", "allow_insecure"),
                "client-fingerprint": _q(q, "fp", "fingerprint", default="chrome") or "chrome",
                "udp": True}
    elif link.startswith('juicity://'):
        ui, host, port, q, _ = _split_link(link)
        uuid, _, pwd = ui.partition(":")
        if not (host and port and uuid):
            return None
        return {"name": name, "type": "juicity", "server": host, "port": port,
                "uuid": uuid, "password": pwd,
                "sni": _q(q, "sni", "peer", "servername") or host,
                "skip-cert-verify": _bool(q, "allow_insecure", "insecure", "allowInsecure"),
                "udp": True}
    elif link.startswith('hysteria://'):
        # hysteria v1 — другой протокол, чем hy2: auth-str + up/down + obfs
        _, host, port, q, _ = _split_link(link)
        if not (host and port):
            return None
        proxy = {"name": name, "type": "hysteria", "server": host, "port": port,
                 "auth-str": _q(q, "auth", "auth-str", default=""),
                 "sni": _q(q, "peer", "sni", "servername") or host,
                 "skip-cert-verify": _bool(q, "insecure", "allow_insecure", "allowInsecure"),
                 "up": _q(q, "upmbps", "up", default="50"),
                 "down": _q(q, "downmbps", "down", default="50"),
                 "protocol": _q(q, "protocol", default="udp"),
                 "udp": True}
        obfs = _q(q, "obfs")
        if obfs and obfs != "none":
            proxy["obfs"] = obfs
        return proxy
    elif link.startswith('ssr://'):
        p = parse_ssr(link)
        if not p:
            return None
        proxy = {"name": name, "type": "ssr", "server": p["host"], "port": p["port"],
                 "cipher": p["cipher"], "password": p["password"],
                 "protocol": p["protocol"], "obfs": p["obfs"], "udp": True}
        if p["obfs_param"]:
            proxy["obfs-param"] = p["obfs_param"]
        if p["protocol_param"]:
            proxy["protocol-param"] = p["protocol_param"]
        return proxy
    elif link.startswith(('hy2://', 'hysteria2://')):
        p = parse_hy2(link)
        if not p:
            return None
        proxy = {"name": name, "type": "hysteria2", "server": p['host'], "port": p['port'],
                 "password": p['auth'], "sni": p['sni'], "skip-cert-verify": p['insecure'], "udp": True}
        if p['obfs']:
            proxy["obfs"] = p['obfs']
            proxy["obfs-password"] = p['obfs_pass']
        return proxy
    elif link.startswith('vmess://'):
        p = parse_vmess(link)
        if not p:
            return None
        proxy = {"name": name, "type": "vmess", "server": p['host'], "port": p['port'],
                 "uuid": p['uuid'], "alterId": p['aid'], "cipher": p['cipher'] or 'auto', "udp": True}
        if p['tls']:
            proxy["tls"] = True
            proxy["servername"] = p['sni'] or p['hosthdr'] or p['host']
            proxy["skip-cert-verify"] = True
        if p['alpn']:
            proxy["alpn"] = [a for a in re.split(r'[,\s]+', p['alpn']) if a]
        if p['net'] == 'ws':
            proxy["network"] = "ws"
            ws = {"path": p['path'] or '/'}
            if p['hosthdr']:
                ws["headers"] = {"Host": p['hosthdr']}
            proxy["ws-opts"] = ws
        elif p['net'] == 'grpc':
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = {"grpc-service-name": p['path'] or ''}
        elif p['net'] in ('h2', 'http'):
            proxy["network"] = "h2"
            proxy["h2-opts"] = {"path": p['path'] or '/', "host": [p['hosthdr']] if p['hosthdr'] else []}
        return proxy
    elif link.startswith('trojan://'):
        p = parse_trojan(link)
        if not p:
            return None
        proxy = {"name": name, "type": "trojan", "server": p['host'], "port": p['port'],
                 "password": p['password'], "sni": p['sni'] or p['hosthdr'] or p['host'],
                 "skip-cert-verify": True, "udp": True}
        if p['alpn']:
            proxy["alpn"] = [a for a in re.split(r'[,\s]+', p['alpn']) if a]
        if p['type'] == 'ws':
            proxy["network"] = "ws"
            ws = {"path": p['path'] or '/'}
            if p['hosthdr']:
                ws["headers"] = {"Host": p['hosthdr']}
            proxy["ws-opts"] = ws
        elif p['type'] == 'grpc':
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = {"grpc-service-name": p['serviceName'] or p['path'] or ''}
        return proxy
    elif link.startswith('ss://'):
        p = parse_ss(link)
        if not p:
            return None
        proxy = {"name": name, "type": "ss", "server": p['host'], "port": p['port'],
                 "cipher": p['method'], "password": p['password'], "udp": True}
        if p['plugin'] and p['plugin_opts'].get('obfs'):
            proxy["plugin"] = "obfs"
            proxy["plugin-opts"] = {"mode": p['plugin_opts'].get('obfs', 'http'),
                                    "host": p['plugin_opts'].get('obfs-host', '')}
        return proxy
    return None

# ---------------------------------------------------------------- mihomo
def ensure_mihomo():
    if os.path.exists(MIHOMO):
        return True
    os.makedirs(BIN_DIR, exist_ok=True)
    log("⬇️  скачиваю mihomo...")
    # найти актуальный тег
    try:
        d = json.loads(http_get('https://api.github.com/repos/MetaCubeX/mihomo/releases/latest', 15).decode())
        tag = d['tag_name']
        url = f'https://github.com/MetaCubeX/mihomo/releases/download/{tag}/mihomo-linux-amd64-compatible-{tag}.gz'
        raw = http_get(url, 60)
        with open(MIHOMO + '.gz', 'wb') as f:
            f.write(raw)
        import gzip
        with gzip.open(MIHOMO + '.gz', 'rb') as gz, open(MIHOMO, 'wb') as f:
            shutil.copyfileobj(gz, f)
        os.chmod(MIHOMO, 0o755)
        os.remove(MIHOMO + '.gz')
        log("✅ mihomo установлен в ~/bin/mihomo")
        return True
    except Exception as e:
        log(f"❌ не удалось скачать mihomo: {e}")
        return False

def api_get(path):
    with urllib.request.urlopen(f'http://127.0.0.1:{API_PORT}{path}', timeout=5) as r:
        return json.loads(r.read())

def api_put(path, data):
    req = urllib.request.Request(f'http://127.0.0.1:{API_PORT}{path}',
                                 data=json.dumps(data).encode(),
                                 method='PUT', headers={'Content-Type': 'application/json'})
    urllib.request.urlopen(req, timeout=5)

def check_exit_ip():
    try:
        r = subprocess.run(['curl', '-s', '--connect-timeout', '8', '--max-time', '15',
                            '-x', f'http://127.0.0.1:{MIXED_PORT}',
                            'http://ip-api.com/json/?fields=status,countryCode,query,isp'],
                           capture_output=True, text=True)
        if r.returncode == 0 and '"success"' in r.stdout:
            return json.loads(r.stdout)
    except Exception:
        pass
    return None

def get_delays():
    d = api_get(f'/proxies/{GROUP}')
    delays = {}
    for name in d.get('all', []):
        try:
            pd = api_get(f'/proxies/{urllib.parse.quote(name)}')
            hist = pd.get('history', [])
            delay = hist[-1].get('delay', 0) if hist else 0
            delays[name] = delay
        except Exception:
            delays[name] = 0
    return delays

# ---------------------------------------------------------------- пайплайн
def collect_country_sources(cc):
    """Пробует прямые файлы по стране из COUNTRY_SOURCES (F0rc3Run, v2go, Au1rxx)."""
    links = []
    for name, tmpl, mode in COUNTRY_SOURCES:
        candidates = []
        if mode == 'cc':
            candidates = [tmpl.format(cc=cc)]
        elif mode == 'name':
            names = COUNTRY_NAMES.get(cc, [])
            candidates = [tmpl.format(name=n) for n in names]
        for url in candidates:
            try:
                raw = http_get(url, timeout=20)
                # Au1rxx — base64, остальные plain
                fmt = 'base64' if 'au1rxx' in name else 'plain'
                text = b64_decode(raw) if fmt == 'base64' else raw.decode(errors='ignore')
                got = extract_links(text)
                if got:
                    log(f"  {name} (country file): {len(got)} ссылок")
                    links += got
                    break  # первая успешная версия имени страны
            except Exception:
                pass
    return links

def collect_and_filter(cc, protos):
    """Собирает ссылки из источников, фильтрует по стране и протоколу."""
    all_links = []
    # 1) прямые country-файлы (уже отфильтрованы по стране — берём все)
    all_links += collect_country_sources(cc)
    # 2) общие агрегаторы
    for name, url, fmt in SOURCES:
        try:
            raw = http_get(url)
            if fmt == 'base64':
                text = b64_decode(raw)
            else:
                text = raw.decode(errors='ignore')
            # Авто-детекция: если в тексте нет '://', пробуем декодировать как base64
            if '://' not in text[:300] and len(raw) > 50:
                dec = b64_decode(raw)
                if '://' in dec[:500]:
                    text = dec
            links = extract_links(text)
            log(f"  {name}: {len(links)} ссылок")
            all_links += links
        except Exception as e:
            log(f"  {name}: ОШИБКА {e}")

    # dedup по строке до #
    seen, uniq = set(), []
    for l in all_links:
        key = l.split('#')[0]
        if key not in seen:
            seen.add(key)
            uniq.append(l)
    log(f"всего уникальных: {len(uniq)}")

    # фильтр по стране и протоколу
    filtered = []
    for l in uniq:
        scheme = l.split('://')[0]
        proto_ok = scheme in protos or (scheme == 'hysteria' and 'hy2' in protos)
        if proto_ok and country_match(l, cc):
            filtered.append(l)
    log(f"по стране {cc} и протоколам {protos}: {len(filtered)}")
    return filtered

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('country', help='Код страны, напр. TR, DE, US')
    ap.add_argument('--proto', default='vless', help='Протоколы через запятую: vless,hy2')
    ap.add_argument('--top', type=int, default=10, help='Сколько топ-ссылок выводить')
    ap.add_argument('--no-cache', action='store_true', help='Игнорировать кэш результатов')
    ap.add_argument('--keep-mihomo', action='store_true', help='Не убивать mihomo после теста')
    args = ap.parse_args()

    cc = args.country.upper()
    protos = [p.strip() for p in args.proto.split(',')]

    os.makedirs(RESULT_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_file = os.path.join(CACHE_DIR, f'{cc}_{",".join(protos)}.json')

    if not args.no_cache and os.path.exists(cache_file):
        age = time.time() - os.path.getmtime(cache_file)
        if age < CACHE_TTL:
            data = json.load(open(cache_file))
            log(f"📦 кэш ({int(age/60)} мин назад): {data['working_cnt']} рабочих")
            working = data['working']
            print_working(working, args.top)
            save_outputs(cc, working, args.top)
            return

    if not ensure_mihomo():
        sys.exit(1)

    log(f"🔍 ищу {cc} ({protos})...")
    links = collect_and_filter(cc, protos)
    if not links:
        log("❌ ничего не найдено по фильтру страны")
        sys.exit(1)

    # генерируем конфиг
    proxies, names = [], []
    skipped = 0
    for i, l in enumerate(links):
        name = f"{cc}{i:02d}"
        pr = link_to_proxy(l, name)
        if pr:
            proxies.append(pr)
            names.append(name)
        else:
            skipped += 1
    log(f"прокси в mihomo: {len(proxies)} (пропущено: {skipped})")
    if not proxies:
        log("❌ нет поддерживаемых прокси")
        sys.exit(1)

    cfg_path = os.path.join(CACHE_DIR, f'mihomo_{cc}.yaml')
    open(cfg_path, 'w').write(gen_mihomo_yaml(proxies, names))

    # запуск mihomo
    subprocess.run(['pkill', '-f', 'bin/miho'], capture_output=True)
    time.sleep(0.8)
    proc = subprocess.Popen([MIHOMO, '-d', CACHE_DIR, '-f', cfg_path],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        # ждём url-test
        time.sleep(15)
        try:
            delays = get_delays()
        except Exception as e:
            # mihomo мог упасть на парсинге — показать причину
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
            out = proc.stdout.read() if proc.stdout else ''
            fatal = [l for l in out.splitlines() if 'fatal' in l.lower()]
            log(f"❌ mihomo не стартовал: {fatal[0] if fatal else e}")
            log("   Скорее всего невалидный параметр в одной из ссылок. "
                "Проверь sid (чётный hex), public-key (base64url 32 байта).")
            sys.exit(1)
        alive = {n: d for n, d in delays.items() if d and 0 < d < 2000}
        log(f"живых (TCP): {len(alive)}/{len(names)}")

        # проверка реального выхода
        working = []
        link_by_name = {f"{cc}{i:02d}": l for i, l in enumerate(links)}
        for name, delay in sorted(alive.items(), key=lambda x: x[1]):
            try:
                api_put(f'/proxies/{GROUP}', {'name': name})
                time.sleep(0.8)
                geo = check_exit_ip()
                if geo and geo.get('countryCode') == cc:
                    link = link_by_name.get(name, '')
                    working.append({'link': link, 'name': name, 'delay': delay,
                                    'exit_ip': geo.get('query'), 'isp': geo.get('isp', '')})
                    log(f"  ✅ {name} {delay}ms → {cc} {geo.get('query')} {geo.get('isp','')[:35]}")
                else:
                    log(f"  ❌ {name} {delay}ms → {geo.get('countryCode') if geo else 'нет ответа'}")
            except Exception as e:
                log(f"  ⚠️ {name}: {e}")
            time.sleep(0.2)

        working.sort(key=lambda x: x['delay'])
        log(f"\n=== РАБОЧИХ с выходом {cc}: {len(working)} ===")
        if working:
            print_working(working, args.top)
            save_outputs(cc, working, args.top)
            json.dump({'working_cnt': len(working), 'working': working,
                       'ts': time.time()}, open(cache_file, 'w'))
        else:
            log("❌ рабочих не найдено. Попробуй позже (конфиги ротируются) или другие протоколы.")
    finally:
        if not args.keep_mihomo:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

def print_working(working, top):
    for i, w in enumerate(working[:top]):
        print(f"\n[{i+1}] {w['delay']}ms | {w['exit_ip']} | {w['isp'][:40]}")
        print(w['link'])

def save_outputs(cc, working, top):
    os.makedirs(RESULT_DIR, exist_ok=True)
    with open(os.path.join(RESULT_DIR, f'{cc}_working.txt'), 'w') as f:
        f.write('\n'.join(w['link'] for w in working))
    with open(os.path.join(RESULT_DIR, f'{cc}_top{top}.txt'), 'w') as f:
        f.write('\n'.join(w['link'] for w in working[:top]))
    with open(os.path.join(RESULT_DIR, f'{cc}_report.json'), 'w') as f:
        json.dump(working, f, ensure_ascii=False, indent=1)
    log(f"\n💾 сохранено: {RESULT_DIR}/{cc}_working.txt ({len(working)} шт), "
        f"{cc}_top{top}.txt, {cc}_report.json")

if __name__ == '__main__':
    main()
