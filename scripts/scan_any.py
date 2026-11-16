#!/usr/bin/env python3
"""
scan_any.py — поиск РАБОЧИХ и БЫСТРЫХ бесплатных прокси без привязки к стране.

Отвечает на запрос «дай рабочие vless/hysteria2, плевать откуда» — то есть
фильтр по стране не нужен, нужны реально живые и быстрые из РФ.

Режимы:
  collect                         — скачать все источники, собрать уникальные ссылки
  latency [N]                     — url-test через mihomo, отобрать живые по TCP (N=сколько vless тестировать, деф. 1400)
  verify [N]                      — для N самых быстрых по задержке: реальный выход (ip-api) + скорость (Cloudflare 3 МБ)
  clean [--live]                  — проверить, что узлы ходят НАПРЯМУЮ (не через WG/PBR роутера)
  report                          — отсортировать verified.json, сохранить plain-список ссылок

Пример:
  python3 scan_any.py collect && python3 scan_any.py latency && python3 scan_any.py verify 45 && python3 scan_any.py report

Зависимости: ~/bin/mihomo (берётся из навыка find-free-vpn-configs, ffv.ensure_mihomo()).
"""
import collections, json, os, random, re, subprocess, sys, time, urllib.parse, urllib.request
import paths  # noqa: E402  (локальные пути проекта)

HOME = os.path.expanduser("~")
BIN = paths.binary("mihomo")
SCRATCH = paths.SCRATCH
CACHE = paths.CACHE
RAW = os.path.join(CACHE, "raw")
RESULTS = paths.OUT
LINKS_F = os.path.join(CACHE, "all_links.json")
ALIVE_F = os.path.join(CACHE, "alive.json")
TESTED_F = os.path.join(CACHE, "tested.json")
VERIFIED_F = os.path.join(CACHE, "verified.json")
HIST_F = os.path.join(CACHE, "history.json")   # link -> время последней успешной проверки

GROUP = "SCAN"
TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=3000000"
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")
LINK_RE = re.compile(r'(?:vless|vmess|trojan|ssr|ss|hy2|hysteria2|hysteria|tuic|anytls|juicity)://[^\s"\'<>\\]+')

# Источники, проверенные 2026-11-15 (все отдают 200 и обновляются в тот же день).
# Формат: name -> repo/path (raw.githubusercontent.com)
SOURCES = {
    "radikal":      "0xRadikal/Free-v2ray-Configs/main/all/configs.txt",              # 15 мин, 11.7k строк
    "matin_all":    "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "matin_hy2":    "MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",  # b64
    "matin_vless":  "MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",      # b64
    "igareck_ru":   "igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",        # заточен под РФ
    "igareck_ss":   "igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
    "argh94_hy2":   "Argh94/V2RayAutoConfig/main/configs/Hysteria2.txt",             # только hy2
    "kwinshadow_v": "Kwinshadow/TelegramV2rayCollector/main/sublinks/vless.txt",
    "kwinshadow_m": "Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt",
    "nirevil":      "NiREvil/vless/main/edge/assets/p-all.txt",                       # 77k строк, много мусора
    "aliasghar":    "ALIILAPRO/v2rayNG-Config/main/server.txt",
    "mahdibland":   "mahdibland/V2RayAggregator/master/Eternity.txt",
    # SS-специфичные пулы: на них сейчас самый высокий выход живых нод
    # (проверка трафиком: ss 14/17 против trojan 0/78 и vmess 0/525)
    "mhd_ss_merge": "mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "mhd_ss_etern": "mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "mhd_taheri":   "MhdiTaheri/V2rayCollector/main/sub/mix",
    "roosterkid":   "roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "tssf_fly":     "ts-sf/fly/main/v2",
    # Проверено 15.11.2026: все живы и обновлены в этот день.
    # barry_all — крупнейший SS-пул (8753 ss из 9614 строк), kort_* — заточен под РФ
    # (в т.ч. vless с RU-SNI), lagzian обновляется каждые 2 часа.
    "barry_all":    "barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "barry_ss":     "barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt",
    "aliilapro":    "ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "kort_ss":      "kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/ss.txt",
    "kort_vless":   "kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/vless.txt",
    "kort_runsni":  "kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/vless.txt",
    "lagzian_mix":  "lagzian/SS-Collector/main/configs/psg/mix.txt",
    "lagzian_vless":"lagzian/SS-Collector/main/configs/mixed/vless.txt",
    "freenode_all": "ripaojiedian/freenode/main/http",
    # Au1rxx: единственный источник, который ПРОВЕРЯЕТ ноды реальным HTTP перед публикацией
    "au1rxx_v1":    "Au1rxx/free-vpn-subscriptions/main/output/all-verified/v2ray-base64-0001.txt",
    "au1rxx_v2":    "Au1rxx/free-vpn-subscriptions/main/output/all-verified/v2ray-base64-0002.txt",
    "au1rxx_v3":    "Au1rxx/free-vpn-subscriptions/main/output/all-verified/v2ray-base64-0003.txt",
    "au1rxx_hy2":   "Au1rxx/free-vpn-subscriptions/main/output/protocol/hysteria2/v2ray-base64-0001.txt",
    "au1rxx_vless": "Au1rxx/free-vpn-subscriptions/main/output/protocol/vless/v2ray-base64-0001.txt",
    # Найдено 16.11.2026 поиском по GitHub: здесь есть hysteria v1 (старый протокол,
    # которого нет в крупных списках) и смесь с socks-прокси.
    "wlget64":      "WLget/V2Ray_configs_64/HEAD/ConfigSub_list.txt",
    "solispirit":   "SoliSpirit/v2ray-configs/HEAD/all_configs.txt",
    # Barabama/FreeNodes — агрегатор китайских каталогов (cfmem/clashnode/yudou…),
    # единственный найденный источник с anytls и hysteria v1 в живом виде.
    # Найдено 16.11.2026: единственные живые источники с anytls/hysteria v1/ssr
    # (cbusifabcap обновляется ежедневно, TGParse парсит 100+ телеграм-каналов)
    "daily_free_vpn": "cbusifabcap/daily_free_vpn/HEAD/Z.txt",
    "tgparse":        "Surfboardv2ray/TGParse/HEAD/configtg.txt",
    "barabara_merged": "Barabama/FreeNodes/HEAD/nodes/merged.txt",
    "barabara_cfmem":  "Barabama/FreeNodes/HEAD/nodes/cfmem.txt",
    "barabara_yudou":  "Barabama/FreeNodes/HEAD/nodes/yudou.txt",
    "au1rxx_trojan":"Au1rxx/free-vpn-subscriptions/main/output/protocol/trojan/v2ray-base64-0001.txt",
    # Свежие активные репозитории-коллекторы (проверено 2026-11)
    "tahmaseb_hy2":    "tahmaseb73/configs-collector-v2ray/main/data/sub/protocols/hysteria2.txt",
    "tahmaseb_vless":  "tahmaseb73/configs-collector-v2ray/main/data/sub/protocols/vless.txt",
    "tahmaseb_reality":"tahmaseb73/configs-collector-v2ray/main/data/sub/networks/reality.txt",
    "tahmaseb_tuic":   "tahmaseb73/configs-collector-v2ray/main/data/sub/protocols/tuic.txt",
    "shin_all":        "therealaleph/Shin-TG-V2ray-Collector/main/collected_configs.txt",
    "mohamadfg_vless": "mohamadfg-dev/telegram-v2ray-configs-collector/main/category/vless.txt",
}
def daily_sources():
    """Свежие файлы каталогов-зеркал: node.<домен>/uploads/YYYY/MM/YYYYMMDD.txt.

    Проверено 16.11.2026: все три зеркала отдают один и тот же список (155 ссылок),
    oss.oneclash.cc на такой шаблон отвечает пустотой. Берём сегодня и вчера:
    до 8 утра по UTC свежего файла может ещё не быть.
    """
    import datetime
    out = {}
    now = datetime.datetime.now(datetime.timezone.utc)
    for delta in (0, 1):
        d = now - datetime.timedelta(days=delta)
        tag = d.strftime("%Y%m%d")
        for host in ("node.clashnode.cc", "node.freeclashnode.com", "node.nodev2ray.com"):
            out[f"daily_{tag}_{host.split('.')[1]}"] = f"https://{host}/uploads/{d:%Y}/{d:%m}/{tag}.txt"
    return out


def dynamic_community_sources():
    """Динамические источники подписок из проверенных репозиториев сообщества."""
    out = {}
    try:
        url = "https://raw.githubusercontent.com/tahmaseb73/configs-collector-v2ray/main/data/sub_link.json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            links = json.loads(r.read().decode("utf-8", "ignore"))
            for i, l in enumerate(links[:30]):
                if isinstance(l, str) and l.startswith("http"):
                    out[f"dyn_tahmaseb_{i:02d}"] = l
    except Exception:
        pass
    return out


RAW_BASE = "https://raw.githubusercontent.com/"

sys.path.insert(0, paths.SCRIPT_DIR)
import find_free_vpn as ffv  # переиспользуем парсеры vless/hy2 и yaml-рендер


# ------------------------------------------------------------------ утилиты
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
PBK_RE = re.compile(r"^[A-Za-z0-9_\-]{42,44}=?$")   # REALITY public key: base64url, 43 символа


def sane(s, fallback=""):
    """ASCII-only, без '#'-хвостов. Иначе mihomo падает на '\\ud83c' в YAML."""
    s = str(s).split("#")[0]
    s = re.sub(r"[^\x20-\x7e]", "", s).strip().strip("/")
    return s or fallback


def yaml_str(s):
    return ffv.yaml_str(sane(s))


UNSUPPORTED_TYPES = {"juicity"}   # mihomo 1.19.29 не умеет juicity — держим парсер на будущее


def sanitize_proxy(p):
    if p and p.get("type") in UNSUPPORTED_TYPES:
        return None
    host = sane(p.get("server", ""))
    if not HOST_RE.match(host):
        return None
    p["server"] = host
    p["port"] = int(p.get("port") or 0)
    if not 0 < p["port"] < 65536:
        return None
    for k in ("sni", "servername"):
        if k in p:
            v = sane(p.get(k), host)
            p[k] = v if HOST_RE.match(v) else host
    for k in ("password", "uuid"):
        if k in p:
            v = sane(p.get(k))
            if not v:
                return None
            p[k] = v
    if p.get("type") in ("vless", "vmess") and p.get("uuid"):
        u = p["uuid"]
        if not UUID_RE.match(u):
            return None            # mihomo: invalid UUID -> падает весь конфиг
    if p.get("type") == "vless" and isinstance(p.get("reality-opts"), dict):
        pbk = p["reality-opts"].get("public-key", "")
        if not PBK_RE.match(pbk or ""):
            return None            # invalid REALITY public key -> падает весь конфиг
    if p.get("type") == "vmess":
        try:
            aid = int(p.get("alterId") or 0)
        except Exception:
            return None
        if not 0 <= aid <= 65535:
            return None
        p["alterId"] = aid
    if p.get("type") == "ss":
        cipher = p.get("cipher") or ""
        if cipher not in ffv.SS_CIPHERS or not p.get("password"):
            return None            # неизвестный шифр mihomo не примет
        # SS-2022: пароль — base64-ключ строго заданной длины. В бесплатных списках
        # ключи массово обрезаны, и mihomo падает на всём конфиге, не только на ноде.
        if cipher.startswith("2022-"):
            need = 16 if "128" in cipher else 32
            keys = []
            for part in str(p["password"]).split(":"):
                raw = part.strip()
                try:
                    dec = __import__("base64").b64decode(raw + "=" * (-len(raw) % 4))
                except Exception:
                    return None
                if len(dec) != need:
                    return None
                keys.append(raw + "=" * (-len(raw) % 4))
            p["password"] = ":".join(keys)
    if isinstance(p.get("ws-opts"), dict):
        p["ws-opts"]["path"] = sane(p["ws-opts"].get("path") or "/", "/")
        h = p["ws-opts"].get("headers")
        if isinstance(h, dict):
            p["ws-opts"]["headers"] = {kk: sane(vv) for kk, vv in h.items() if sane(vv)}
            if not p["ws-opts"]["headers"]:
                p.pop("ws-opts")
    return p


def gen_yaml(proxies, mixed, api_port):
    out = [f"mixed-port: {mixed}", "allow-lan: false", "mode: rule", "log-level: silent",
           "ipv6: false", f"external-controller: 127.0.0.1:{api_port}", "", "proxies:"]
    for pr in proxies:
        out.append("  - name: " + yaml_str(pr["name"]))
        for k, v in pr.items():
            if k == "name":
                continue
            if isinstance(v, (dict, list)):
                out += [f"    {k}:", ffv.dump_yaml_value(v, 6)]
            elif isinstance(v, bool):
                out.append(f"    {k}: {'true' if v else 'false'}")
            else:
                out.append(f"    {k}: {yaml_str(v)}")
    # ВАЖНО: тип группы в mihomo — `select`, не `selector` («unsupported type: selector»)
    out += ["", "proxy-groups:", f"  - name: {GROUP}", "    type: select", "    proxies:"]
    out += ["      - " + yaml_str(p["name"]) for p in proxies]
    out += ["", "rules:", f"  - MATCH,{GROUP}"]
    return "\n".join(out)


def api(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=20) as r:
        body = r.read()
        return json.loads(body) if body else {}


def probe_delay(port, name, timeout=4000, tries=2):
    """Задержка через прокси, до `tries` попыток.

    Одна попытка ошибается в обе стороны: свободные ноды часто отдают первый
    запрос с задержкой в секунды (прогрев TLS/очередь), а перегруженная нода
    случайно успевает ответить. Берём минимум из двух — нода с реальным
    соединением подтвердится, случайный отклик не спасёт мёртвую.
    """
    q = urllib.parse.quote(name, safe="")
    best = 0
    for _ in range(max(1, tries)):
        u = f"/proxies/{q}/delay?timeout={timeout}&url={urllib.parse.quote(TEST_URL, safe='')}"
        try:
            d = int(api(port, u).get("delay") or 0)
        except Exception:
            d = 0
        if d:
            best = d if not best else min(best, d)
            break
    return best


# ------------------------------------------------------------------ режимы
def collect():
    os.makedirs(RAW, exist_ok=True)
    os.makedirs(CACHE, exist_ok=True)
    links = set()
    for name, path in list(SOURCES.items()) + list(daily_sources().items()) + list(dynamic_community_sources().items()):
        try:
            # в SOURCES встречаются и относительные пути (клеим к RAW_BASE),
            # и готовые URL (файлы каталогов по дате) — вторые не трогаем
            url = path if str(path).startswith("http") else RAW_BASE + path
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=45) as r:
                raw = r.read()
            open(os.path.join(RAW, name + ".txt"), "wb").write(raw)
            text = raw.decode("utf-8", "replace")
            if not LINK_RE.search(text):
                try:
                    dec = __import__("base64").b64decode(text.strip() + "=" * (-len(text.strip()) % 4)).decode("utf-8", "replace")
                    if LINK_RE.search(dec):
                        text = dec
                except Exception:
                    pass
            found = set(LINK_RE.findall(text))
            links |= found
            print(f"{name:14} {len(raw):>9}B links={len(found)}")
        except Exception as e:
            print(f"{name:14} ERR {str(e)[:60]}")
    # ссылки со сайтов-каталогов (bin/scrape_web.py через Scrapling): их нет
    # в GitHub-списках, а часть сайтов отдаёт ключи только в HTML
    WEB_F = os.path.join(paths.CACHE, "web_links.txt")
    if os.path.exists(WEB_F):
        web = {l.strip() for l in open(WEB_F) if l.strip()}
        print(f"{'web_scrape':14} {'':>9} links={len(web)}")
        links |= web
    # хвосты после '#' — это чужие ссылки/эмодзи, они ломают YAML: отрезаем
    links = {re.split(r"#", l)[0] for l in links}
    links = {ffv.normalize_link(l) for l in links}   # чиним перепутанные схемы
    # vmess идёт base64-блоком без "@", ss бывает в legacy-форме — фильтр по схеме,
    # а не по наличию "@", иначе теряется половина источников
    # Фильтр по схеме + проверка, что ссылка вообще разбирается в proxy.
    # Раньше требовался "@", из-за чего молча выпадали ssr (base64), hysteria v1,
    # tuic/anytls с нестандартной authority-формой.
    ALLOWED = ("vless", "vmess", "hy2", "hysteria2", "hysteria",
               "trojan", "ss", "ssr", "tuic", "anytls", "juicity")
    links = {l for l in links if l.split("://")[0] in ALLOWED and ffv.link_to_proxy(l, "x")}
    before = len(links)
    links = dedupe_connections(sorted(links))
    print(f"дедуп по конечной точке: {before} -> {len(links)}")
    json.dump(sorted(links), open(LINKS_F, "w"))
    print("unique:", len(links), dict(collections.Counter(l.split('://')[0] for l in links)))


def _host_of(link):
    """host:port из любой ссылки — для дедупликации по реальной конечной точке.

    Разбираем строку, а не через link_to_proxy: у hy2/ss пароль бывает с '@' или ':',
    и полноценный парсер на таких ссылках возвращает None — тогда ноды молча
    выпадали из пула (hy2 терялся целиком).
    """
    if link.startswith("ss://"):
        p = ffv.parse_ss(link)          # legacy-форма: ss://b64(method:pass@host:port)
        return (p["host"], p["port"]) if p else None
    if link.startswith("vmess://"):
        # vmess — base64-JSON, в строке нет ни '@', ни ':порт'
        p = ffv.parse_vmess(link)
        return (p["host"], p["port"]) if p else None
    try:
        body = link.split("://", 1)[1].split("#", 1)[0].split("?", 1)[0]
        if "@" in body:
            body = body.rsplit("@", 1)[1]
        if body.startswith("["):                     # [IPv6]:port
            host, _, port = body.partition("]:")
            host = host.lstrip("[")
        else:
            host, _, port = body.rpartition(":")
        port = port.strip("/")
        if host and port.isdigit():
            return host, int(port)
    except Exception:
        pass
    # ssr:// — base64, у tuic/anytls/juicity/hysteria своя authority-форма:
    # разбор через общий конвертер, иначе такие ссылки молча выпадают из пула
    try:
        p = ffv.link_to_proxy(link, "x")
        if p and p.get("server") and p.get("port"):
            return p["server"], int(p["port"])
    except Exception:
        return None
    return None




def dedupe_connections(links):
    """Дедуп по идентичности подключения, а не по адресу.

    За CDN (Cloudflare, Fastly) на одном IP:443 живут десятки разных сервисов,
    различающихся SNI/путём/ключом: замер на одном источнике — 89 разных конфигов
    на 199.232.78.159:443. Дедуп по IP:порт выбрасывал 10 % пула, причём мог
    оставить мёртвый конфиг и выкинуть рабочий.
    """
    import concurrent.futures as cf
    import socket

    def fam(link):
        return "hy2" if link.startswith(("hy2://", "hysteria2://", "hysteria://")) else link.split("://")[0]

    hosts = {(_host_of(l) or (None,))[0] for l in links}
    hosts.discard(None)
    hostmap = {}

    def resolve(h):
        try:
            return h, socket.getaddrinfo(h, None, socket.AF_INET)[0][4][0]
        except Exception:
            return h, h

    with cf.ThreadPoolExecutor(max_workers=32) as ex:
        for h, ip in ex.map(resolve, hosts):
            hostmap[h] = ip

    seen, out = set(), []
    for l in links:
        hp = _host_of(l)
        if not hp:
            continue
        ip = hostmap.get(hp[0], hp[0])
        p = ffv.link_to_proxy(l, "x") or {}
        ws = p.get("ws-opts") or {}
        grpc = p.get("grpc-opts") or {}
        cid = (fam(l), ip, hp[1],
               str(p.get("uuid") or p.get("password") or p.get("auth") or "")[:24],
               (p.get("servername") or p.get("sni") or "").lower(),
               str(ws.get("path") or grpc.get("grpc-service-name") or ""),
               str((ws.get("headers") or {}).get("Host") or "").lower())
        if cid in seen:
            continue
        seen.add(cid)
        out.append(l)
    return out


def dedupe_endpoints(links):
    """Один тест на сервер, а не на каждую копию.

    Бесплатные списки перепечатывают одни и те же серверы десятками копий с разными
    именами и ключами. Считаем уникальной пару (семейство протокола, IP, порт):
    домены резолвим, чтобы `node1.example.com` и `1.2.3.4` не дублировались.
    """
    import concurrent.futures as cf
    import socket

    def fam(link):
        sc = link.split("://")[0]
        return "hy2" if sc in ("hy2", "hysteria2", "hysteria") else sc

    hostmap = {}
    hosts = set()
    for l in links:
        hp = _host_of(l)
        if hp and hp[0]:
            hosts.add(hp[0])

    def resolve(h):
        try:
            return h, socket.getaddrinfo(h, None, socket.AF_INET)[0][4][0]
        except Exception:
            return h, h

    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for h, ip in ex.map(resolve, hosts):
            hostmap[h] = ip

    seen, out = set(), []
    for l in links:
        hp = _host_of(l)
        if not hp:
            continue
        host, port = hp
        ip = hostmap.get(host, host)
        key = (fam(l), ip, port)
        if key in seen:
            continue
        seen.add(key)
        out.append(l)
    return out

def _config_ok(proxies):
    """Проверка конфига mihomo -t. Одна нода с битым pbk/uuid/cipher валит старт
    целиком, и без этой проверки весь чанк молча считался мёртвым."""
    cfg = os.path.join(SCRATCH, "_probe.yaml")
    open(cfg, "w").write(gen_yaml(proxies, 7893, 9096))
    try:
        r = subprocess.run([BIN, "-t", "-d", SCRATCH, "-f", cfg],
                           capture_output=True, text=True, timeout=90)
    except Exception:
        return True, ""
    if r.returncode == 0:
        return True, ""
    msg = (r.stdout or "") + (r.stderr or "")
    bad = [l for l in msg.splitlines() if "level=error" in l or "failed" in l]
    return False, (bad[0] if bad else msg[-160:])


def filter_valid(proxies, depth=0):
    """Бисекция: возвращает только ноды, с которыми mihomo стартует."""
    ok, err = _config_ok(proxies)
    if ok:
        return proxies
    if len(proxies) <= 1:
        print(f"  !! отбрасываю ноду {proxies[0].get('name')}: {err.strip()[:110]}", flush=True)
        return []
    mid = len(proxies) // 2
    return filter_valid(proxies[:mid], depth + 1) + filter_valid(proxies[mid:], depth + 1)


def kill_stale_mihomo():
    """Добить осиротевшие mihomo этого движка: после падения прогона они держат
    порты 7891/9098 и память, а новый запуск молча получает чужие результаты."""
    killed = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = open(f"/proc/{pid}/cmdline", "rb").read().decode("utf-8", "ignore")
        except Exception:
            continue
        if "mihomo" in cmd and SCRATCH in cmd:
            try:
                os.kill(int(pid), 9)
                killed += 1
            except Exception:
                pass
    return killed


def run_chunk(links, idx, mixed=7891, api_port=9098):
    proxies, mapping, seen = [], {}, set()
    for i, l in enumerate(links):
        name = f"p{idx}_{i}"
        p = ffv.link_to_proxy(l, name)
        p = sanitize_proxy(p) if p else None
        if not p:
            continue
        key = (p["type"], p["server"], p["port"], p.get("uuid") or p.get("password"))
        if key in seen:
            continue
        seen.add(key)
        proxies.append(p)
        mapping[name] = l
    if not proxies:
        return {}
    proxies = filter_valid(proxies)
    kept = {p["name"] for p in proxies}
    mapping = {k: v for k, v in mapping.items() if k in kept}   # отбракованные не пингуем
    if not proxies:
        return {}
    cfg = os.path.join(SCRATCH, f"scan_{idx}.yaml")
    open(cfg, "w").write(gen_yaml(proxies, mixed, api_port))
    log = open(os.path.join(SCRATCH, f"scan_{idx}.log"), "w")
    proc = subprocess.Popen([BIN, "-d", SCRATCH, "-f", cfg], stdout=log, stderr=log)
    time.sleep(5)
    if proc.poll() is not None:
        log.close()
        print("  !! mihomo died: " + open(os.path.join(SCRATCH, f"scan_{idx}.log")).read()[:160])
        return {}
    res = {}
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(probe_delay, api_port, n): n for n in mapping}
        try:
            for fu in cf.as_completed(futs, timeout=240):
                n = futs[fu]
                try:
                    d = fu.result()
                except Exception:
                    d = 0
                if d:
                    res[mapping[n]] = d
        except Exception as e:
            # один зависший чанк не должен убивать весь прогон: забираем что успело
            print(f"  !! чанк {idx} не уложился в таймаут ({type(e).__name__}), беру {len(res)} результатов", flush=True)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    log.close()
    return res


def latency(n_vless=1400):
    links = [re.split(r"#", l)[0] for l in json.load(open(LINKS_F))]
    # SCAN_ONLY=hy2 — весь бюджет теста уходит на один протокол.
    # Нужно там, где оператор режет VLESS по отпечатку (Yota/МегаФон): тогда
    # собирать vless бессмысленно, а hy2 живёт.
    only = os.environ.get("SCAN_ONLY", "").strip().lower()
    if only:
        pref = (("hy2://", "hysteria2://", "hysteria://")
                if only in ("hy2", "hysteria2", "hysteria") else (only + "://",))
        links = [l for l in links if l.startswith(pref)]
        print(f"SCAN_ONLY={only}: осталось {len(links)} ссылок")
    hy2 = [l for l in links if l.startswith(("hy2://", "hysteria2://", "hysteria://"))]
    vless = [l for l in links if l.startswith("vless://")]
    reality = [l for l in vless if "security=reality" in l]
    plain = [l for l in vless if "security=reality" not in l]
    random.seed(7)
    random.shuffle(reality)
    random.shuffle(plain)
    # Стратификация по транспорту: приоритет reality-over-raw-TCP устарел (с февраля 2026
    # ТСПУ морозит именно его после ~16 КБ), поэтому берём квоты по каждому транспорту.
    def has(l, *needles):
        return any(n in l for n in needles)
    bx = [l for l in vless if has(l, "type=xhttp")]
    bg = [l for l in vless if has(l, "type=grpc")]
    bw = [l for l in vless if has(l, "type=ws", "type=httpupgrade")]
    br = [l for l in vless if "security=reality" in l and has(l, "type=tcp", "type=raw") or
          ("security=reality" in l and "type=" not in l)]
    bo = [l for l in vless if l not in bx and l not in bg and l not in bw and l not in br]
    per = max(150, n_vless // 5)
    # протоколы, которые понимает YPtun (Xray + sing-box), кроме vless/hy2
    tjs = [l for l in links if l.startswith(("trojan://", "vmess://", "ss://"))]
    per2 = max(80, n_vless // 8)
    cand = hy2 + bx[:per] + bg[:per] + bw[:per] + br[:per] + bo[:per] + tjs[:per2 * 3]
    if only:
        # режим одного протокола — квоты не нужны, гоним весь пул
        cand = links
    print(f"RAM {RAM_MB} МБ -> чанк {CHUNK}, верификация {VERIFY_BATCH} нод "
          f"(ip {VERIFY_IP_PAR} пар, скорость {VERIFY_SPEED_PAR} пар)")
    print(f"hy2={len(hy2)} xhttp={len(bx)} grpc={len(bg)} ws={len(bw)} reality_tcp={len(br)} "
          f"прочее={len(bo)} trojan/vmess/ss={len(tjs)} -> тестирую {len(cand)}")
    k = kill_stale_mihomo()
    if k:
        print(f"  (убито осиротевших mihomo: {k})")
    alive = {}
    CH = CHUNK
    for i in range(0, len(cand), CH):
        t0 = time.time()
        try:
            r = run_chunk(cand[i:i + CH], i // CH)
        except Exception as e:
            print(f"  !! чанк {i // CH} упал ({type(e).__name__}: {str(e)[:60]}) — иду дальше", flush=True)
            r = {}
        alive.update(r)
        print(f"chunk {i // CH}: {len(r)} alive за {time.time() - t0:.0f}s", flush=True)
    json.dump(alive, open(ALIVE_F, "w"), indent=1)
    # что вообще тестировали: publish_sub по этому списку понимает, какие ноды
    # из прошлой подписки реально умерли, а какие просто не попали в прогон
    json.dump(sorted(set(cand)), open(TESTED_F, "w"))
    print("ALIVE:", len(alive))


def verify_one(link, port=7891, api_port=9098):
    p = ffv.link_to_proxy(link, "V")
    p = sanitize_proxy(p) if p else None
    if not p:
        return None
    cfg = os.path.join(SCRATCH, "verify.yaml")
    open(cfg, "w").write(gen_yaml([p], port, api_port))
    lg = open(os.path.join(SCRATCH, "verify.log"), "w")
    proc = subprocess.Popen([BIN, "-d", SCRATCH, "-f", cfg], stdout=lg, stderr=lg)
    try:
        time.sleep(3)
        info = None
        # ip-api.com по HTTP отваливается: лимит 45 запросов/мин на IP и часто
        # режет plain-HTTP через прокси — часть живых нод помечалась мёртвыми.
        # Поэтому несколько HTTPS-эндпоинтов, по два подхода на каждый.
        for attempt in range(2):
            for url, pick in (
                ("https://ipinfo.io/json", lambda j: {"ip": j.get("ip"), "cc": j.get("country"),
                                                      "city": j.get("city"), "isp": j.get("org")}),
                ("https://api.ipify.org?format=json", lambda j: {"ip": j.get("ip")}),
                ("https://ifconfig.me/all.json", lambda j: {"ip": j.get("ip_addr")}),
            ):
                r = subprocess.run(["curl", "-s", "--connect-timeout", "6", "--max-time", "10",
                                    "-x", f"http://127.0.0.1:{port}", url],
                                   capture_output=True, text=True)
                try:
                    j = json.loads(r.stdout)
                except Exception:
                    continue
                got = pick(j)
                if got.get("ip"):
                    info = got
                    break
            if info:
                break
        if not info:
            return None
        if not info.get("cc"):
            # гео добираем отдельно, отсутствие страны не повод выбрасывать ноду
            rg = subprocess.run(["curl", "-s", "--connect-timeout", "5", "--max-time", "8",
                                 "-x", f"http://127.0.0.1:{port}",
                                 f"https://ipinfo.io/{info['ip']}/json"],
                                capture_output=True, text=True)
            try:
                j = json.loads(rg.stdout)
                info.update({"cc": j.get("country"), "city": j.get("city"), "isp": j.get("org")})
            except Exception:
                pass
        sp = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}",
                             "--max-time", "12", "-x", f"http://127.0.0.1:{port}", SPEED_URL],
                            capture_output=True, text=True)
        speed = float(sp.stdout.strip() or 0) / 1e6
        return {"link": link, "proto": link.split("://")[0], "ip": info["ip"],
                "cc": info.get("cc") or "??", "city": info.get("city") or "",
                "isp": info.get("isp") or "", "speed_MBps": round(speed, 2)}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except Exception:
            proc.kill()
        lg.close()


# ---------------------------------------------------------------- быстрая проверка пачкой
# Последовательный verify_one поднимает mihomo на каждую ноду: 3 с старта + curl,
# ~12-15 с на ноду. На 80 нод это 15-20 минут. Вместо этого один mihomo на пачку,
# по слушателю на ноду (mihomo `listeners` с полем `proxy`), и параллельные curl'ы.
#
# Параллельность считается от двух пределов:
#   1) канал: 500 Мбит. Замер скорости искажается, если параллельных потоков больше,
#      чем канал/(ожидаемый потолок одной ноды). При потолке ~60-80 Мбит это 6-8.
#      Для фазы «выходной IP» трафик копеечный (единицы КБ), там можно 48.
#   2) железо: N100, 4 ядра, 7 ГБ. mihomo в userspace тянет TLS на ~150-250 Мбит
#      на ядро; 48 параллельных рукопожатий дают короткий пик, но длинных потоков
#      в фазе IP нет. В фазе скорости держим 6 потоков -> ~360-480 Мбит, CPU < 3 ядер.
def _mem_avail_mb():
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable"):
                return int(line.split()[1]) // 1024
    except Exception:
        pass
    return 4096


# Параллельность ограничена не только каналом, но и памятью: у N100 её 7 ГБ, из них
# под кэш/систему уходит половина. При нехватке RAM mihomo с сотней слушателей
# начинает свопиться и весь прогон идёт в таймауты — поэтому урезаем заранее.
RAM_MB = _mem_avail_mb()
VERIFY_IP_PAR = int(os.environ.get("VERIFY_IP_PAR", "48" if RAM_MB > 1500 else "24" if RAM_MB > 900 else "12"))
VERIFY_SPEED_PAR = int(os.environ.get("VERIFY_SPEED_PAR", "6" if RAM_MB > 1500 else "4" if RAM_MB > 900 else "2"))
VERIFY_BATCH = int(os.environ.get("VERIFY_BATCH", "120" if RAM_MB > 1500 else "60" if RAM_MB > 900 else "30"))
CHUNK = 350 if RAM_MB > 1500 else 200 if RAM_MB > 900 else 120


def _batch_yaml(proxies, base_port, api_port, mixed):
    out = [f"mixed-port: {mixed}", "allow-lan: false", "mode: rule", "log-level: silent",
           "ipv6: false", f"external-controller: 127.0.0.1:{api_port}", "", "proxies:"]
    for pr in proxies:
        out.append("  - name: " + yaml_str(pr["name"]))
        for k, v in pr.items():
            if k == "name":
                continue
            if isinstance(v, (dict, list)):
                out += [f"    {k}:", ffv.dump_yaml_value(v, 6)]
            elif isinstance(v, bool):
                out.append(f"    {k}: {'true' if v else 'false'}")
            else:
                out.append(f"    {k}: {yaml_str(v)}")
    out += ["", "listeners:"]
    for i, pr in enumerate(proxies):
        out += [f"  - name: L{i}", "    type: http", "    listen: 127.0.0.1",
                f"    port: {base_port + i}", "    proxy: " + yaml_str(pr["name"])]
    out += ["", "rules:", "  - MATCH,DIRECT"]
    return "\n".join(out)


def _curl(args, timeout):
    try:
        r = subprocess.run(["curl"] + args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _exit_ip(port):
    for url in ("https://api.ipify.org?format=json", "https://ifconfig.me/all.json",
                "https://ipinfo.io/json"):
        out = _curl(["-s", "--connect-timeout", "4", "--max-time", "6",
                     "-x", f"http://127.0.0.1:{port}", url], 9)
        if not out:
            continue
        try:
            j = json.loads(out)
        except Exception:
            continue
        ip = j.get("ip") or j.get("ip_addr")
        if ip:
            return ip
    return None


def _geo(ip):
    out = _curl(["-s", "--max-time", "6", f"https://ipinfo.io/{ip}/json"], 9)
    try:
        j = json.loads(out)
        return {"cc": j.get("country") or "??", "city": j.get("city") or "",
                "isp": j.get("org") or ""}
    except Exception:
        return {"cc": "??", "city": "", "isp": ""}


def _speed(port):
    out = _curl(["-s", "-o", "/dev/null", "-w", "%{speed_download}", "--max-time", "8",
                 "-x", f"http://127.0.0.1:{port}", SPEED_URL], 12)
    try:
        return float(out or 0) / 1e6
    except Exception:
        return 0.0


def verify_batch(top, base_port=20000, api_port=9097):
    """top: [(link, delay)] -> список проверенных. Один mihomo на пачку."""
    import concurrent.futures as cf
    results = []
    kill_stale_mihomo()
    for start in range(0, len(top), VERIFY_BATCH):
        chunk = top[start:start + VERIFY_BATCH]
        proxies, ports = [], {}
        for i, (link, delay) in enumerate(chunk):
            p = ffv.link_to_proxy(link, f"b{start + i}")
            p = sanitize_proxy(p) if p else None
            if not p:
                continue
            p["port"] = int(p["port"])
            proxies.append(p)
            ports[p["name"]] = (link, delay)
        if not proxies:
            continue
        proxies = filter_valid(proxies)
        cfg = os.path.join(SCRATCH, f"batch_{start}.yaml")
        open(cfg, "w").write(_batch_yaml(proxies, base_port, api_port, base_port - 11000))
        lg = open(os.path.join(SCRATCH, f"batch_{start}.log"), "w")
        proc = subprocess.Popen([BIN, "-d", SCRATCH, "-f", cfg], stdout=lg, stderr=lg)
        try:
            time.sleep(4)
            # фаза 1: выходной IP, широко и параллельно
            with cf.ThreadPoolExecutor(max_workers=VERIFY_IP_PAR) as ex:
                futs = {ex.submit(_exit_ip, base_port + i): p
                        for i, p in enumerate(proxies)}
                for fu in cf.as_completed(futs):
                    p = futs[fu]
                    try:
                        ip = fu.result()
                    except Exception:
                        ip = None
                    if ip:
                        ports[p["name"]] = ports[p["name"]] + (ip,)
            live = [(n, v) for n, v in ports.items() if len(v) == 3]
            print(f"  фаза IP: {len(live)}/{len(proxies)} живы", flush=True)

            # фаза 2: скорость, узко — иначе потоки делят 500 Мбит и замер врёт
            def worker(idx_name):
                idx, name = idx_name
                return name, _speed(base_port + idx)

            idx_map = {p["name"]: i for i, p in enumerate(proxies)}
            with cf.ThreadPoolExecutor(max_workers=VERIFY_SPEED_PAR) as ex:
                futs = {ex.submit(worker, (idx_map[n], n)): n for n, _ in live}
                for fu in cf.as_completed(futs):
                    name, sp = fu.result()
                    link, delay, ip = ports[name]
                    g = _geo(ip)
                    results.append({"link": link, "proto": link.split("://")[0], "ip": ip,
                                    "cc": g["cc"], "city": g["city"], "isp": g["isp"],
                                    "delay": delay, "speed_MBps": round(sp, 2)})
                    print(f"   {g['cc']} {g['city'][:14]:<14} {delay:>5}ms {sp:>6.2f} MB/s "
                          f"{ip:<15} {link[:44]}", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            lg.close()
    return results

def verify(n=45):
    alive = json.load(open(ALIVE_F))
    # квота по протоколам: иначе быстрые vless вытесняют hy2 из проверки,
    # хотя именно hy2 нужен там, где vless режут по отпечатку
    is_h2 = lambda l: l.startswith(("hy2://", "hysteria2://", "hysteria://"))
    h2 = sorted([kv for kv in alive.items() if is_h2(kv[0])], key=lambda kv: kv[1])
    rest = sorted([kv for kv in alive.items() if not is_h2(kv[0])], key=lambda kv: kv[1])
    quota = n if not rest else max(n // 2, int(n * 0.6))

    def pick(cands, budget, per_addr=2):
        """Сначала по одному-два конфига с адреса, остальное — как добор."""
        out, seen, spare = [], {}, []
        for link, d in cands:
            a = _host_of(link)
            if not a:
                continue
            if seen.get(a, 0) < per_addr:
                seen[a] = seen.get(a, 0) + 1
                out.append((link, d))
                if len(out) >= budget:
                    return out
            else:
                spare.append((link, d))
        for link, d in spare:
            if len(out) >= budget:
                break
            out.append((link, d))
        return out

    top = pick(h2, quota) + pick(rest, max(0, n - min(len(h2), quota)))

    # Ротация: часть бюджета уходит на перепроверку уже опубликованных нод,
    # иначе однажды проверенная нода висит в подписке вечно, даже если умерла.
    # Берём самые «просроченные» по времени последней успешной проверки.
    try:
        hist = json.load(open(HIST_F))
    except Exception:
        hist = {}
    now = time.time()
    STALE_H = float(os.environ.get("VERIFY_STALE_H", "12"))
    chosen = {l for l, _ in top}
    stale = sorted(((ts, l) for l, ts in hist.items()
                    if now - ts > STALE_H * 3600 and l not in chosen),
                   key=lambda x: x[0])
    budget_stale = max(4, int(n * 0.3))
    for ts, l in stale[:budget_stale]:
        top.append((l, 0))
    if os.environ.get("VERIFY_SEQ", "") == "1":
        out = []
        for i, (link, delay) in enumerate(top):
            v = verify_one(link)
            if v:
                v["delay"] = delay
                out.append(v)
                print(f"{i:3} {v['cc']} {v['city'][:14]:<14} {v['isp'][:26]:<26} {delay:>5}ms {v['speed_MBps']:>6} MB/s  {link[:50]}", flush=True)
            else:
                print(f"{i:3} dead {link[:55]}", flush=True)
    else:
        out = verify_batch(top)
    json.dump(out, open(VERIFIED_F, "w"), indent=1)
    for v in out:
        hist[v["link"]] = now
    json.dump(hist, open(HIST_F, "w"))
    print(f"verified: {len(out)} (перепроверено из старых: {min(len(stale), budget_stale)})")


def report():
    d = json.load(open(VERIFIED_F))
    d.sort(key=lambda x: -x["speed_MBps"])
    os.makedirs(RESULTS, exist_ok=True)
    out = os.path.join(RESULTS, "free_any_%s.txt" % time.strftime("%Y-%m-%d"))
    open(out, "w").write("\n".join(x["link"] for x in d) + "\n")
    print("saved:", out, "| by proto:", dict(collections.Counter(x["proto"] for x in d)))
    for x in d[:12]:
        print(f"{x['cc']} {x['city'][:14]:<14} {x['speed_MBps']:>6} MB/s {x['delay']:>5} ms {x['proto']:<10} {x['ip']}")



# ------------------------------------------------------------------ чистота измерений
# Скан обязан идти напрямую: если роутер заворачивает часть IP в WireGuard (PBR/ТСПУ-обход),
# нода «работает» только через туннель — на телефоне без VPN она мертва. Это ложный плюс.
ROUTER = os.environ.get("SCAN_ROUTER", "")
ROUTER_PASS = os.environ.get("SCAN_ROUTER_PASS", "")


def _ssh(cmd, timeout=30):
    base = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", ROUTER, cmd]
    if ROUTER_PASS:
        base = ["sshpass", "-p", ROUTER_PASS] + base
    r = subprocess.run(base, capture_output=True, text=True, timeout=timeout)
    return r.stdout


def _router_policy():
    """Возвращает (сети из статических политик PBR, множество IP динамического nftset)."""
    import ipaddress
    nets, dyn = [], set()
    try:
        out = _ssh("grep 'list dest_addr' /etc/config/pbr")
        for m in re.finditer(r"list dest_addr '([^']+)'", out):
            try:
                nets.append(ipaddress.ip_network(m.group(1).strip(), strict=False))
            except Exception:
                pass  # домены в политике не проверяем офлайн
        out = _ssh("nft list set inet fw4 pbr_wg0_4_dst_ip_blocked 2>/dev/null")
        dyn = set(re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", out))
    except Exception as e:
        print(f"  !! роутер недоступен ({str(e)[:40]}) — проверка чистоты пропущена")
    return nets, dyn


def _resolve(host):
    import socket
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        return [host]
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except Exception:
        return []


def node_host(link):
    """Хост ноды для проверки PBR. Через общий разбор: regex ломался на IPv6,
    на hy2 со слешем и на legacy-ss (там host вообще в base64)."""
    hp = _host_of(link)
    return hp[0] if hp else ""


def _live_route(link, port=7895, api_port=9099):
    """Ground truth: поднять ноду, покачать через неё и спросить роутер, куда ушёл поток."""
    p = ffv.link_to_proxy(link, "V")
    p = sanitize_proxy(p) if p else None
    if not p:
        return "no-parse"
    cfg = os.path.join(SCRATCH, "livechk.yaml")
    open(cfg, "w").write(gen_yaml([p], port, api_port))
    lg = open(os.path.join(SCRATCH, "livechk.log"), "w")
    proc = subprocess.Popen([BIN, "-d", SCRATCH, "-f", cfg], stdout=lg, stderr=lg)
    try:
        import threading
        time.sleep(3)
        t = threading.Thread(target=lambda: subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "--max-time", "12",
             "-x", f"http://127.0.0.1:{port}", SPEED_URL], capture_output=True))
        t.start()
        time.sleep(4)
        dst = []
        for ip in (_resolve(p["server"]) or [p["server"]]):
            try:
                dst += re.findall(r"dst=(\S+)", _ssh(f"grep {ip} /proc/net/nf_conntrack | head -4", timeout=20))
            except Exception:
                pass
        t.join(timeout=20)
        if any(d.startswith("10.66.66.") for d in dst):
            return "via-WG(conntrack)"
        return "direct" if dst else "unverified(no-conntrack)"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except Exception:
            proc.kill()
        lg.close()


def clean(live=False, src="final.json"):
    """Проверить, что найденные ноды ходят НАПРЯМУЮ, а не через WG/PBR роутера."""
    import ipaddress
    # приоритет: явно указанный файл -> свежий verified.json -> final.json
    path = os.path.join(CACHE, src) if src != "final.json" else os.path.join(CACHE, "verified.json")
    if not os.path.exists(path):
        path = os.path.join(CACHE, "final.json")
    data = json.load(open(path))
    nets, dyn = _router_policy()
    good, bad = [], []
    for v in data:
        host = node_host(v["link"])
        ips = _resolve(host)
        verdict = "direct"
        for ip in ips:
            try:
                a = ipaddress.ip_address(ip)
            except Exception:
                continue
            if ip in dyn or any(a in n for n in nets):
                verdict = f"via-WG(policy {ip})"
                break
        if verdict == "direct" and live:
            verdict = _live_route(v["link"])
        (bad if verdict.startswith("via-WG") else good).append(dict(v, route=verdict))
    os.makedirs(RESULTS, exist_ok=True)
    out = os.path.join(RESULTS, "clean_%s.txt" % time.strftime("%Y-%m-%d"))
    open(out, "w").write("\n".join(x["link"] for x in good) + "\n")
    unver = [x for x in good if x["route"].startswith("unverified")]
    print(f"clean: {len(good) - len(unver)} подтверждено напрямую, {len(unver)} без подтверждения, "
          f"{len(bad)} через туннель -> {out}")
    for x in unver:
        print(f"  ? {x.get('cc')} {x['route']:<24} {x['link'][:60]}")
    for x in bad:
        print(f"  X {x.get('cc')} {x['route']:<24} {x['link'][:60]}")
    return good


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "report"
    arg = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
    {"collect": collect, "latency": lambda: latency(arg or 1400), "verify": lambda: verify(arg or 45),
     "clean": lambda: clean(live="--live" in sys.argv), "report": report}[mode]()
