#!/usr/bin/env python3
"""pi_verify.py — проверка нод ИЗ СЕТИ YOTA (Raspberry Pi за Keenetic).

Запускается на малинке: mihomo поднимает по слушателю на ноду, здесь считаем
задержку, проверяем UDP (звонки Telegram идут по UDP) и меряем скорость.
Трафик мобильный, поэтому: задержка стоит ~6 КБ на ноду, скорость — 1 МБ и только
для лучших по задержке, плюс жёсткий бюджет в мегабайтах.

  pi_verify.py <config.yaml> <nodes.json> <out.json>

nodes.json: [{"name": "L0", "port": 21000, "link": "vless://..."}]
"""
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

MIHOMO = "/opt/vpntest/mihomo"
API = "http://127.0.0.1:9099"
DELAY_URL = "https://www.gstatic.com/generate_204"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
SPEED_TOP = int(os.environ.get("SPEED_TOP", "12"))
BUDGET_MB = float(os.environ.get("BUDGET_MB", "14"))
DELAY_TIMEOUT = int(os.environ.get("DELAY_TIMEOUT", "6000"))

# DNS-запрос example.com A — минимальный полезный UDP-пакет
DNS_Q = bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001")


def socks5_udp_dns(port, dst=("1.1.1.1", 53), timeout=5.0):
    """Проверка UDP через SOCKS5: реальный DNS-запрос к 1.1.1.1.

    Отдельный тест нужен потому, что TCP-проверка ничего не говорит о UDP:
    нода может отлично возить HTTPS и не пропускать UDP — тогда звонки Telegram
    и QUIC-видео не работают, хотя «нода рабочая».
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return False
        s.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
        rep = s.recv(10)
        if len(rep) < 10 or rep[1] != 0:
            return False
        relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])
        if relay[0] == "0.0.0.0" or relay[1] == 0:
            relay = ("127.0.0.1", port)

        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(timeout)
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton(dst[0]) + struct.pack(">H", dst[1]) + DNS_Q
        u.sendto(pkt, relay)
        data, _ = u.recvfrom(2048)
        u.close()
        if len(data) < 12:
            return False
        dns = data[10:]
        return len(dns) > 12 and dns[3] & 0x0F == 0 and struct.unpack(">H", dns[6:8])[0] > 0
    except Exception:
        return False
    finally:
        s.close()


def api_get(path, timeout=DELAY_TIMEOUT / 1000 + 3):
    try:
        out = subprocess.run(["curl", "-s", "--max-time", str(int(timeout)),
                              API + path], capture_output=True, text=True, timeout=timeout + 2)
        return json.loads(out.stdout or "{}")
    except Exception:
        return {}


def wait_api(sec=25):
    for _ in range(sec * 2):
        if api_get("/version", 2):
            return True
        time.sleep(0.5)
    return False


def speed(port, max_time=8):
    try:
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", str(max_time),
                            "-w", "%{speed_download}",
                            "--socks5-hostname", f"127.0.0.1:{port}", SPEED_URL],
                           capture_output=True, text=True, timeout=max_time + 3)
        return float(r.stdout.strip() or 0) / 1e6
    except Exception:
        return 0.0


def check_gemini_gate(port, timeout=7):
    """Проверка доступности Google Gemini и Antigravity (Cloud Code PA).

    1) daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist:
       POST {} -> 401 (или 200) = локация принята, IP чистый. 400/403 = геоблок / отказ.
    2) gemini.google.com/app:
       GET -> 200 = интерфейс Gemini открывается. 403 / sorry = бан IP или капча.

    Возвращает статус: 'ok', 'geoblock', 'sorry' или 'err'.
    """
    cmd_lca = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", str(timeout),
        "-X", "POST", "-H", "Content-Type: application/json", "-d", "{}",
        "--socks5-hostname", f"127.0.0.1:{port}",
        "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
    ]
    try:
        r_lca = subprocess.run(cmd_lca, capture_output=True, text=True, timeout=timeout + 3)
        glca = r_lca.stdout.strip()
    except Exception:
        glca = "000"

    if glca in ("400", "403"):
        return "geoblock"
    if glca not in ("401", "200"):
        return "err"

    cmd_gem = [
        "curl", "-s", "-D", "-", "-o", "/dev/null",
        "--max-time", str(timeout),
        "--socks5-hostname", f"127.0.0.1:{port}",
        "https://gemini.google.com/app",
    ]
    try:
        r_gem = subprocess.run(cmd_gem, capture_output=True, text=True, timeout=timeout + 3)
        hdr = r_gem.stdout
    except Exception:
        hdr = ""

    code, loc = "", ""
    for line in hdr.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) > 1:
                code = parts[1]
        elif line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()

    if code == "200":
        return "ok"
    if "sorry" in loc.lower():
        return "sorry"
    if code in ("400", "403"):
        return "geoblock"
    if code.startswith("3") and "not-available" in loc.lower():
        return "geoblock"
    if code.startswith("3") and "sorry" not in loc.lower():
        return "ok"
    return code or "err"


def mem_avail_mb():
    """Свободная память без учёта кэша — по ней считаем параллельность."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return 0


def kill_stale_mihomo(workdir):
    """Добивает mihomo от предыдущего упавшего прогона.

    Без этого он держит API-порт 9099 и socks-порты, и новый прогон либо не
    поднимается, либо получает ответы от чужого конфига — то есть проверяет
    не те ноды, которые просили.
    """
    killed = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            args = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        except Exception:
            continue
        if not args or b"mihomo" not in args[0]:
            continue
        if workdir.encode() in b" ".join(args):
            try:
                os.kill(int(pid), 15)
                killed += 1
            except Exception:
                pass
    if killed:
        time.sleep(1.5)
    return killed


def cleanup_workdir(workdir, keep_logs=3):
    """tmpfs /run всего 192 МБ: чистим старые конфиги и разросшиеся логи."""
    freed = 0
    try:
        for name in os.listdir(workdir):
            p = os.path.join(workdir, name)
            if not os.path.isfile(p):
                continue
            if name.endswith(".log") and os.path.getsize(p) > 512 * 1024:
                os.truncate(p, 0)
                freed += 1
            elif name.endswith((".json", ".yaml")) and name not in ("nodes.json", "results.json"):
                if time.time() - os.path.getmtime(p) > 3600:
                    os.remove(p)
                    freed += 1
    except Exception:
        pass
    return freed



def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    cfg, nodes_f, out_f = sys.argv[1:4]
    nodes = json.load(open(nodes_f))
    workdir = os.path.dirname(cfg)

    # малинка: 955 МБ RAM, tmpfs 192 МБ — без уборки и гварда прогон умирает молча
    killed = kill_stale_mihomo(workdir)
    if killed:
        print(f"  добил висящих mihomo: {killed}", flush=True)
    swept = cleanup_workdir(workdir)
    if swept:
        print(f"  убрано старых файлов в {workdir}: {swept}", flush=True)
    avail = mem_avail_mb()
    if avail < 120:
        print(f"мало памяти ({avail} МБ свободно) — прогон отменён, чтобы не уйти в swap",
              file=sys.stderr)
        return 4

    log = open(os.path.join(workdir, "mihomo.log"), "w")
    proc = subprocess.Popen([MIHOMO, "-d", workdir, "-f", cfg],
                            stdout=log, stderr=subprocess.STDOUT)
    try:
        if not wait_api():
            print("mihomo не поднялся:", open(os.path.join(workdir, "mihomo.log")).read()[-800:],
                  file=sys.stderr)
            return 3

        # Проверки идут параллельно: последовательно мёртвая нода стоит полный
        # таймаут (6 с), и 69 кандидатов растягиваются на 7 минут — на Pi 3 это
        # ещё и лишний нагрев. 6 потоков = 1.5–2 минуты при том же трафике.
        import concurrent.futures as cf
        # 6 потоков — норма для Pi 3 при ~760 МБ свободных; при нехватке памяти
        # проверки начинают свопиться и всё упирается в таймауты
        if avail > 400:
            par_default = 6
        elif avail > 250:
            par_default = 4
        else:
            par_default = 2
        PAR = int(os.environ.get("PI_PAR", str(par_default)))

        def probe(n):
            q = urllib.parse.quote(DELAY_URL, safe="")
            d = api_get(f"/proxies/{n['name']}/delay?timeout={DELAY_TIMEOUT}&url={q}")
            delay = int(d.get("delay") or 0)
            udp = socks5_udp_dns(n["port"]) if delay else False
            return {**n, "delay": delay, "speed": 0.0, "udp": udp}

        # Фаза 0: TCP-достижимость самого адреса ноды, без прокси и без трафика.
        # На Yota часть подсетей (AWS и др.) просто не маршрутизируется: и hy2,
        # и ss, и vless там дают Timeout на любом порту. Отсеиваем это до
        # протокольных проверок — дешевле и честнее, чем считать ноду «мёртвой по QUIC».
        def reachable(n):
            dst = n.get("dst")
            if not dst:
                return n, True
            s = socket.socket()
            s.settimeout(5)
            try:
                s.connect((dst[0], int(dst[1])))
                return n, True
            except Exception:
                return n, False
            finally:
                s.close()

        unreach = 0
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            for n, ok in ex.map(reachable, nodes):
                n["reachable"] = ok
                unreach += 0 if ok else 1
        if unreach:
            print(f"  недостижимо с Yota (адрес): {unreach} из {len(nodes)}", flush=True)

        rows = []
        live_nodes = [n for n in nodes if n.get("reachable", True)]
        with cf.ThreadPoolExecutor(max_workers=PAR) as ex:
            for r in ex.map(probe, live_nodes):
                rows.append(r)
                if r["delay"]:
                    print(f"  {r['delay']:>5} мс  udp={'да ' if r['udp'] else 'нет'}  {r['link'][:46]}", flush=True)
        rows += [{**n, "delay": 0, "speed": 0.0, "udp": False, "reason": "ip-unreachable"}
                 for n in nodes if not n.get("reachable", True)]

        live0 = [r for r in rows if r["delay"]]
        skip_gemini = os.environ.get("SKIP_GEMINI_GATE") == "1"
        if not skip_gemini and live0:
            print(f"  проверка гейта Gemini/Antigravity для {len(live0)} живых нод…", flush=True)
            with cf.ThreadPoolExecutor(max_workers=PAR) as ex:
                for r, gres in zip(live0, ex.map(lambda x: check_gemini_gate(x["port"]), live0)):
                    r["gemini"] = gres
            gem_ok = sum(1 for r in live0 if r.get("gemini") == "ok")
            print(f"  гейт Gemini/Antigravity пройден: {gem_ok} из {len(live0)}", flush=True)

        traffic = len(live_nodes) * 0.008

        # Приоритет в замере скорости: сначала ноды, прошедшие гейт Gemini/Antigravity
        live = sorted([r for r in rows if r["delay"]],
                      key=lambda r: (0 if r.get("gemini") == "ok" else 1, r["delay"]))
        batch = live[:SPEED_TOP]
        for i in range(0, len(batch), 3):
            if traffic >= BUDGET_MB:
                print(f"  бюджет {BUDGET_MB} МБ исчерпан — скорость дальше не меряю", flush=True)
                break
            chunk = batch[i:i + 3]
            with cf.ThreadPoolExecutor(max_workers=3) as ex:
                for r, sp in zip(chunk, ex.map(lambda x: speed(x["port"]), chunk)):
                    r["speed"] = round(sp, 2)
                    traffic += 1.0
                    print(f"  скорость {r['speed']:>5.2f} МБ/с gemini={r.get('gemini', 'skip')}  {r['link'][:44]}", flush=True)

        json.dump(rows, open(out_f, "w"))
        print(f"итог: {len(live)} из {len(nodes)} живых, трафик ≈ {traffic:.1f} МБ", flush=True)
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
