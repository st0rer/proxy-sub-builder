#!/usr/bin/env python3
"""pi_sb_verify.py — проверка нод с малинки через sing-box (вместо mihomo 1.18).

Зачем: mihomo 1.18.10 на Cortex-A53 не обновить (новее — segfault), а anytls и tuic
он не знает вообще (`unsupport proxy type: anytls`). sing-box 1.14.4 arm64 на этой
же малинке работает и умеет оба протокола.

  pi_sb_verify.py <sb.json> <nodes.json> <out.json>

nodes.json: [{"name": "N0", "port": 21000, "link": "anytls://...", "dst": ["ip", 443]}]
Конфиг sing-box со socks-слушателями уже собран на N100 (там же парсеры).
"""
import json
import os
import socket
import struct
import subprocess
import sys
import time

SB = "/opt/vpntest/sing-box"
# Один URL — источник ложных отсевов: замер 16.11 на 42 отвергнутых нодах дал
# 4 живых (27% от достижимых). Причина в том, что gstatic у части выходов режется,
# а данные при этом ходят. Поэтому три ступени и одна повторная попытка.
DELAY_STAGES = (
    ("https://www.gstatic.com/generate_204", 7, "gstatic"),
    ("http://cp.cloudflare.com/generate_204", 10, "cp-cf"),
    ("https://speed.cloudflare.com/__down?bytes=16384", 12, "body16k"),
)
QUIC_PROTOS = ("hy2", "hysteria2", "hysteria", "tuic")
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=500000"
SPEED_TOP = int(os.environ.get("SPEED_TOP", "10"))
BUDGET_MB = float(os.environ.get("BUDGET_MB", "12"))
DELAY_TIMEOUT = int(os.environ.get("DELAY_TIMEOUT", "7"))
DNS_Q = bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001")


def socks5_udp_dns(port, dst=("1.1.1.1", 53), timeout=5.0):
    """UDP через SOCKS5: реальный DNS-запрос. TCP-проверка о UDP ничего не говорит,
    а звонки Telegram и QUIC-видео живут только на UDP."""
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


def mem_avail_mb():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return 0


def kill_stale():
    killed = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            args = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        except Exception:
            continue
        if args and args[0].endswith(b"sing-box"):
            try:
                os.kill(int(pid), 15)
                killed += 1
            except Exception:
                pass
    if killed:
        time.sleep(1.5)
    return killed


def sweep(workdir):
    freed = 0
    try:
        for name in os.listdir(workdir):
            p = os.path.join(workdir, name)
            if not os.path.isfile(p):
                continue
            if name.endswith(".log") and os.path.getsize(p) > 512 * 1024:
                os.truncate(p, 0)
                freed += 1
            elif name.endswith((".json", ".yaml")) and name not in ("nodes.json", "sb.json", "out.json"):
                if time.time() - os.path.getmtime(p) > 3600:
                    os.remove(p)
                    freed += 1
    except Exception:
        pass
    return freed


def curl_probe(port, url, max_time, fmt="%{http_code} %{time_total}"):
    r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", fmt, "--max-time", str(max_time),
                        "--socks5-hostname", f"127.0.0.1:{port}", url],
                       capture_output=True, text=True, timeout=max_time + 3)
    return r.stdout.strip().split()


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


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    cfg, nodes_f, out_f = sys.argv[1:4]
    nodes = json.load(open(nodes_f))
    workdir = os.path.dirname(cfg)

    killed = kill_stale()
    if killed:
        print(f"  добил висящих sing-box: {killed}", flush=True)
    swept = sweep(workdir)
    if swept:
        print(f"  убрал старых файлов: {swept}", flush=True)
    avail = mem_avail_mb()
    if avail < 120:
        print(f"мало памяти ({avail} МБ) — прогон отменён", file=sys.stderr)
        return 4

    log = open(os.path.join(workdir, "singbox.log"), "w")
    proc = subprocess.Popen([SB, "run", "-c", cfg], stdout=log, stderr=subprocess.STDOUT)
    try:
        # ждём, пока поднимутся listeners (sing-box стартует быстрее mihomo)
        t0 = time.time()
        ready = False
        while time.time() - t0 < 15:
            if proc.poll() is None and os.path.exists(f"/proc/{proc.pid}"):
                time.sleep(1.2)
                ready = True
                break
            time.sleep(0.3)
        if not ready or proc.poll() is not None:
            print("sing-box не поднялся:", open(os.path.join(workdir, "singbox.log")).read()[-600:],
                  file=sys.stderr)
            return 3

        def tcp_ok(n):
            if n["link"].split("://")[0] in QUIC_PROTOS:
                return True          # у QUIC TCP-порт закрыт штатно
            host = n["link"].split("://", 1)[1].split("#")[0]
            if "@" in host:
                host = host.split("@", 1)[1]
            host = host.split("?")[0].split("/")[0]
            h, _, p = host.rpartition(":")
            if not h:
                h, p = host, "443"
            try:
                port_num = int(p)
            except Exception:
                return False
            # На мобильном интернете (Yota 4G через модем) часто случаются задержки
            # радиоканала (RRC-переходы, джиттер). Таймаут 4.5 с + 1 ретрай на 3.5 с
            # спасают до 30% ложно-отсеянных узлов.
            for attempt, to in enumerate((4.5, 3.5)):
                s = socket.socket()
                s.settimeout(to)
                try:
                    s.connect((h, port_num))
                    return True
                except Exception:
                    pass
                finally:
                    s.close()
            return False

        import concurrent.futures as cf
        t0 = time.time()
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            flags = list(ex.map(tcp_ok, nodes))
        nodes = [n for n, ok in zip(nodes, flags) if ok]
        print(f"  фаза 0 (TCP): {len(nodes)} из {len(flags)} достижимы, {time.time()-t0:.1f} c", flush=True)
        if not nodes:
            json.dump([], open(out_f, "w"))
            return 0
        par = 6 if avail > 400 else (4 if avail > 250 else 2)

        def try_stages(port, stages):
            """Пройти лестницу URL, вернуть (задержка_мс, метка_этапа) или (0, "")."""
            for url, mt, label in stages:
                out = curl_probe(port, url, mt, "%{http_code} %{size_download} %{time_total}")
                code = out[0] if out else "000"
                size = int(float(out[1])) if len(out) > 2 else 0
                # Проверка размера тела: заглушка (страница воркера, портал оператора)
                # отвечает 200 и проходит по коду, но трафика не везёт. 16 КБ — тот
                # самый запрос, значит меньше 15 КБ пришло не от CDN.
                if code == "200" and "bytes=" in url and size < 15000:
                    code = "short"
                if code in ("204", "200"):
                    return (int(float(out[2]) * 1000) if len(out) > 2 else 1), label
            return 0, ""

        def probe(n):
            delay, stage = try_stages(n["port"], list(DELAY_STAGES))
            udp = socks5_udp_dns(n["port"]) if delay else False
            return {**n, "delay": delay, "speed": None, "speed_measured": False,
                    "udp": udp, "stage": stage}

        rows = []
        with cf.ThreadPoolExecutor(max_workers=par) as ex:
            for r in ex.map(probe, nodes):
                rows.append(r)
                if r["delay"]:
                    print(f"  {r['delay']:>5} мс  udp={'да ' if r['udp'] else 'нет'}  [{r['stage']}]  {r['link'][:42]}",
                          flush=True)

        # Второй проход по «мёртвым» с длинными таймаутами. Замер 16.11.2026 на
        # 101 ноде: 10 живых в быстром режиме, 14 при повторной проверке — 4 рабочие
        # ноды (28 % от живых) терялись на flap'ах и таймаутах 7/10 с. Один повтор
        # с 15/18 с возвращает их, стоит ~40 с на мёртвую ноду и не тратит трафик.
        RECOVERY = (("http://cp.cloudflare.com/generate_204", 15, "cp-cf-r"),
                    ("https://speed.cloudflare.com/__down?bytes=16384", 18, "body16k-r"),
                    ("https://www.gstatic.com/generate_204", 10, "gstatic-r"))
        dead = [r for r in rows if not r["delay"]]
        if dead and os.environ.get("NO_RECOVERY") != "1":
            print(f"  второй проход по {len(dead)} мёртвым (длинные таймауты)…", flush=True)
            def redo(r):
                delay, stage = try_stages(r["port"], RECOVERY)
                if delay:
                    udp = socks5_udp_dns(r["port"])
                    print(f"  +{delay:>5} мс  [{stage}]  {r['link'][:42]}", flush=True)
                    return {**r, "delay": delay, "stage": stage, "udp": udp}
                return r
            t1 = time.time()
            with cf.ThreadPoolExecutor(max_workers=par) as ex:
                rows = list(ex.map(redo, rows))
            print(f"  второй проход: {time.time()-t1:.0f} c, живых стало "
                  f"{sum(1 for r in rows if r['delay'])}", flush=True)

        # подтверждение выхода: 204 означает «через туннель что-то ответило», но не
        # доказывает, что трафик выходит именно из ноды. ipify/ifconfig стоят ~1 КБ
        def exit_ip(n):
            for url in ("https://api.ipify.org?format=json", "http://ifconfig.me/all.json",
                        "https://ipinfo.io/json"):
                out = subprocess.run(["curl", "-s", "--max-time", "8", "--socks5-hostname",
                                      f"127.0.0.1:{n['port']}", url], capture_output=True, text=True)
                try:
                    j = json.loads(out.stdout or "{}")
                except Exception:
                    continue
                ip = j.get("ip") or j.get("ip_addr")
                if ip:
                    return ip
            return ""

        live0 = [r for r in rows if r["delay"]]
        with cf.ThreadPoolExecutor(max_workers=par) as ex:
            for r, ip in zip(live0, ex.map(exit_ip, live0)):
                r["ip"] = ip

        skip_gemini = os.environ.get("SKIP_GEMINI_GATE") == "1"
        if not skip_gemini and live0:
            print(f"  проверка гейта Gemini/Antigravity для {len(live0)} живых нод…", flush=True)
            with cf.ThreadPoolExecutor(max_workers=par) as ex:
                for r, gres in zip(live0, ex.map(lambda x: check_gemini_gate(x["port"]), live0)):
                    r["gemini"] = gres
            gem_ok = sum(1 for r in live0 if r.get("gemini") == "ok")
            print(f"  гейт Gemini/Antigravity пройден: {gem_ok} из {len(live0)}", flush=True)

        # Раньше нода без ответа ipify выбрасывалась. Это ложное отрицание: факт
        # прохождения 16 КБ с CDN уже доказывает, что трафик выходит, а ipify у
        # части выходов блокируется или отвечает дольше 8 с. Оставляем поле как
        # справку; жёсткий отсев — только по флагу.
        if os.environ.get("REQUIRE_EXIT_IP") == "1":
            rows = [r for r in rows if not r["delay"] or r.get("ip")]
        traffic = len(nodes) * 0.009
        # Приоритет в замере скорости: сначала ноды, прошедшие гейт Gemini/Antigravity,
        # чтобы вписаться в BUDGET_MB именно нужными для работы нодами!
        live = sorted([r for r in rows if r["delay"]],
                      key=lambda r: (0 if r.get("gemini") == "ok" else 1, r["delay"]))
        for r in live[:SPEED_TOP]:
            if traffic >= BUDGET_MB:
                print(f"  бюджет {BUDGET_MB} МБ исчерпан — скорость дальше не меряю", flush=True)
                break
            out = curl_probe(r["port"], SPEED_URL, 12, "%{speed_download}")
            try:
                r["speed"] = round(float(out[0]) / 1e6, 2) if out else 0.0
                r["speed_measured"] = True
            except ValueError:
                r["speed"] = 0.0
                r["speed_measured"] = True
            traffic += 0.5
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
