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
    pids = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            args = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        except Exception:
            continue
        if args and any(p in args[0] for p in (b"sing-box", b"mihomo")):
            try:
                os.kill(int(pid), 15)
                pids.append(int(pid))
                killed += 1
            except Exception:
                pass
    if pids:
        time.sleep(1.2)
        # Добиваем зависшие процессы через SIGKILL, освобождая порты 21000+
        for pid in pids:
            try:
                os.kill(pid, 9)
            except Exception:
                pass
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


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"


def check_gemini_gate(port, timeout=5):
    """Проверка доступности Google Gemini и Antigravity (Cloud Code PA).

    1) daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist:
       POST {} -> 401 (или 200) = локация принята, IP чистый. 400/403 = геоблок / отказ.
    2) gemini.google.com/app:
       GET -> 200 = интерфейс Gemini открывается. 403 / sorry = бан IP или капча.

    Возвращает статус: 'ok', 'geoblock', 'sorry' или 'err'.
    Не отсекает ноды ложно при сетевом джиттере мобильного канала.
    """
    cmd_lca = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", str(timeout), "--connect-timeout", "3",
        "-X", "POST", "-H", "Content-Type: application/json", "-d", "{}",
        "-A", UA,
        "--socks5-hostname", f"127.0.0.1:{port}",
        "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
    ]
    try:
        r_lca = subprocess.run(cmd_lca, capture_output=True, text=True, timeout=timeout + 2)
        glca = r_lca.stdout.strip()
    except Exception:
        glca = "000"

    # Явный региональный отказ со стороны Google Cloud Code (РФ/Иран и т.п.)
    if glca in ("400", "403"):
        return "geoblock"

    cmd_gem = [
        "curl", "-s", "-D", "-", "-o", "/dev/null",
        "--max-time", str(timeout), "--connect-timeout", "3",
        "-A", UA,
        "--socks5-hostname", f"127.0.0.1:{port}",
        "https://gemini.google.com/app",
    ]
    try:
        r_gem = subprocess.run(cmd_gem, capture_output=True, text=True, timeout=timeout + 2)
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

    # Анализ ответов:
    # 1. Явные блокировки
    if "sorry" in loc.lower():
        return "sorry"   # Анти-бот капча Google Sorry
    if code in ("400", "403") or (code.startswith("3") and "not-available" in loc.lower()):
        return "geoblock"

    # 2. Подтверждённый успех
    if code == "200" or (code.startswith("3") and "accounts.google.com" in loc.lower()):
        return "ok"
    if glca in ("401", "200"):
        # Если loadCodeAssist принял локацию, но gemini.google.com дал таймаут из-за
        # радиоканала Yota, нода пригодна для Antigravity и Cloud Code — не отсекаем её ложно.
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
            dst = n.get("dst")
            if dst:
                h, p = dst[0], dst[1]
            else:
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
        # На Raspberry Pi 3 ровно 4 ядра (Cortex-A53): больше 4 воркеров создаёт
        # перегрузку планировщика ядра и троттлинг CPU. Ограничиваем сверху 4.
        par = min(4, 4 if avail > 250 else 2)

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

        # Второй проход по «мёртвым» с длинными таймаутами. 2 ступени (10s + 8s)
        # возвращают флапающие ноды, не задерживая прогон на 40+ с на каждый мертвый узел.
        RECOVERY = (("http://cp.cloudflare.com/generate_204", 10, "cp-cf-r"),
                    ("https://www.gstatic.com/generate_204", 8, "gstatic-r"))
        dead = [r for r in rows if not r["delay"]]
        rec_max = int(os.environ.get("RECOVERY_MAX", "140"))
        if dead and os.environ.get("NO_RECOVERY") != "1":
            subset = dead[:rec_max]
            skipped = len(dead) - len(subset)
            print(f"  второй проход по {len(subset)} мёртвым (длинные таймауты)"
                  + (f", пропущено {skipped} сверх лимита RECOVERY_MAX" if skipped else ""),
                  flush=True)
            def redo(r):
                delay, stage = try_stages(r["port"], RECOVERY)
                if delay:
                    udp = socks5_udp_dns(r["port"])
                    print(f"  +{delay:>5} мс  [{stage}]  {r['link'][:42]}", flush=True)
                    return {**r, "delay": delay, "stage": stage, "udp": udp}
                return r
            t1 = time.time()
            with cf.ThreadPoolExecutor(max_workers=par) as ex:
                fixed = list(ex.map(redo, subset))
            by_port = {r["port"]: r for r in fixed}
            rows = [by_port.get(r["port"], r) for r in rows]
            print(f"  второй проход: {time.time()-t1:.0f} c, живых стало "
                  f"{sum(1 for r in rows if r['delay'])}", flush=True)

        def fast_exit_ip(port):
            """Быстрый запрос IP через api.ipify.org (1 запрос, тайм-аут 4с)."""
            try:
                out = subprocess.run(["curl", "-s", "--max-time", "4", "--connect-timeout", "3",
                                      "--socks5-hostname", f"127.0.0.1:{port}",
                                      "https://api.ipify.org?format=json"],
                                     capture_output=True, text=True, timeout=5)
                j = json.loads(out.stdout or "{}")
                return j.get("ip") or ""
            except Exception:
                return ""

        live0 = [r for r in rows if r["delay"]]
        skip_gemini = os.environ.get("SKIP_GEMINI_GATE") == "1"
        need_exit_ip = os.environ.get("REQUIRE_EXIT_IP") == "1"

        # Объединяем проверку гейта Gemini и exit_ip в один параллельный проход:
        # это экономит до 30-40 секунд и исключает дублирующие форки процессов на Pi 3.
        def verify_live(r):
            gres = check_gemini_gate(r["port"]) if not skip_gemini else "skip"
            ip = fast_exit_ip(r["port"]) if need_exit_ip else ""
            return {**r, "gemini": gres, "ip": ip}

        if live0:
            print(f"  проверка гейта Gemini/Antigravity для {len(live0)} живых нод…", flush=True)
            t_gate = time.time()
            with cf.ThreadPoolExecutor(max_workers=par) as ex:
                rows_live = list(ex.map(verify_live, live0))
            live_map = {r["name"]: r for r in rows_live}
            rows = [live_map.get(r["name"], r) for r in rows]
            gem_ok = sum(1 for r in rows_live if r.get("gemini") == "ok")
            print(f"  гейт Gemini/Antigravity пройден: {gem_ok} из {len(live0)} ({time.time()-t_gate:.1f} c)", flush=True)

        if need_exit_ip:
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
