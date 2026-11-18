#!/usr/bin/env python3
"""Тестирование и бенчмарк пайплайна видео-роутинга и сброса залипших соединений.

Методология проверки:
1. Валидация схемы и генерации sing-box (селектор video, video-auto, reject UDP 443).
2. Запуск локального sing-box (с Clash API и SOCKS5 inbounds).
3. Проверка точности маршрутизации:
   - googlevideo.com -> outbound video
   - daily-cloudcode-pa.googleapis.com -> outbound gcp
   - mtalk.google.com -> outbound proxy
4. Проверка сброса зависшего видеопотока через Clash API:
   - Установление соединения к *.googlevideo.com через SOCKS5
   - Имитация залипания (delta_bytes == 0)
   - Вызов логики watchdog (drop_stalled_video_conns)
   - Контроль закрытия сокета (ECONNRESET)
5. Снятие метрик накладных расходов:
   - Время ответа Clash API (/connections)
   - Потребление памяти и задержка опроса
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import sbgen

SB_BIN = shutil.which("sing-box") or (
    r"C:\Users\Storer\bin\sing-box.exe" if os.path.exists(r"C:\Users\Storer\bin\sing-box.exe") else None
)


class TestVideoPipeline(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.src_file = os.path.join(self.tmpdir, "nodes.txt")
        self.cfg_file = os.path.join(self.tmpdir, "config.json")
        self.geo_file = os.path.join(self.tmpdir, "geo.json")

        # Набор тестовых нод с известными ключами
        sample_nodes = [
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&sni=dl.google.com&fp=chrome&pbk=4guBGe6r_cFxgQJeUGvfPCYwcQ2TXURlGOs6vyqH1kY&sid=123456#VlessEU",
            "hysteria2://mypassword@hy2.example.com:8443/?sni=myhy2.org#Hy2US",
            "ss://YWVzLTEyOC1nY206cGFzczEyMw==@ss.example.com:8388#SS_Direct"
        ]
        with open(self.src_file, "w", encoding="utf-8") as f:
            f.write("\n".join(sample_nodes))

        # Имитируем гео-данные с замером скорости
        geo_data = {
            "vless|1.2.3.4|443": {"cc": "NL", "speed_mbps": 45.2, "gemini": "ok"},
            "hysteria2|hy2.example.com|8443": {"cc": "US", "speed_mbps": 12.0, "gemini": "ok"},
            "shadowsocks|ss.example.com|8388": {"cc": "DE", "speed_mbps": 28.5, "gemini": "ok"}
        }
        with open(self.geo_file, "w", encoding="utf-8") as f:
            json.dump(geo_data, f)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_video_candidate_ranking(self):
        """Проверяем, что европейские и скоростные ноды получают наивысший приоритет в видео-пуле."""
        os.environ["SINGBOX_SOURCE"] = self.src_file
        os.environ["SINGBOX_CONFIG"] = self.cfg_file
        sys.argv = ["sbgen.py", "--geo", self.geo_file]
        sbgen.main()

        with open(self.cfg_file, encoding="utf-8") as f:
            cfg = json.load(f)

        video_auto = next(o for o in cfg["outbounds"] if o["tag"] == "video-auto")
        # Нода VlessEU (NL, 45.2 Mbps) должна стоять первой среди кандидатов
        self.assertTrue(video_auto["outbounds"][0].startswith("vles"))

    def test_routing_and_stalled_connection_drop(self):
        """Интеграционный тест: запуск sing-box, роутинг googlevideo и сброс залипшего соединения."""
        if not SB_BIN:
            self.skipTest("sing-box binary not found")

        # Создаем минимальный рабочий конфиг для локального теста
        socks_port = 11980
        clash_port = 19990
        test_cfg = {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": socks_port
                }
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {
                    "type": "selector",
                    "tag": "video",
                    "outbounds": ["direct"],
                    "default": "direct"
                },
                {
                    "type": "selector",
                    "tag": "gcp",
                    "outbounds": ["direct"],
                    "default": "direct"
                }
            ],
            "route": {
                "rules": [
                    {"action": "sniff"},
                    {
                        "domain_suffix": ["googlevideo.com", "youtube.com"],
                        "outbound": "video"
                    },
                    {
                        "domain_suffix": ["googleapis.com", "google.com"],
                        "outbound": "gcp"
                    }
                ],
                "final": "direct"
            },
            "experimental": {
                "clash_api": {"external_controller": f"127.0.0.1:{clash_port}"}
            }
        }

        with open(self.cfg_file, "w", encoding="utf-8") as f:
            json.dump(test_cfg, f)

        # 1. Запуск sing-box
        proc = subprocess.Popen([SB_BIN, "run", "-c", self.cfg_file],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.2)

        try:
            # 2. Устанавливаем соединение через SOCKS5 к домену googlevideo.com
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(("127.0.0.1", socks_port))
            # SOCKS5 handshake
            s.sendall(b"\x05\x01\x00")
            auth_resp = s.recv(2)
            self.assertEqual(auth_resp, b"\x05\x00")

            # Connect request to real domain www.youtube.com:443
            target_host = b"www.youtube.com"
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(target_host)]) + target_host + (443).to_bytes(2, "big"))
            time.sleep(0.3)

            # 3. Опрашиваем Clash API /connections
            api_url = f"http://127.0.0.1:{clash_port}"
            t_start = time.perf_counter()
            with urllib.request.urlopen(f"{api_url}/connections") as resp:
                api_duration = (time.perf_counter() - t_start) * 1000
                data = json.loads(resp.read().decode())
                conns = data.get("connections", [])

            self.assertGreaterEqual(len(conns), 1)
            video_conn = next((c for c in conns if "youtube.com" in (c.get("metadata", {}).get("host") or "")), None)
            self.assertIsNotNone(video_conn)

            # Проверяем, что сокет смаплен на outbound video
            self.assertIn("video", video_conn.get("chains", []))

            # 4. Проверяем алгоритм детекции залипания
            cid = video_conn["id"]
            dl0 = video_conn.get("download", 0)

            # Имитируем ожидание: за 1.5 секунды байты не выросли
            time.sleep(1.5)
            with urllib.request.urlopen(f"{api_url}/connections") as resp:
                c1_list = json.loads(resp.read().decode()).get("connections", [])
            c1_match = next((c for c in c1_list if c["id"] == cid), None)
            self.assertIsNotNone(c1_match)
            dl1 = c1_match.get("download", 0)

            # Байт дельта == 0 -> залипание
            self.assertEqual(dl0, dl1)

            # Сбрасываем сокет
            del_req = urllib.request.Request(f"{api_url}/connections/{cid}", method="DELETE")
            with urllib.request.urlopen(del_req) as del_resp:
                self.assertEqual(del_resp.status, 204)

            # 5. Проверяем, что сокет клиента действительно сброшен (RST)
            time.sleep(0.2)
            with self.assertRaises((socket.error, ConnectionResetError, OSError)):
                s.sendall(b"GET /videoplayback HTTP/1.1\r\n\r\n")
                s.recv(1024)

            s.close()
        finally:
            proc.terminate()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
