#!/usr/bin/env python3
"""Тесты генерации подписок, разделения по протоколам и флагов стран (publish_sub)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import publish_sub as ps
import pi_sb_verify as psbv
import pi_verify as piv


class TestPublish(unittest.TestCase):

    def test_cc_to_flag(self):
        # Проверяем корректную генерацию флагов Unicode из кодов стран
        self.assertEqual(ps.cc_to_flag("DE"), "🇩🇪")
        self.assertEqual(ps.cc_to_flag("NL"), "🇳🇱")
        self.assertEqual(ps.cc_to_flag("US"), "🇺🇸")
        self.assertEqual(ps.cc_to_flag("RU"), "🇷🇺")
        self.assertEqual(ps.cc_to_flag("FI"), "🇫🇮")
        self.assertEqual(ps.cc_to_flag(""), "")
        self.assertEqual(ps.cc_to_flag("123"), "")

    def test_protocol_filtering(self):
        links = [
            "vless://11111111-2222-3333-4433-555555555555@1.2.3.4:443?security=reality&pbk=abc=&sni=dl.google.com#Reality1",
            "vless://22222222-3333-4433-5555-666666666666@1.2.3.5:443?security=tls&sni=dl.google.com#VlessWs",
            "hysteria2://pass@hy2.com:8443/?sni=hy2.com#Hy2Node",
            "ss://YWVzLTEyOC1nY206cGFzczEyMw==@10.0.0.1:8388#SSNode",
        ]
        vless = [l for l in links if l.startswith("vless://")]
        reality = [l for l in vless if "pbk=" in l or "security=reality" in l]
        hy2 = [l for l in links if ps.is_hy2(l)]
        ss = [l for l in links if l.startswith("ss://")]

        self.assertEqual(len(vless), 2)
        self.assertEqual(len(reality), 1)
        self.assertEqual(len(hy2), 1)
        self.assertEqual(len(ss), 1)

    def test_tuic_and_hy2_priority(self):
        links = [
            "vless://11111111-2222-3333-4433-555555555555@1.2.3.4:443?security=reality#Vless",
            "tuic://uuid:pwd@tuic.com:8443?sni=tuic.com#TuicNode",
            "hysteria2://pass@hy2.com:8443/?sni=hy2.com#Hy2Node",
            "ss://YWVzLTEyOC1nY206cGFzczEyMw==@10.0.0.1:8388#SSNode",
        ]
        speeds = {"tuic://uuid:pwd@tuic.com:8443?sni=tuic.com#TuicNode": 5.0,
                  "hysteria2://pass@hy2.com:8443/?sni=hy2.com#Hy2Node": 10.0}

        def proto_priority(l):
            if ps.is_hy2(l) or l.startswith("tuic://"):
                return 2
            elif l.startswith("vless://"):
                return 1
            return 0

        sorted_links = sorted(links, key=lambda l: (proto_priority(l), speeds.get(l, 0)), reverse=True)
        # Hy2 (10 MB/s) should be first, Tuic (5 MB/s) second, then Vless, then SS
        self.assertTrue(sorted_links[0].startswith("hysteria2://"))
        self.assertTrue(sorted_links[1].startswith("tuic://"))
        self.assertTrue(sorted_links[2].startswith("vless://"))
        self.assertTrue(sorted_links[3].startswith("ss://"))

    def test_gemini_gate_probe_logic(self):
        # Проверяем все ветви логики check_gemini_gate в pi_sb_verify и pi_verify

        # 1. loadCodeAssist 401 + gemini.google.com 200 -> ok
        def mock_run_ok(cmd, *args, **kwargs):
            m = MagicMock()
            if "loadCodeAssist" in cmd[-1]:
                m.stdout = "401"
            elif "gemini.google.com" in cmd[-1]:
                m.stdout = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            return m

        with patch("subprocess.run", side_effect=mock_run_ok):
            self.assertEqual(psbv.check_gemini_gate(21000), "ok")
            self.assertEqual(piv.check_gemini_gate(21000), "ok")

        # 2. loadCodeAssist 403 (геоблок Google Cloud Code) -> geoblock
        def mock_run_geoblock_lca(cmd, *args, **kwargs):
            m = MagicMock()
            if "loadCodeAssist" in cmd[-1]:
                m.stdout = "403"
            return m

        with patch("subprocess.run", side_effect=mock_run_geoblock_lca):
            self.assertEqual(psbv.check_gemini_gate(21000), "geoblock")
            self.assertEqual(piv.check_gemini_gate(21000), "geoblock")

        # 3. loadCodeAssist 401, но gemini.google.com отдаёт 302 с sorry/index (капча / анти-бот) -> sorry
        def mock_run_sorry(cmd, *args, **kwargs):
            m = MagicMock()
            if "loadCodeAssist" in cmd[-1]:
                m.stdout = "401"
            elif "gemini.google.com" in cmd[-1]:
                m.stdout = "HTTP/1.1 302 Found\r\nLocation: https://www.google.com/sorry/index?continue=https://gemini.google.com/app\r\n"
            return m

        with patch("subprocess.run", side_effect=mock_run_sorry):
            self.assertEqual(psbv.check_gemini_gate(21000), "sorry")
            self.assertEqual(piv.check_gemini_gate(21000), "sorry")

        # 4. loadCodeAssist 401 + gemini 302 на Google Accounts (редирект на логин) -> ok
        def mock_run_login_redirect(cmd, *args, **kwargs):
            m = MagicMock()
            if "loadCodeAssist" in cmd[-1]:
                m.stdout = "401"
            elif "gemini.google.com" in cmd[-1]:
                m.stdout = "HTTP/1.1 302 Found\r\nLocation: https://accounts.google.com/ServiceLogin?service=bard\r\n"
            return m

        with patch("subprocess.run", side_effect=mock_run_login_redirect):
            self.assertEqual(psbv.check_gemini_gate(21000), "ok")
            self.assertEqual(piv.check_gemini_gate(21000), "ok")

        # 5. loadCodeAssist 401, а gemini.google.com дал таймаут радиоканала -> ok (не отсекаем ложно!)
        def mock_run_gemini_timeout(cmd, *args, **kwargs):
            m = MagicMock()
            if "loadCodeAssist" in cmd[-1]:
                m.stdout = "401"
                return m
            raise subprocess.TimeoutExpired(cmd, 5)

        with patch("subprocess.run", side_effect=mock_run_gemini_timeout):
            self.assertEqual(psbv.check_gemini_gate(21000), "ok")
            self.assertEqual(piv.check_gemini_gate(21000), "ok")

        # 6. loadCodeAssist таймаут, но gemini.google.com 200 -> ok (резервный гейт сработал!)
        def mock_run_lca_timeout(cmd, *args, **kwargs):
            m = MagicMock()
            if "gemini.google.com" in cmd[-1]:
                m.stdout = "HTTP/1.1 200 OK\r\n"
                return m
            raise subprocess.TimeoutExpired(cmd, 5)

        with patch("subprocess.run", side_effect=mock_run_lca_timeout):
            self.assertEqual(psbv.check_gemini_gate(21000), "ok")
            self.assertEqual(piv.check_gemini_gate(21000), "ok")

        # 7. таймаут или обрыв сети на обоих ресурсах -> err
        def mock_run_err(cmd, *args, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 5)

        with patch("subprocess.run", side_effect=mock_run_err):
            self.assertEqual(psbv.check_gemini_gate(21000), "err")
            self.assertEqual(piv.check_gemini_gate(21000), "err")

    def test_gemini_filtering_in_publish_sub(self):
        # Тестируем отбор нод по SUB_REQUIRE_GEMINI=1
        tmp = tempfile.mkdtemp()
        sub_from = os.path.join(tmp, "mobile_results.json")
        out_dir = os.path.join(tmp, "out")

        nodes = [
            {"name": "N0", "port": 21000, "link": "vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443?security=reality&pbk=abc#GeminiOK1",
             "delay": 150, "speed": 1.5, "speed_measured": True, "udp": True, "gemini": "ok"},
            {"name": "N1", "port": 21001, "link": "vless://22222222-2222-2222-2222-222222222222@2.2.2.2:443?security=reality&pbk=abc#GeminiOK2",
             "delay": 180, "speed": 2.0, "speed_measured": True, "udp": True, "gemini": "ok"},
            {"name": "N2", "port": 21002, "link": "vless://33333333-3333-3333-3333-333333333333@3.3.3.3:443?security=reality&pbk=abc#GeminiGeoblock",
             "delay": 120, "speed": 3.0, "speed_measured": True, "udp": True, "gemini": "geoblock"},
            {"name": "N3", "port": 21003, "link": "vless://44444444-4444-4444-4444-444444444444@4.4.4.4:443?security=reality&pbk=abc#GeminiSorry",
             "delay": 130, "speed": 2.5, "speed_measured": True, "udp": True, "gemini": "sorry"},
            {"name": "N4", "port": 21004, "link": "vless://55555555-5555-5555-5555-555555555555@5.5.5.5:443?security=reality&pbk=abc#GeminiErr",
             "delay": 140, "speed": 1.8, "speed_measured": True, "udp": True, "gemini": "err"},
        ]
        with open(sub_from, "w", encoding="utf-8") as f:
            json.dump(nodes, f)

        # 1. Запуск с SUB_REQUIRE_GEMINI=1
        env = {
            "SUB_FROM": sub_from,
            "SUB_OUT": out_dir,
            "SUB_REQUIRE_GEMINI": "1",
            "SUB_MIN_NODES": "2",
            "SUB_ALLOW_SHRINK": "1",
            "SUB_NODES": "nodes-yota.txt",
            "SUB_V2RAY": "yota.txt",
            "SKIP_XRAY_GATE": "1",
            "NO_MERGE": "1",
        }
        with patch.dict(os.environ, env):
            ret = ps.main()
            self.assertEqual(ret, 0)

        with open(os.path.join(out_dir, "nodes-yota.txt"), encoding="utf-8") as f:
            out_nodes = f.read().splitlines()
        # Должны остаться ТОЛЬКО ноды с gemini == 'ok' (N0 и N1)
        self.assertEqual(len(out_nodes), 2)
        self.assertTrue(any("GeminiOK1" in l for l in out_nodes))
        self.assertTrue(any("GeminiOK2" in l for l in out_nodes))
        self.assertFalse(any("GeminiGeoblock" in l for l in out_nodes))
        self.assertFalse(any("GeminiSorry" in l for l in out_nodes))
        self.assertFalse(any("GeminiErr" in l for l in out_nodes))

        # Проверяем index.json
        with open(os.path.join(out_dir, "index.json"), encoding="utf-8") as f:
            index_data = json.load(f)
        self.assertTrue(index_data.get("gemini_only"))
        self.assertEqual(index_data.get("count"), 2)

        # 2. Запуск без SUB_REQUIRE_GEMINI (должны пройти все 5 живых нод)
        env_all = dict(env)
        env_all["SUB_REQUIRE_GEMINI"] = "0"
        env_all["SUB_MIN_NODES"] = "3"
        with patch.dict(os.environ, env_all):
            ret = ps.main()
            self.assertEqual(ret, 0)

        with open(os.path.join(out_dir, "nodes-yota.txt"), encoding="utf-8") as f:
            out_nodes_all = f.read().splitlines()
        self.assertEqual(len(out_nodes_all), 5)

    def test_gemini_history_replenishment(self):
        # Проверяем добор из mobile_history при сетевом голодании (< min_nodes)
        import time
        tmp = tempfile.mkdtemp()
        sub_from = os.path.join(tmp, "mobile_results.json")
        out_dir = os.path.join(tmp, "out")
        hist_p = os.path.join(tmp, "mobile_history.json")

        # В текущем прогоне прошла всего 1 нода
        nodes = [
            {"name": "N0", "port": 21000, "link": "vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443?security=reality&pbk=abc#CurrNode",
             "delay": 150, "speed": 1.5, "speed_measured": True, "udp": True, "gemini": "ok"},
        ]
        with open(sub_from, "w", encoding="utf-8") as f:
            json.dump(nodes, f)

        # В истории лежат ещё 2 свежие ноды с gemini == 'ok' (возраст 2 часа)
        now_ts = time.time()
        mhist = {
            "vless://22222222-2222-2222-2222-222222222222@2.2.2.2:443?security=reality&pbk=abc#HistNode1": {
                "ts": now_ts - 7200, "speed": 2.0, "delay": 180, "gemini": "ok"
            },
            "vless://33333333-3333-3333-3333-333333333333@3.3.3.3:443?security=reality&pbk=abc#HistNode2": {
                "ts": now_ts - 3600, "speed": 2.2, "delay": 160, "gemini": "ok"
            },
            "vless://44444444-4444-4444-4444-444444444444@4.4.4.4:443?security=reality&pbk=abc#HistBad": {
                "ts": now_ts - 1000, "speed": 0.5, "delay": 200, "gemini": "geoblock"
            },
        }
        with open(hist_p, "w", encoding="utf-8") as f:
            json.dump(mhist, f)

        env = {
            "SUB_FROM": sub_from,
            "SUB_OUT": out_dir,
            "SUB_REQUIRE_GEMINI": "1",
            "SUB_MIN_NODES": "3",
            "SUB_ALLOW_SHRINK": "1",
            "SUB_NODES": "nodes-yota.txt",
            "SUB_V2RAY": "yota.txt",
            "SKIP_XRAY_GATE": "1",
            "NO_MERGE": "1",
            "PROXY_SUB_CACHE": tmp,
        }
        with patch.dict(os.environ, env), patch("publish_sub.CACHE", tmp):
            ret = ps.main()
            self.assertEqual(ret, 0)

        with open(os.path.join(out_dir, "nodes-yota.txt"), encoding="utf-8") as f:
            out_nodes = f.read().splitlines()
        # Должны быть 3 ноды: CurrNode + HistNode1 + HistNode2 (HistBad отсеяна!)
        self.assertEqual(len(out_nodes), 3)
        self.assertTrue(any("CurrNode" in l for l in out_nodes))
        self.assertTrue(any("HistNode1" in l for l in out_nodes))
        self.assertTrue(any("HistNode2" in l for l in out_nodes))
        self.assertFalse(any("HistBad" in l for l in out_nodes))

    def test_mobile_push_candidate_expansion_and_ru_filter(self):
        # Проверяем расширение пула кандидатов из all_links.json и исключение RU-выходов
        import mobile_push as mp
        tmp = tempfile.mkdtemp()

        # 1. verified.json с 1 немецкой и 1 российской нодой
        verif = [
            {"link": "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=reality&pbk=abc#DE_Node",
             "cc": "DE", "delay": 80, "speed_MBps": 2.5},
            {"link": "vless://22222222-2222-2222-2222-222222222222@5.6.7.8:443?security=reality&pbk=abc#RU_Node",
             "cc": "RU", "delay": 30, "speed_MBps": 5.0},
        ]
        with open(os.path.join(tmp, "verified.json"), "w", encoding="utf-8") as f:
            json.dump(verif, f)

        # 2. alive.json пуст по TCP (только 1 hy2)
        alive = {
            "hy2://pass@9.9.9.9:8443?sni=test.com#Hy2": 150
        }
        with open(os.path.join(tmp, "alive.json"), "w", encoding="utf-8") as f:
            json.dump(alive, f)

        # 3. all_links.json содержит кандидатов Reality VLESS и SS
        pool = [
            "vless://33333333-3333-3333-3333-333333333333@10.0.0.1:443?security=reality&pbk=abc#PoolVless1",
            "vless://44444444-4444-4444-4444-444444444444@10.0.0.2:443?security=reality&pbk=abc#PoolVless2",
            "ss://YWVzLTEyOC1nY206cGFzczEyMw==@10.0.0.3:8388#PoolSS1",
            "vless://22222222-2222-2222-2222-222222222222@5.6.7.8:443?security=reality&pbk=abc#RU_Node_In_Pool",
        ]
        with open(os.path.join(tmp, "all_links.json"), "w", encoding="utf-8") as f:
            json.dump(pool, f)

        env = {
            "PROXY_SUB_CACHE": tmp,
            "PI_N_VLESS": "10",
            "PI_N_SS": "5",
            "PI_N_HY2": "5",
            "FAST_TCP_PRECHECK": "0",  # отключаем реальный сокет в тесте
        }
        with patch.dict(os.environ, env), patch("mobile_push.CACHE", tmp), patch("mobile_push.FAST_TCP_PRECHECK", False):
            cands = mp.pick_candidates()

        # Российская нода не должна попасть в кандидаты
        self.assertFalse(any("RU_Node" in l for l in cands))
        # Немецкая нода из verified.json должна попасть
        self.assertTrue(any("DE_Node" in l for l in cands))
        # Кандидаты из all_links.json должны добрать квоту VLESS и SS
        self.assertTrue(any("PoolVless1" in l for l in cands))
        self.assertTrue(any("PoolVless2" in l for l in cands))
        self.assertTrue(any("PoolSS1" in l for l in cands))

    def test_filter_live_tcp(self):
        # Проверяем работу filter_live_tcp: QUIC пропускается без TCP-проверки,
        # а TCP-ссылки фильтруются по результату соединения
        import mobile_push as mp
        links = [
            "hy2://pass@1.1.1.1:8443#Hy2Node",
            "vless://uuid@1.1.1.2:443?security=reality#LiveVless",
            "ss://pass@1.1.1.3:8388#DeadSS",
        ]

        def mock_create_connection(addr, timeout=1.2):
            host, port = addr
            if host == "1.1.1.2":
                return MagicMock()
            raise OSError("Connection refused")

        with patch("socket.create_connection", side_effect=mock_create_connection), \
             patch("mobile_push.FAST_TCP_PRECHECK", True):
            filtered = mp.filter_live_tcp(links)

        self.assertIn("hy2://pass@1.1.1.1:8443#Hy2Node", filtered)
        self.assertIn("vless://uuid@1.1.1.2:443?security=reality#LiveVless", filtered)
        self.assertNotIn("ss://pass@1.1.1.3:8388#DeadSS", filtered)


if __name__ == "__main__":
    unittest.main()
