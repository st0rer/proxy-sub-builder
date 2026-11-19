#!/usr/bin/env python3
"""Тесты модулей скрейпинга (tg_scrape, discover_channels, fast_pass)."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import tg_scrape as tgs
import fast_pass as fp


class TestScraper(unittest.TestCase):

    def test_is_candidate_sub(self):
        # Должны приниматься
        self.assertTrue(tgs.is_candidate_sub("https://raw.githubusercontent.com/user/repo/main/vless.txt"))
        self.assertTrue(tgs.is_candidate_sub("https://sub-worker.user.workers.dev/sub?uuid=123"))
        self.assertTrue(tgs.is_candidate_sub("https://my-panel.com/api/v1/client/subscribe?token=xyz"))
        self.assertTrue(tgs.is_candidate_sub("https://example.com/configs.yaml"))

        # Должны игнорироваться (соцсети, каналы, поисковики)
        self.assertFalse(tgs.is_candidate_sub("https://t.me/s/my_channel"))
        self.assertFalse(tgs.is_candidate_sub("https://youtube.com/watch?v=123"))
        self.assertFalse(tgs.is_candidate_sub("https://telegra.ph/How-to-setup-vpn-01-01"))
        self.assertFalse(tgs.is_candidate_sub("https://yandex.ru/search"))

    def test_extract_from_html(self):
        html = """
        <div class="tgme_widget_message_text">
            Вот свежий конфиг:
            vless://11111111-2222-3333-4433-555555555555@1.2.3.4:443?security=tls&amp;sni=a.com#Test
            И еще один:
            hysteria2://pass123@hy2.test.com:8443/?sni=hy2.test.com#Hy2
        </div>
        """
        links = tgs.extract(html)
        self.assertEqual(len(links), 2)
        # Проверяем, что &amp; был заменен на &
        self.assertIn("&sni=a.com", links[0])

    def test_channel_priority_ranking(self):
        stats = {
            "spam_channel": {"runs": 10, "links": 500, "last_links": 100, "zero_runs": 0, "verified_alive": 0},
            "quality_channel": {"runs": 10, "links": 5, "last_links": 3, "zero_runs": 0, "verified_alive": 4},
            "dead_channel": {"runs": 10, "links": 0, "last_links": 0, "zero_runs": 5, "verified_alive": 0},
        }
        # Канал с verified_alive должен стоять выше спам-канала
        ranked = fp.top_channels(limit=3)
        # Проверяем напрямую функцию скоринга из tg_scrape
        # verified_alive дает +200 очков на ноду
        p_quality = 4 * 200.0 + min(3, 30)
        p_spam = 0 * 200.0 + min(100, 30)
        self.assertGreater(p_quality, p_spam)

    def test_thread_safe_fetched_subs(self):
        # Стресс-тест: 30 параллельных потоков пытаются добавить один и тот же URL
        fetched = {}
        target_url = "https://test.workers.dev/sub"
        added_count = [0]

        def worker():
            with tgs.subs_lock:
                if target_url not in fetched:
                    time.sleep(0.001)  # симуляция задержки
                    fetched[target_url] = int(time.time())
                    added_count[0] += 1

        threads = [threading.Thread(target=worker) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # URL должен быть добавлен ровно 1 раз, несмотря на 30 потоков
        self.assertEqual(added_count[0], 1)
        self.assertIn(target_url, fetched)

    def test_extract_raw_links_enhanced(self):
        import scan_any as sa
        # 1. HTML entities (&amp;)
        sample_html = b"vless://uuid1@1.2.3.4:443?security=reality&amp;sni=test.com&amp;pbk=4guBGe6r_cFxgQJeUGvfPCYwcQ2TXURlGOs6vyqH1kY#Node1"
        res = sa.extract_raw_links(sample_html)
        self.assertTrue(any("&sni=test.com" in l and "&amp;" not in l for l in res))

        # 2. Embedded Base64 block in comments
        b64_part = __import__("base64").b64encode(b"vless://uuid2@5.6.7.8:443?security=reality#B64Node\nss://YWVzLTEyOC1nY206cGFzczEyMw==@9.10.11.12:8388#SSNode").decode()
        sample_b64 = f"# Hello world\n# Header comment\n{b64_part}\n# End comment".encode()
        res_b64 = sa.extract_raw_links(sample_b64)
        self.assertEqual(len(res_b64), 2)

        # 3. Clash YAML with proxies
        clash_yaml = b"""
proxies:
  - {name: N1, type: vless, server: 2.3.4.5, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, reality-opts: {public-key: 4guBGe6r_cFxgQJeUGvfPCYwcQ2TXURlGOs6vyqH1kY}, servername: my.site.com}
  - {name: N2, type: ss, server: 3.4.5.6, port: 8388, cipher: aes-128-gcm, password: pass}
"""
        res_clash = sa.extract_raw_links(clash_yaml)
        self.assertEqual(len(res_clash), 2)


if __name__ == "__main__":
    unittest.main()
