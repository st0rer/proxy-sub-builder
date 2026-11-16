#!/usr/bin/env python3
"""Тесты дедупликации и извлечения host:port (_host_of, dedupe_connections)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import scan_any as sa


class TestDedup(unittest.TestCase):

    def test_host_of_vless_ipv4(self):
        link = "vless://12345678-1234-1234-1234-123456789abc@192.168.1.1:443?type=tcp"
        hp = sa._host_of(link)
        self.assertEqual(hp, ("192.168.1.1", 443))

    def test_host_of_vless_ipv6(self):
        link = "vless://12345678-1234-1234-1234-123456789abc@[2001:db8::1]:8443?type=tcp"
        hp = sa._host_of(link)
        self.assertEqual(hp, ("2001:db8::1", 8443))

    def test_host_of_ss_legacy(self):
        # ss://base64(method:password@host:port)
        # aes-128-gcm:pass@10.0.0.1:8388
        link = "ss://YWVzLTEyOC1nY206cGFzc0AxMC4wLjAuMTo4Mzg4#Node"
        hp = sa._host_of(link)
        self.assertEqual(hp, ("10.0.0.1", 8388))

    def test_host_of_hy2_with_special_characters_in_password(self):
        # Пароль может содержать '@' или ':'
        link = "hysteria2://user@pass:secret@my.host.net:443/?sni=my.host.net"
        hp = sa._host_of(link)
        self.assertEqual(hp, ("my.host.net", 443))

    def test_dedupe_connections_identical(self):
        # Две абсолютно одинаковые ноды, но с разными именами (#Remark)
        l1 = "vless://11111111-2222-3333-4433-555555555555@1.2.3.4:443?security=tls&sni=a.com&type=ws&path=/ws#RemarkA"
        l2 = "vless://11111111-2222-3333-4433-555555555555@1.2.3.4:443?security=tls&sni=a.com&type=ws&path=/ws#RemarkB"
        deduped = sa.dedupe_connections([l1, l2])
        self.assertEqual(len(deduped), 1)

    def test_dedupe_connections_cdn_preservation(self):
        # Один и тот же IP:порт (например, Cloudflare), но разные SNI и пути
        l1 = "vless://11111111-2222-3333-4433-555555555555@104.16.1.1:443?security=tls&sni=site1.com&type=ws&path=/vless#Node1"
        l2 = "vless://99999999-8888-7777-6666-555555555555@104.16.1.1:443?security=tls&sni=site2.com&type=ws&path=/chat#Node2"
        deduped = sa.dedupe_connections([l1, l2])
        # Обе ноды должны сохраниться, так как это разные сервисы за одним CDN IP!
        self.assertEqual(len(deduped), 2)


if __name__ == "__main__":
    unittest.main()
