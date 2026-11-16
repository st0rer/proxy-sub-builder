#!/usr/bin/env python3
"""Тесты генерации подписок, разделения по протоколам и флагов стран (publish_sub)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import publish_sub as ps


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


if __name__ == "__main__":
    unittest.main()
