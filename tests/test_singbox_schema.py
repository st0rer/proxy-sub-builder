#!/usr/bin/env python3
"""Тесты валидации конфигов sing-box и безопасности flow."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import sb_verify as sbv
import mobile_push as mp
import find_free_vpn as ffv
import scan_any as sa


class TestSingboxSchema(unittest.TestCase):

    def test_vless_reality_singbox_outbound(self):
        link = "vless://11111111-2222-3333-4433-555555555555@1.2.3.4:443?security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF=&sid=123456&sni=dl.google.com&flow=xtls-rprx-vision#Node1"
        p = ffv.link_to_proxy(link, "N0")
        p = sa.sanitize_proxy(p)
        ob = sbv.to_singbox(p, "N0")

        self.assertIsNotNone(ob)
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["server"], "1.2.3.4")
        self.assertEqual(ob["server_port"], 443)
        self.assertEqual(ob["flow"], "xtls-rprx-vision")

        # Проверяем структуру Reality
        tls = ob.get("tls", {})
        self.assertTrue(tls.get("reality", {}).get("enabled"))
        self.assertEqual(tls["reality"]["public_key"], "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF=")
        self.assertEqual(tls["reality"]["short_id"], "123456")
        # Проверяем TLS ClientHello fragmentation для обхода DPI/ТСПУ
        self.assertTrue(tls.get("fragment"))
        self.assertEqual(tls.get("fragment_fallback_delay"), "500ms")

    def test_unsupported_flow_excluded_in_sb_verify(self):
        # Если flow битый (например xtls-rprx-vision-udp443), build() должен его выбросить,
        # чтобы sing-box не упал на старте
        bad_link = "vless://11111111-2222-3333-4433-555555555555@1.2.3.4:443?security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF=&sni=dl.google.com&flow=xtls-rprx-vision-udp443#BadFlow"
        good_link = "vless://22222222-3333-4433-5555-666666666666@1.2.3.5:443?security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF=&sni=dl.google.com&flow=xtls-rprx-vision#GoodFlow"

        cfg, meta = sbv.build([bad_link, good_link])
        outbounds = cfg.get("outbounds", [])

        # В outbounds должна попасть только good_link + direct (всего 2)
        outbound_tags = [o["tag"] for o in outbounds]
        self.assertIn("direct", outbound_tags)
        self.assertEqual(len(meta), 1)
        self.assertEqual(list(meta.values())[0]["link"], good_link)

    def test_unsupported_flow_excluded_in_mobile_push(self):
        # Проверяем, что в mobile_push.build_sb_config также отсекается битый flow
        bad_link = "vless://11111111-2222-3333-4433-555555555555@1.2.3.4:443?security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF=&sni=dl.google.com&flow=xtls-rprx-vision-udp443#BadFlow"
        good_link = "vless://22222222-3333-4433-5555-666666666666@1.2.3.5:443?security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF=&sni=dl.google.com&flow=xtls-rprx-vision#GoodFlow"

        _yaml, _nodes, pairs = mp.build_config([bad_link, good_link])
        sb_cfg, used = mp.build_sb_config(pairs)

        # Битый flow должен быть отсеян
        self.assertEqual(used, 1)


if __name__ == "__main__":
    unittest.main()
