#!/usr/bin/env python3
"""Тесты парсеров протоколов (VLESS, Hysteria2, SS, Trojan, VMess, Clash YAML)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import find_free_vpn as ffv


class TestParsers(unittest.TestCase):

    def test_parse_vless_standard(self):
        link = "vless://12345678-1234-1234-1234-123456789abc@192.168.1.1:443?security=tls&sni=example.com&type=ws&path=/ws#TestNode"
        p = ffv.parse_vless(link)
        self.assertIsNotNone(p)
        self.assertEqual(p["uuid"], "12345678-1234-1234-1234-123456789abc")
        self.assertEqual(p["host"], "192.168.1.1")
        self.assertEqual(p["port"], 443)
        self.assertEqual(p["sni"], "example.com")
        self.assertEqual(p["type"], "ws")

    def test_parse_vless_reality(self):
        link = "vless://12345678-1234-1234-1234-123456789abc@1.1.1.1:443?security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF=&sid=123456&sni=dl.google.com&flow=xtls-rprx-vision#RealityNode"
        p = ffv.parse_vless(link)
        self.assertIsNotNone(p)
        self.assertEqual(p["flow"], "xtls-rprx-vision")
        self.assertEqual(p["pbk"], "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF=")
        self.assertEqual(p["sid"], "123456")

    def test_parse_vless_invalid_sid(self):
        # Нечетная длина sid (невалидный hex) должна сбрасывать sid
        link = "vless://12345678-1234-1234-1234-123456789abc@1.1.1.1:443?security=reality&pbk=abc=&sid=123#BadSid"
        p = ffv.parse_vless(link)
        self.assertIsNotNone(p)
        self.assertEqual(p["sid"], "")

    def test_parse_hy2_standard(self):
        link = "hysteria2://my_secret_password@hy2.server.com:8443/?sni=my_sni.org#Hy2Node"
        p = ffv.parse_hy2(link)
        self.assertIsNotNone(p)
        self.assertEqual(p["auth"], "my_secret_password")
        self.assertEqual(p["host"], "hy2.server.com")
        self.assertEqual(p["port"], 8443)
        self.assertEqual(p["sni"], "my_sni.org")

    def test_parse_ss_sip002(self):
        # ss://base64(method:password)@server:port#remark
        link = "ss://YWVzLTEyOC1nY206cGFzczEyMw==@10.0.0.1:8388#SSNode"
        p = ffv.parse_ss(link)
        self.assertIsNotNone(p)
        self.assertEqual(p["host"], "10.0.0.1")
        self.assertEqual(p["port"], 8388)
        self.assertEqual(p["method"], "aes-128-gcm")
        self.assertEqual(p["password"], "pass123")

    def test_parse_trojan(self):
        link = "trojan://trojan_password@trojan.com:443?sni=trojan.com#TrojanNode"
        p = ffv.parse_trojan(link)
        self.assertIsNotNone(p)
        self.assertEqual(p["password"], "trojan_password")
        self.assertEqual(p["host"], "trojan.com")
        self.assertEqual(p["port"], 443)

    def test_clash_yaml_extraction(self):
        clash_yaml = """
proxies:
  - name: "Node VLESS"
    type: vless
    server: 203.0.113.10
    port: 443
    uuid: "11111111-2222-3333-4433-555555555555"
    network: ws
    tls: true
    servername: "cdn.test.com"
    ws-opts:
      path: "/vless-ws"
  - name: "Node Hy2"
    type: hysteria2
    server: 203.0.113.20
    port: 8443
    password: "secret_hy2_pass"
    sni: "hy2.test.com"
  - name: "Node SS"
    type: ss
    server: 203.0.113.30
    port: 8388
    cipher: aes-256-gcm
    password: "ss_password"
"""
        links = ffv.extract_links(clash_yaml)
        self.assertEqual(len(links), 3)
        self.assertTrue(any(l.startswith("vless://") for l in links))
        self.assertTrue(any(l.startswith("hysteria2://") for l in links))
        self.assertTrue(any(l.startswith("ss://") for l in links))

    def test_extract_links_corrupted(self):
        # Проверка, что битый текст или случайный бинарный мусор не роняют парсер
        garbage = "Some random text \x00\xff vless://invalid-without-at-sign hysteria2://::99999"
        links = ffv.extract_links(garbage)
        self.assertIsInstance(links, list)

    def test_trojan_with_slash_and_uuid_password(self):
        # Проверка: Trojan с UUID-паролем не должен превращаться в VLESS через normalize_link
        link = "trojan://11111111-2222-3333-4444-555555555555@trojan-server.com:443/?sni=trojan-server.com#MyTrojan"
        norm = ffv.normalize_link(link)
        self.assertTrue(norm.startswith("trojan://"), f"Trojan link was wrongly converted: {norm}")
        p = ffv.parse_trojan(norm)
        self.assertIsNotNone(p)
        self.assertEqual(p["host"], "trojan-server.com")
        self.assertEqual(p["port"], 443)
        self.assertEqual(p["password"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(p["sni"], "trojan-server.com")


if __name__ == "__main__":
    unittest.main()
