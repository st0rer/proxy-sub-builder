#!/usr/bin/env python3
import json
import os
import tempfile
import unittest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import sbgen

class TestSbGen(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.src_file = os.path.join(self.tmpdir, "nodes.txt")
        self.out_file = os.path.join(self.tmpdir, "config.json")
        sample_nodes = [
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=dl.google.com&fp=chrome&pbk=123456&sid=abcd#TestVless",
            "hysteria2://mypassword@hy2.example.com:8443/?sni=myhy2.org#TestHy2",
            "ss://YWVzLTEyOC1nY206cGFzczEyMw==@ss.example.com:8388#TestSS"
        ]
        with open(self.src_file, "w", encoding="utf-8") as f:
            f.write("\n".join(sample_nodes))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_sbgen_tun_mode(self):
        os.environ["SINGBOX_SOURCE"] = self.src_file
        os.environ["SINGBOX_CONFIG"] = self.out_file
        os.environ["SINGBOX_MODE"] = "tun"
        os.environ["SINGBOX_TUN_DEV"] = "sb0"
        os.environ["SINGBOX_TUN_MTU"] = "1200"
        sbgen.main()

        self.assertTrue(os.path.exists(self.out_file))
        with open(self.out_file, encoding="utf-8") as f:
            cfg = json.load(f)
        inbounds = cfg["inbounds"]
        tun_in = next((i for i in inbounds if i["type"] == "tun"), None)
        self.assertIsNotNone(tun_in)
        self.assertEqual(tun_in["interface_name"], "sb0")
        self.assertEqual(tun_in["mtu"], 1200)

        # Check route rules have action sniff
        sniff_rule = next((r for r in cfg["route"]["rules"] if r.get("action") == "sniff"), None)
        self.assertIsNotNone(sniff_rule)
        self.assertIn("tun-in", sniff_rule["inbound"])

        # Check outbounds contain parsed nodes
        outbounds = cfg["outbounds"]
        tags = [o["tag"] for o in outbounds]
        self.assertIn("auto", tags)
        self.assertIn("gcp", tags)
        self.assertIn("proxy", tags)

    def test_sbgen_tproxy_mode(self):
        os.environ["SINGBOX_SOURCE"] = self.src_file
        os.environ["SINGBOX_CONFIG"] = self.out_file
        os.environ["SINGBOX_MODE"] = "tproxy"
        os.environ["SINGBOX_TPROXY_PORT"] = "12345"
        sbgen.main()

        with open(self.out_file, encoding="utf-8") as f:
            cfg = json.load(f)
        inbounds = cfg["inbounds"]
        tproxy_in = next((i for i in inbounds if i["type"] == "tproxy"), None)
        self.assertIsNotNone(tproxy_in)
        self.assertEqual(tproxy_in["listen_port"], 12345)

        sniff_rule = next((r for r in cfg["route"]["rules"] if r.get("action") == "sniff"), None)
        self.assertIsNotNone(sniff_rule)
        self.assertIn("tproxy-in", sniff_rule["inbound"])

if __name__ == "__main__":
    unittest.main()
