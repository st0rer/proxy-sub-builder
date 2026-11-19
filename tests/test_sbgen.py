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
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=dl.google.com&fp=chrome&pbk=4guBGe6r_cFxgQJeUGvfPCYwcQ2TXURlGOs6vyqH1kY&sid=123456#TestVless",
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
        vless_ob = next((o for o in outbounds if o.get("type") == "vless"), None)
        self.assertIsNotNone(vless_ob)
        self.assertTrue(vless_ob.get("tls", {}).get("record_fragment"))

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

    def test_gcp_routing_and_candidates(self):
        os.environ["SINGBOX_SOURCE"] = self.src_file
        os.environ["SINGBOX_CONFIG"] = self.out_file
        sbgen.main()

        with open(self.out_file, encoding="utf-8") as f:
            cfg = json.load(f)

        # Check gcp selector
        gcp = next((o for o in cfg["outbounds"] if o.get("tag") == "gcp"), None)
        self.assertIsNotNone(gcp)
        self.assertEqual(gcp["type"], "selector")
        self.assertNotEqual(gcp["default"], "cf")
        self.assertTrue(any(t.startswith("hyst") or t.startswith("vles") for t in gcp["outbounds"]))

        # By default unified_delay is off for sing-box < 1.14 compatibility
        self.assertNotIn("unified_delay", cfg.get("experimental", {}))

        # Check that SINGBOX_UNIFIED_DELAY=1 enables it
        os.environ["SINGBOX_UNIFIED_DELAY"] = "1"
        try:
            sbgen.main()
            with open(self.out_file, encoding="utf-8") as f:
                cfg_delay = json.load(f)
            self.assertTrue(cfg_delay.get("experimental", {}).get("unified_delay", {}).get("enabled", False))
        finally:
            os.environ.pop("SINGBOX_UNIFIED_DELAY", None)

        # Check route rules for antigravity.google and googleapis
        gcp_rule = next((r for r in cfg["route"]["rules"] if r.get("outbound") == "gcp"), None)
        self.assertIsNotNone(gcp_rule)
        domains = gcp_rule.get("domain_suffix", [])
        self.assertIn("antigravity.google", domains)
        self.assertIn("googleapis.com", domains)

    def test_video_routing_and_quic_reject(self):
        os.environ["SINGBOX_SOURCE"] = self.src_file
        os.environ["SINGBOX_CONFIG"] = self.out_file
        sbgen.main()

        with open(self.out_file, encoding="utf-8") as f:
            cfg = json.load(f)

        # 1. Проверяем наличие селектора video и urltest video-auto
        video_sel = next((o for o in cfg["outbounds"] if o.get("tag") == "video"), None)
        self.assertIsNotNone(video_sel)
        self.assertEqual(video_sel["type"], "selector")
        self.assertEqual(video_sel["default"], "video-auto")

        video_auto = next((o for o in cfg["outbounds"] if o.get("tag") == "video-auto"), None)
        self.assertIsNotNone(video_auto)
        self.assertEqual(video_auto["type"], "urltest")

        # 2. Проверяем правило сброса QUIC (UDP 443) для видеодоменов
        quic_rule = next((r for r in cfg["route"]["rules"]
                          if r.get("network") == "udp" and r.get("port") == 443 and r.get("action") == "reject"), None)
        self.assertIsNotNone(quic_rule)
        self.assertEqual(quic_rule.get("method"), "default")
        self.assertIn("googlevideo.com", quic_rule.get("domain_suffix", []))
        self.assertIn("youtube.com", quic_rule.get("domain_suffix", []))

        # 3. Проверяем правило направления видеодоменов в outbound video
        video_rule = next((r for r in cfg["route"]["rules"] if r.get("outbound") == "video"), None)
        self.assertIsNotNone(video_rule)
        self.assertIn("googlevideo.com", video_rule.get("domain_suffix", []))

        # 4. Проверяем валидность сгенерированного конфига через реальный sing-box check (если бинарник есть)
        import shutil, subprocess
        sb_bin = shutil.which("sing-box") or (r"C:\Users\Storer\bin\sing-box.exe" if os.path.exists(r"C:\Users\Storer\bin\sing-box.exe") else None)
        if sb_bin:
            res = subprocess.run([sb_bin, "check", "-c", self.out_file], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"sing-box check failed: {res.stderr}")

if __name__ == "__main__":
    unittest.main()
