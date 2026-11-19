#!/usr/bin/env python3
import json
import os
import shutil
import tempfile
import unittest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import mobile_push
import proto_stats


class TestMobilePushAndStats(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_net24_extraction(self):
        self.assertEqual(mobile_push._net24("1.2.3.4"), "1.2.3.0/24")
        self.assertEqual(mobile_push._net24("192.168.1.100"), "192.168.1.0/24")
        # Non-IP fallback
        self.assertEqual(mobile_push._net24("example.com"), "example.com")

    def test_diverse_by_net(self):
        # 4 links from 1.2.3.0/24 and 2 links from 5.6.7.0/24
        links = [
            "vless://uuid@1.2.3.1:443?security=reality#n1",
            "vless://uuid@1.2.3.2:443?security=reality#n2",
            "vless://uuid@1.2.3.3:443?security=reality#n3",
            "vless://uuid@1.2.3.4:443?security=reality#n4",
            "vless://uuid@5.6.7.1:443?security=reality#n5",
            "vless://uuid@5.6.7.2:443?security=reality#n6",
        ]
        res = mobile_push.diverse_by_net(links, per_net=2)
        # Should take 2 from 1.2.3.0/24 and 2 from 5.6.7.0/24
        self.assertEqual(len(res), 4)
        self.assertIn(links[0], res)
        self.assertIn(links[1], res)
        self.assertNotIn(links[2], res)
        self.assertNotIn(links[3], res)
        self.assertIn(links[4], res)
        self.assertIn(links[5], res)

    def test_prune_invalid_sb_missing_binary(self):
        cfg = {"inbounds": [], "outbounds": [], "route": {"rules": []}}
        nodes = [{"name": "N0", "link": "vless://..."}]
        # Non-existent binary should return gracefully without crash
        nodes_out, ok, dropped = mobile_push.prune_invalid_sb(cfg, nodes, sb_bin="non_existent_binary_xyz_123")
        self.assertTrue(ok)
        self.assertEqual(len(nodes_out), 1)
        self.assertEqual(dropped, [])

    def test_proto_stats_fam(self):
        self.assertEqual(proto_stats.fam("hy2://pass@host:443"), "hy2")
        self.assertEqual(proto_stats.fam("hysteria2://pass@host:443"), "hy2")
        self.assertEqual(proto_stats.fam("hysteria://pass@host:443"), "hy2")
        self.assertEqual(proto_stats.fam("vless://uuid@host:443"), "vless")
        self.assertEqual(proto_stats.fam("ss://method:pass@host:443"), "ss")

    def test_proto_stats_load_runs(self):
        runs_dir = os.path.join(self.tmpdir, "runs", "20261119_120000")
        os.makedirs(runs_dir, exist_ok=True)
        sample_run = {
            "sent": [
                {"name": "N0", "link": "vless://u@1.2.3.4:443"},
                {"name": "N1", "link": "hy2://p@1.2.3.5:443"},
            ],
            "out": [
                {"name": "N0", "link": "vless://u@1.2.3.4:443", "delay": 150, "gemini": "ok"},
                {"name": "N1", "link": "hy2://p@1.2.3.5:443", "delay": 0, "gemini": "fail"},
            ]
        }
        with open(os.path.join(runs_dir, "run.json"), "w", encoding="utf-8") as f:
            json.dump(sample_run, f)

        # Patch CACHE in proto_stats
        orig_cache = proto_stats.CACHE
        try:
            proto_stats.CACHE = self.tmpdir
            runs = proto_stats.load_runs()
            self.assertEqual(len(runs), 1)
            self.assertEqual(len(runs[0]["sent"]), 2)
            self.assertEqual(len(runs[0]["out"]), 2)
        finally:
            proto_stats.CACHE = orig_cache


if __name__ == "__main__":
    unittest.main()
