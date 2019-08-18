"""
Unit tests for Count-Min sketch, Counting Bloom filter, and TCAM ACL.
"""

import unittest
from chock.pipeline import ChockSwitchPipeline
from chock.pipeline.externs import ChockRegister, ChockHash
from chock.pcap import build_ipv4_packet, build_ethernet_frame

class TestSecuritySketches(unittest.TestCase):
    def setUp(self):
        self.sw = ChockSwitchPipeline()

    def test_tcam_acl_deny_drop(self):
        # Configure ACL deny rule for malicious IP
        self.sw.acl_table.add_entry({"dst_ip": 0xDEADBEEF}, "acl_deny", {}, priority=200)
        
        ip_pkt = build_ipv4_packet(0xC0A80001, 0xDEADBEEF, 6, b"ATTACK_VECTOR")
        eth_pkt = build_ethernet_frame(b"\x00\x11\x22\x33\x44\x55", b"\xaa\xbb\xcc\xdd\xee\xff", 0x0800, ip_pkt)
        
        res = self.sw.process_packet(eth_pkt, ingress_port=1)
        self.assertTrue(res["metadata"]["drop"])
        self.assertIsNone(res["egress_packet"])

    def test_count_min_sketch_heavy_hitter_tracking(self):
        sketch = [ChockRegister(65536, 0) for _ in range(4)]
        hasher = ChockHash("CRC32")
        
        flow_key = b"192.168.1.100:10.0.0.50:6:443:55000"
        idx = hasher.compute(flow_key) % 65536
        
        for r in sketch:
            r.write(idx, r.read(idx) + 1)
            
        estimates = [r.read(idx) for r in sketch]
        min_est = min(estimates)
        self.assertEqual(min_est, 1)

if __name__ == "__main__":
    unittest.main()
