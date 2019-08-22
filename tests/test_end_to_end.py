"""
Integration tests for complete end-to-end switch pipelines and edge cases.
"""

import unittest
from chock.pipeline import ChockSwitchPipeline
from chock.pcap import build_ipv4_packet, build_ethernet_frame

class TestEndToEndSwitch(unittest.TestCase):
    def setUp(self):
        self.sw = ChockSwitchPipeline()
        self.sw.ipv4_lpm_table.add_entry({"dst_ip": 0x0A000001}, "set_next_hop_unicast", {"port": 2})

    def test_malformed_truncated_packet(self):
        # 5-byte packet (too short for Ethernet)
        res = self.sw.process_packet(b"SHORT", ingress_port=1)
        self.assertTrue(res["metadata"]["drop"])
        self.assertIsNone(res["egress_packet"])

    def test_maximum_transmission_unit_boundary(self):
        # 1500-byte standard MTU packet
        payload = b"X" * (1500 - 14 - 20)
        ip = build_ipv4_packet(0xC0A80001, 0x0A000001, 17, payload)
        pkt = build_ethernet_frame(b"\x00\x11\x22\x33\x44\x55", b"\xaa\xbb\xcc\xdd\xee\xff", 0x0800, ip)
        
        res = self.sw.process_packet(pkt, ingress_port=1)
        self.assertFalse(res["metadata"]["drop"])
        self.assertEqual(res["metadata"]["egress_port"], 2)

if __name__ == "__main__":
    unittest.main()

    def test_random_packet_fuzzing_safety(self):
        import random
        # Fuzz pipeline with 50 random byte vectors of various sizes
        for _ in range(50):
            rand_len = random.randint(1, 2048)
            rand_bytes = bytes([random.randint(0, 255) for _ in range(rand_len)])
            res = self.sw.process_packet(rand_bytes, ingress_port=1)
            self.assertIn("metadata", res)
            self.assertIn("trace", res)

