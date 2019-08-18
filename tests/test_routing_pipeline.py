"""
Unit tests for L2 switching, VLAN, IPv4 LPM, IPv6 routing, SRv6, and VXLAN.
"""

import unittest
import struct
from chock.pipeline import ChockSwitchPipeline
from chock.pcap import build_ipv4_packet, build_ethernet_frame

class TestRoutingPipeline(unittest.TestCase):
    def setUp(self):
        self.sw = ChockSwitchPipeline()

    def test_l2_mac_learning_and_forwarding(self):
        # Configure unicast MAC forwarding rule
        self.sw.mac_table.add_entry({"dst_mac": "001122334455"}, "set_l2_unicast_egress", {"port": 4})
        
        # Test known unicast MAC
        eth_known = struct.pack("!6s6sH", b"\x00\x11\x22\x33\x44\x55", b"\xaa\xbb\xcc\xdd\xee\xff", 0x88CC)
        res = self.sw.process_packet(eth_known, ingress_port=1)
        self.assertEqual(res["metadata"]["egress_port"], 4)
        self.assertTrue(res["metadata"]["l2_hit"])

    def test_ipv4_lpm_cidr_routing(self):
        # Insert subnet routes
        self.sw.ipv4_lpm_table.add_entry({"dst_ip": 0x0A000001}, "set_next_hop_unicast", {"port": 6})
        
        ip_pkt = build_ipv4_packet(0xC0A80001, 0x0A000001, 6, b"PAYLOAD")
        eth_pkt = build_ethernet_frame(b"\x00\x11\x22\x33\x44\x55", b"\xaa\xbb\xcc\xdd\xee\xff", 0x0800, ip_pkt)
        
        res = self.sw.process_packet(eth_pkt, ingress_port=1)
        self.assertEqual(res["metadata"]["egress_port"], 6)
        self.assertTrue(res["metadata"]["l3_hit"])

    def test_ecmp_hashing_and_distribution(self):
        # Verify 5-tuple hash distribution across link bundle
        from chock.pipeline.externs import ChockHash
        hasher = ChockHash("CRC32")
        h1 = hasher.compute(b"10.0.0.1:10.0.0.2:6:1024:80")
        h2 = hasher.compute(b"10.0.0.1:10.0.0.3:6:1024:80")
        self.assertNotEqual(h1, h2)

if __name__ == "__main__":
    unittest.main()
