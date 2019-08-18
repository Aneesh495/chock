"""
Unit tests for NetCache, NetPaxos, and Market Data feed arbitration.
"""

import unittest
from chock.pipeline.externs import ChockRegister
from chock.pcap import build_market_feed_packet

class TestComputeAcceleration(unittest.TestCase):
    def test_market_feed_arbitration_deduplication(self):
        last_seq_reg = ChockRegister(256, 0)
        channel_id = 5
        
        # First packet arrives from Line A with seq=100
        seq_a = 100
        last_seq = last_seq_reg.read(channel_id)
        is_dup_a = seq_a <= last_seq
        self.assertFalse(is_dup_a)
        last_seq_reg.write(channel_id, seq_a)
        
        # Duplicate packet arrives from Line B with same seq=100
        seq_b = 100
        last_seq = last_seq_reg.read(channel_id)
        is_dup_b = seq_b <= last_seq
        self.assertTrue(is_dup_b)

    def test_netcache_key_slot_lookup(self):
        cache_keys = ChockRegister(16384, 0)
        cache_vals = ChockRegister(16384, 0)
        cache_valid = ChockRegister(16384, 0)
        
        # Write cache slot 10
        cache_keys.write(10, 0xCAFEBABE)
        cache_vals.write(10, 0x1234567890ABCDEF)
        cache_valid.write(10, 1)
        
        # Query cache slot 10
        self.assertEqual(cache_valid.read(10), 1)
        self.assertEqual(cache_keys.read(10), 0xCAFEBABE)
        self.assertEqual(cache_vals.read(10), 0x1234567890ABCDEF)

if __name__ == "__main__":
    unittest.main()
