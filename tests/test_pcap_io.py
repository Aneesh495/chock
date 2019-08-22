"""
Unit tests for PCAP file reader and writer.
"""

import unittest
import os
import tempfile
from chock.pcap import PcapReader, PcapWriter, build_ethernet_frame, build_ipv4_packet

class TestPcapIO(unittest.TestCase):
    def test_pcap_round_trip(self):
        ip = build_ipv4_packet(0x0A000001, 0x0A000002, 6, b"PCAP_TEST_DATA")
        frame = build_ethernet_frame(b"\x00\x11\x22\x33\x44\x55", b"\xaa\xbb\xcc\xdd\xee\xff", 0x0800, ip)
        
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            temp_path = tf.name
            
        try:
            # Write packet
            writer = PcapWriter(temp_path)
            writer.write_packet(frame, timestamp_sec=1600000000.5)
            writer.close()
            
            # Read packet back
            reader = PcapReader(temp_path)
            pkts = reader.read_packets()
            reader.close()
            
            self.assertEqual(len(pkts), 1)
            ts, read_frame = pkts[0]
            self.assertEqual(read_frame, frame)
            self.assertAlmostEqual(ts, 1600000000.5, places=4)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

if __name__ == "__main__":
    unittest.main()
