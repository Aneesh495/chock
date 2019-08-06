"""
Zero-dependency Libpcap (PCAP) File Reader and Writer.

Reads and writes standard wire captures with 24-byte global header
and 16-byte per-packet record headers.
"""

import struct
import time
from typing import List, Tuple, Optional

PCAP_MAGIC_MICROSECONDS = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

class PcapWriter:
    """Writes Ethernet packet captures to standard PCAP files."""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.file = open(filename, "wb")
        self._write_global_header()
        
    def _write_global_header(self):
        # magic, major, minor, thiszone, sigfigs, snaplen, network (1 = Ethernet)
        hdr = struct.pack("!IHHiIII", PCAP_MAGIC_MICROSECONDS, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR, 0, 0, 65535, 1)
        self.file.write(hdr)
        self.file.flush()
        
    def write_packet(self, packet_bytes: bytes, timestamp_sec: Optional[float] = None):
        if timestamp_sec is None:
            timestamp_sec = time.time()
        sec = int(timestamp_sec)
        usec = int((timestamp_sec - sec) * 1000000)
        pkt_len = len(packet_bytes)
        
        # ts_sec, ts_usec, incl_len, orig_len
        rec_hdr = struct.pack("!IIII", sec, usec, pkt_len, pkt_len)
        self.file.write(rec_hdr)
        self.file.write(packet_bytes)
        self.file.flush()
        
    def close(self):
        if self.file:
            self.file.close()
            self.file = None

class PcapReader:
    """Reads packets from standard PCAP capture files."""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.file = open(filename, "rb")
        self._read_global_header()
        
    def _read_global_header(self):
        gh = self.file.read(24)
        if len(gh) < 24:
            raise ValueError("Invalid PCAP file: Global header truncated")
        magic, major, minor, thiszone, sigfigs, snaplen, network = struct.unpack("!IHHiIII", gh)
        if magic != PCAP_MAGIC_MICROSECONDS:
            # Check little-endian variant
            pass
            
    def read_packets(self) -> List[Tuple[float, bytes]]:
        packets = []
        while True:
            rec_hdr = self.file.read(16)
            if len(rec_hdr) < 16:
                break
            sec, usec, incl_len, orig_len = struct.unpack("!IIII", rec_hdr)
            pkt_data = self.file.read(incl_len)
            ts = sec + (usec / 1000000.0)
            packets.append((ts, pkt_data))
        return packets
        
    def close(self):
        if self.file:
            self.file.close()
            self.file = None
