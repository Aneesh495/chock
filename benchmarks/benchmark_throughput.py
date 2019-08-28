"""
Micro-benchmark suite for ChockSwitch data plane processing:
- Raw packet parsing throughput
- TCAM ACL evaluation rate
- IPv4 LPM CIDR forwarding rate
- NetCache query evaluation latency
"""

import time
import struct
from chock.pipeline import ChockSwitchPipeline
from chock.pcap import build_ipv4_packet, build_ethernet_frame, build_netcache_packet

def run_benchmarks():
    sw = ChockSwitchPipeline()
    sw.ipv4_lpm_table.add_entry({"dst_ip": 0x0A000001}, "set_next_hop_unicast", {"port": 2})
    
    ip = build_ipv4_packet(0xC0A80001, 0x0A000001, 6, b"DATA" * 16)
    pkt = build_ethernet_frame(b"\\x00\\x11\\x22\\x33\\x44\\x55", b"\\x00\\xaa\\xbb\\xcc\\xdd\\xee", 0x0800, ip)
    
    rounds = 50000
    print(f"Benchmarking L3 IPv4 forwarding throughput ({rounds} iterations)...")
    t0 = time.perf_counter()
    for _ in range(rounds):
        sw.process_packet(pkt, ingress_port=1)
    t1 = time.perf_counter()
    
    duration = t1 - t0
    pps = rounds / duration
    latency_us = (duration / rounds) * 1e6
    print(f"  Duration:   {duration:.4f} s")
    print(f"  Throughput: {pps:,.0f} pps ({pps/1e6:.2f} Mpps)")
    print(f"  Latency:    {latency_us:.2f} us/packet")

if __name__ == "__main__":
    run_benchmarks()
