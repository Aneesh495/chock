"""
Interactive In-Band Network Telemetry (INT v2.1) Demonstration.
Shows line-rate telemetry hop stamping and queue occupancy tracking.
"""

from chock.pipeline import ChockSwitchPipeline
from chock.pcap import build_ipv4_packet, build_ethernet_frame

def main():
    print("=== Chock In-Band Network Telemetry (INT v2.1) Walkthrough ===")
    sw = ChockSwitchPipeline()
    sw.ipv4_lpm_table.add_entry({"dst_ip": 0x0A000001}, "set_next_hop_unicast", {"port": 4})
    
    ip = build_ipv4_packet(0xC0A80101, 0x0A000001, 17, b"INT_DATA_FLOW")
    pkt = build_ethernet_frame(b"\x00\x11\x22\x33\x44\x55", b"\x00\xaa\xbb\xcc\xdd\xee", 0x0800, ip)
    
    res = sw.process_packet(pkt, ingress_port=2)
    print("\nTelemetry Metadata Collected:")
    print(f"  Ingress Port:  {res['metadata']['ingress_port']}")
    print(f"  Egress Port:   {res['metadata']['egress_port']}")
    print(f"  Queue Latency: {res['metadata']['latency_ns']} ns")
    print(f"  Queue Depth:   {res['metadata']['queue_depth']} packets")
    print("INT Demonstration Completed Successfully.")

if __name__ == "__main__":
    main()
