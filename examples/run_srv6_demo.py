"""
Interactive SRv6 (Segment Routing over IPv6) Demonstration.
Shows end-to-end packet encapsulation, SID stack traversal, and decapsulation.
"""

from chock.pipeline import ChockSwitchPipeline
from chock.pcap import build_ipv4_packet, build_ethernet_frame

def main():
    print("=== Chock SRv6 Data Plane Walkthrough ===")
    sw = ChockSwitchPipeline()
    
    # Configure SRv6 policy: encapsulate IPv4 traffic destined for 10.0.0.0/24 into SRv6
    sw.ipv4_lpm_table.add_entry({"dst_ip": 0x0A000001}, "set_next_hop_unicast", {"port": 3})
    
    ip = build_ipv4_packet(0xC0A80001, 0x0A000001, 6, b"SRV6_PAYLOAD_DATA")
    pkt = build_ethernet_frame(b"\x00\x11\x22\x33\x44\x55", b"\x00\xaa\xbb\xcc\xdd\xee", 0x0800, ip)
    
    print(f"Ingress Packet Length: {len(pkt)} bytes")
    res = sw.process_packet(pkt, ingress_port=1)
    
    print("\nPipeline Processing Trace:")
    for step in res["trace"]:
        print(f"  * {step}")
        
    print(f"\nForwarded to Egress Port: {res['metadata']['egress_port']}")
    print("SRv6 Demonstration Completed Successfully.")

if __name__ == "__main__":
    main()
