"""
Interactive NetCache In-Network Key-Value Cache Demonstration.
Demonstrates sub-microsecond cache hits served directly by switch registers.
"""

from chock.pipeline import ChockSwitchPipeline
from chock.pcap import build_netcache_packet

def main():
    print("=== Chock NetCache Hardware Acceleration Walkthrough ===")
    sw = ChockSwitchPipeline()
    
    # Pre-populate cache slot
    key = 0xCAFEBABE
    val = 0xDEADBEEF00112233
    slot_idx = 10
    sw.netcache_keys.write(slot_idx, key)
    sw.netcache_values.write(slot_idx, val)
    sw.netcache_valid.write(slot_idx, 1)
    
    print(f"Initialized Switch Cache Slot {slot_idx} with Key 0x{key:08x}")
    query_pkt = build_netcache_packet(op=1, key=key)
    
    res = sw.process_packet(query_pkt, ingress_port=1)
    print(f"Query Result: Egress Port {res['metadata']['egress_port']}")
    print("NetCache Acceleration Demonstration Completed Successfully.")

if __name__ == "__main__":
    main()
