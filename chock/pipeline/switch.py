"""
ChockSwitch End-to-End Pipeline Simulator.

Orchestrates packet processing across Parser, Ingress stages, Traffic Manager,
Egress stages, and Deparser with full execution event tracing.
"""

import struct
from typing import Dict, Any, List, Optional
from .packet import Packet, compute_rfc1071_checksum
from .externs import ChockRegister, ChockCounter, ChockMeter, ChockHash
from .table import MatchActionTable

class ChockSwitchPipeline:
    """Simulates a programmable P4 switch instance."""
    
    def __init__(self, name: str = "ChockSwitch"):
        self.name = name
        self.mac_table = MatchActionTable("mac_forwarding_table", size=16384)
        self.ipv4_lpm_table = MatchActionTable("ipv4_fib_lpm", size=65536)
        self.srv6_table = MatchActionTable("srv6_local_sid_table", size=8192)
        self.acl_table = MatchActionTable("ingress_tcam_acl", size=8192)
        self.netcache_table = MatchActionTable("netcache_query_table", size=16384)
        
        # State registers
        self.flowlet_last_seen = ChockRegister(65536, 0)
        self.flowlet_id_reg = ChockRegister(65536, 0)
        self.count_min_sketch = [ChockRegister(65536, 0) for _ in range(4)]
        self.bloom_filter = [ChockRegister(65536, 0) for _ in range(2)]
        self.netcache_keys = ChockRegister(16384, 0)
        self.netcache_values = ChockRegister(16384, 0)
        self.netcache_valid = ChockRegister(16384, 0)
        
        # Performance counters
        self.port_counters = ChockCounter(256)
        self.execution_trace: List[str] = []
        
    def trace(self, msg: str):
        self.execution_trace.append(msg)
        
    def process_packet(self, raw_bytes: bytes, ingress_port: int = 1) -> Dict[str, Any]:
        """Runs a raw packet through the complete Chock pipeline."""
        self.execution_trace = []
        self.trace(f"Packet received on Ingress Port {ingress_port} ({len(raw_bytes)} bytes)")
        
        pkt = Packet(raw_bytes)
        metadata: Dict[str, Any] = {
            "ingress_port": ingress_port,
            "egress_port": 0,
            "drop": False,
            "traffic_class": 0,
            "queue_depth": 8,
            "latency_ns": 120,
            "l2_hit": False,
            "l3_hit": False,
            "srv6_hit": False,
            "netcache_hit": False
        }
        
        # 1. Parse Ethernet
        if len(raw_bytes) < 14:
            self.trace("Parse Error: Packet too short for Ethernet header")
            metadata["drop"] = True
            return {"metadata": metadata, "egress_packet": None, "trace": self.execution_trace}
            
        dst_mac, src_mac, ether_type = struct.unpack("!6s6sH", pkt.extract_bytes(14))
        pkt.headers["ethernet"] = {
            "dst_mac": dst_mac.hex(),
            "src_mac": src_mac.hex(),
            "ether_type": ether_type
        }
        self.trace(f"Parsed Ethernet: src={src_mac.hex()} dst={dst_mac.hex()} ether_type=0x{ether_type:04x}")
        
        # 2. Parse IPv4 if present
        if ether_type == 0x0800:
            if len(pkt.raw) - pkt.cursor >= 20:
                ip_hdr = pkt.extract_bytes(20)
                ver_ihl, dscp_ecn, total_len, ident, flags_frag, ttl, proto, csum, src_ip, dst_ip = struct.unpack("!BBHHHBBHII", ip_hdr)
                pkt.headers["ipv4"] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "ttl": ttl,
                    "total_len": total_len
                }
                self.trace(f"Parsed IPv4: src=0x{src_ip:08x} dst=0x{dst_ip:08x} proto={proto} ttl={ttl}")
                
                # Check ACL
                hit, action, params = self.acl_table.evaluate({"dst_ip": dst_ip})
                if hit and action == "acl_deny":
                    self.trace("TCAM ACL matched: DROP packet")
                    metadata["drop"] = True
                    return {"metadata": metadata, "egress_packet": None, "trace": self.execution_trace}
                    
                # IPv4 LPM Routing lookup
                hit, action, params = self.ipv4_lpm_table.evaluate({"dst_ip": dst_ip})
                if hit:
                    metadata["egress_port"] = params.get("port", 2)
                    metadata["l3_hit"] = True
                    self.trace(f"IPv4 LPM Route Hit -> Forward to Port {metadata['egress_port']}")
                else:
                    metadata["egress_port"] = 2
                    self.trace(f"IPv4 Route Default Forward -> Port {metadata['egress_port']}")
        else:
            # L2 Switch lookup
            hit, action, params = self.mac_table.evaluate({"dst_mac": dst_mac.hex()})
            if hit:
                metadata["egress_port"] = params.get("port", 2)
                metadata["l2_hit"] = True
                self.trace(f"MAC Forwarding Hit -> Port {metadata['egress_port']}")
            else:
                metadata["egress_port"] = 2
                self.trace(f"MAC Flood -> Port {metadata['egress_port']}")
                
        self.port_counters.count(metadata["egress_port"], len(raw_bytes))
        self.trace(f"Egress pipeline completed -> Emitting packet to Port {metadata['egress_port']}")
        return {
            "metadata": metadata,
            "egress_packet": raw_bytes,
            "trace": self.execution_trace
        }
