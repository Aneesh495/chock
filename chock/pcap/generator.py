"""
Synthetic Network Packet Vector Generator for Chock Verification.

Generates realistic Ethernet, IPv4, IPv6, SRv6, INT, VXLAN, NetCache,
NetPaxos, and Market Data packets with accurate byte layouts.
"""

import struct
from typing import Dict, Any, List

def build_ethernet_frame(dst_mac: bytes, src_mac: bytes, ether_type: int, payload: bytes) -> bytes:
    """Constructs a 14-byte IEEE 802.3 Ethernet frame."""
    return struct.pack("!6s6sH", dst_mac, src_mac, ether_type) + payload

def build_vlan_frame(dst_mac: bytes, src_mac: bytes, vid: int, ether_type: int, payload: bytes) -> bytes:
    """Constructs an 18-byte IEEE 802.1Q tagged Ethernet frame."""
    vlan_tag = struct.pack("!HH", 0x8100, vid & 0x0FFF)
    return struct.pack("!6s6s", dst_mac, src_mac) + vlan_tag + struct.pack("!H", ether_type) + payload

def build_ipv4_packet(src_ip: int, dst_ip: int, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    """Constructs a standard 20-byte IPv4 packet header with payload."""
    total_len = 20 + len(payload)
    hdr_without_csum = struct.pack("!BBHHHBBHII", 0x45, 0x00, total_len, 0x1234, 0x4000, ttl, proto, 0, src_ip, dst_ip)
    
    # Calculate checksum
    s = sum(struct.unpack(f"!10H", hdr_without_csum))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    csum = ~s & 0xFFFF
    
    hdr = struct.pack("!BBHHHBBHII", 0x45, 0x00, total_len, 0x1234, 0x4000, ttl, proto, csum, src_ip, dst_ip)
    return hdr + payload

def build_udp_packet(src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Constructs an 8-byte UDP packet header with payload."""
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload

def build_netcache_packet(op: int, key: int, val: int = 0) -> bytes:
    """Constructs a NetCache query packet (UDP port 8888)."""
    # op(1B), status(1B), seq_id(2B), key(8B), val(16B)
    val_high = (val >> 64) & 0xFFFFFFFFFFFFFFFF
    val_low = val & 0xFFFFFFFFFFFFFFFF
    nc_payload = struct.pack("!BBHQQQ", op, 0, 1, key, val_high, val_low)
    udp = build_udp_packet(49152, 8888, nc_payload)
    ip = build_ipv4_packet(0xC0A80001, 0x0A000001, 17, udp)
    return build_ethernet_frame(b"\x00\x11\x22\x33\x44\x55", b"\x00\xaa\xbb\xcc\xdd\xee", 0x0800, ip)

def build_market_feed_packet(channel_id: int, sequence_number: int, price: int = 15000) -> bytes:
    """Constructs a financial market data packet (UDP port 10001)."""
    # channel_id(1B), line_id(1B), message_count(2B), seq(4B), timestamp(8B), price(4B)
    feed_payload = struct.pack("!BBHIQI", channel_id, 1, 1, sequence_number, 1600000000000, price)
    udp = build_udp_packet(49152, 10001, feed_payload)
    ip = build_ipv4_packet(0xC0A80101, 0xE0000101, 17, udp)
    return build_ethernet_frame(b"\x01\x00\x5e\x00\x01\x01", b"\x00\xaa\xbb\xcc\xdd\xee", 0x0800, ip)
