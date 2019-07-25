"""
Packet bit-level slicing, extraction, serialization, and checksum algorithms.
"""

import struct
import zlib
from typing import Dict, Any, Optional

def compute_rfc1071_checksum(data: bytes) -> int:
    """Computes the standard RFC 1071 16-bit one's complement Internet checksum."""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def murmur3_32(data: bytes, seed: int = 0) -> int:
    """Computes 32-bit MurmurHash3."""
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = (length & 0xfffffffc)
    
    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 ^= (data[rounded_end + 2] & 0xff) << 16
    if val in (2, 3):
        k1 ^= (data[rounded_end + 1] & 0xff) << 8
    if val in (1, 2, 3):
        k1 ^= (data[rounded_end] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    return h1

class Packet:
    """Represents a network packet with raw byte buffer and parsed headers."""
    
    def __init__(self, raw_bytes: bytes = b""):
        self.raw = bytearray(raw_bytes)
        self.cursor = 0
        self.headers: Dict[str, Dict[str, Any]] = {}
        self.metadata: Dict[str, Any] = {}
        
    def extract_bytes(self, num_bytes: int) -> bytes:
        if self.cursor + num_bytes > len(self.raw):
            extracted = self.raw[self.cursor:]
            self.cursor = len(self.raw)
            return bytes(extracted)
        extracted = self.raw[self.cursor:self.cursor + num_bytes]
        self.cursor += num_bytes
        return bytes(extracted)
        
    def remaining_payload(self) -> bytes:
        return bytes(self.raw[self.cursor:])
        
    def emit_header(self, header_name: str, field_formats: str, *values):
        serialized = struct.pack(field_formats, *values)
        self.raw.extend(serialized)
