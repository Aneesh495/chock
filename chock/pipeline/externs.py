"""
Hardware switch extern stateful primitives:
Registers, Counters, Meters, Hash engines, PRNG, and Digest dispatch.
"""

import time
import zlib
from typing import List, Any, Optional
from .packet import murmur3_32

class ChockRegister:
    """Stateful register array simulating on-chip SRAM."""
    
    def __init__(self, size: int, initial_value: int = 0):
        self.size = size
        self.cells = [initial_value] * size
        
    def read(self, index: int) -> int:
        return self.cells[index % self.size]
        
    def write(self, index: int, value: int):
        self.cells[index % self.size] = value
        
    def compare_and_swap(self, index: int, compare_val: int, new_val: int) -> int:
        idx = index % self.size
        cur = self.cells[idx]
        if cur == compare_val:
            self.cells[idx] = new_val
        return cur

class ChockCounter:
    """Packet and byte statistics counter array."""
    
    def __init__(self, size: int, counter_type: str = "PACKETS_AND_BYTES"):
        self.size = size
        self.counter_type = counter_type
        self.packet_counts = [0] * size
        self.byte_counts = [0] * size
        
    def count(self, index: int, byte_len: int = 64):
        idx = index % self.size
        self.packet_counts[idx] += 1
        self.byte_counts[idx] += byte_len
        
    def get_packets(self, index: int) -> int:
        return self.packet_counts[index % self.size]
        
    def get_bytes(self, index: int) -> int:
        return self.byte_counts[index % self.size]

class MeterColor:
    GREEN = 0
    YELLOW = 1
    RED = 2

class ChockMeter:
    """RFC 2698 Two-Rate Three-Color Marker (trTCM) meter array."""
    
    def __init__(self, size: int, cir: int = 1000000, cbs: int = 64000, pir: int = 2000000, pbs: int = 128000):
        self.size = size
        self.cir = cir # Committed info rate (bytes/sec)
        self.cbs = cbs # Committed burst size
        self.pir = pir # Peak info rate
        self.pbs = pbs # Peak burst size
        self.tc = [cbs] * size
        self.tp = [pbs] * size
        self.last_update = [time.time()] * size
        
    def execute(self, index: int, packet_bytes: int) -> int:
        idx = index % self.size
        now = time.time()
        elapsed = now - self.last_update[idx]
        self.last_update[idx] = now
        
        # Replenish tokens
        self.tc[idx] = min(self.cbs, self.tc[idx] + int(elapsed * self.cir))
        self.tp[idx] = min(self.pbs, self.tp[idx] + int(elapsed * self.pir))
        
        if self.tp[idx] < packet_bytes:
            return MeterColor.RED
        elif self.tc[idx] < packet_bytes:
            self.tp[idx] -= packet_bytes
            return MeterColor.YELLOW
        else:
            self.tc[idx] -= packet_bytes
            self.tp[idx] -= packet_bytes
            return MeterColor.GREEN

class ChockHash:
    """Hardware polynomial hash generator."""
    
    def __init__(self, algorithm: str = "CRC32"):
        self.algorithm = algorithm
        
    def compute(self, data: bytes) -> int:
        if self.algorithm == "CRC32":
            return zlib.crc32(data) & 0xFFFFFFFF
        elif self.algorithm == "MURMUR3":
            return murmur3_32(data) & 0xFFFFFFFF
        elif "POLYNOMIAL" in self.algorithm:
            h = 0x811c9dc5
            for b in data:
                h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
            return h
        return sum(data) & 0xFFFFFFFF
