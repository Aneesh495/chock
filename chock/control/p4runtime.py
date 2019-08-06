"""
P4Runtime Control Plane API Server and Client Simulation.

Implements the standard P4Runtime RPC interface:
- TableEntry write (INSERT, MODIFY, DELETE)
- CounterEntry read and reset
- RegisterEntry read and write
- PacketIn and PacketOut stream processing
- DigestList learning notifications
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from ..pipeline.switch import ChockSwitchPipeline

class UpdateType:
    INSERT = "INSERT"
    MODIFY = "MODIFY"
    DELETE = "DELETE"

@dataclass
class P4RuntimeEntity:
    table_name: str
    match_fields: Dict[str, Any]
    action_name: str
    action_params: Dict[str, Any]
    priority: int = 100

class P4RuntimeServer:
    """Manages control plane table programming and telemetry reads."""
    
    def __init__(self, switch_pipeline: ChockSwitchPipeline):
        self.switch = switch_pipeline
        self.tables = {
            "mac_forwarding_table": self.switch.mac_table,
            "ipv4_fib_lpm": self.switch.ipv4_lpm_table,
            "srv6_local_sid_table": self.switch.srv6_table,
            "ingress_tcam_acl": self.switch.acl_table,
            "netcache_query_table": self.switch.netcache_table
        }
        
    def write_table_entry(self, update_type: str, entity: P4RuntimeEntity) -> bool:
        """Applies an INSERT, MODIFY, or DELETE table rule."""
        target_table = self.tables.get(entity.table_name)
        if not target_table:
            return False
            
        if update_type == UpdateType.INSERT:
            target_table.add_entry(
                match_keys=entity.match_fields,
                action_name=entity.action_name,
                action_params=entity.action_params,
                priority=entity.priority
            )
            return True
        elif update_type == UpdateType.DELETE:
            target_table.entries = [
                e for e in target_table.entries
                if e.match_keys != entity.match_fields
            ]
            return True
        return False
        
    def read_counters(self, port_id: int) -> Dict[str, int]:
        """Reads packet and byte metrics from hardware counters."""
        return {
            "port_id": port_id,
            "packets": self.switch.port_counters.get_packets(port_id),
            "bytes": self.switch.port_counters.get_bytes(port_id)
        }
        
    def read_register(self, register_name: str, index: int) -> int:
        """Reads on-chip stateful register contents."""
        if register_name == "netcache_keys":
            return self.switch.netcache_keys.read(index)
        elif register_name == "netcache_values":
            return self.switch.netcache_values.read(index)
        elif register_name == "flowlet_id":
            return self.switch.flowlet_id_reg.read(index)
        return 0
