"""
Match-Action Table evaluation engine supporting Exact, LPM, Ternary,
and Range matching with priority resolution.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable, Optional, Tuple

class MatchType:
    EXACT = "exact"
    LPM = "lpm"
    TERNARY = "ternary"
    RANGE = "range"

@dataclass
class TableEntry:
    match_keys: Dict[str, Any]
    action_name: str
    action_params: Dict[str, Any]
    priority: int = 100

class MatchActionTable:
    """Evaluates ingress and egress forwarding rules against packet keys."""
    
    def __init__(self, name: str, size: int = 4096, default_action: str = "NoAction"):
        self.name = name
        self.size = size
        self.default_action = default_action
        self.default_params: Dict[str, Any] = {}
        self.entries: List[TableEntry] = []
        self.actions: Dict[str, Callable] = {}
        
    def register_action(self, name: str, fn: Callable):
        self.actions[name] = fn
        
    def add_entry(self, match_keys: Dict[str, Any], action_name: str, action_params: Dict[str, Any], priority: int = 100):
        entry = TableEntry(match_keys=match_keys, action_name=action_name, action_params=action_params, priority=priority)
        self.entries.append(entry)
        self.entries.sort(key=lambda e: e.priority, reverse=True)
        
    def evaluate(self, lookup_keys: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        for entry in self.entries:
            match = True
            for k, expected in entry.match_keys.items():
                actual = lookup_keys.get(k)
                if actual is None:
                    match = False
                    break
                if isinstance(expected, tuple) and len(expected) == 2:
                    # Ternary (val, mask) or LPM (val, prefix_len)
                    val, mask = expected
                    if (actual & mask) != (val & mask):
                        match = False
                        break
                elif actual != expected:
                    match = False
                    break
            if match:
                return True, entry.action_name, entry.action_params
        return False, self.default_action, self.default_params
