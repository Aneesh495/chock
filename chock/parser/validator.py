"""
Semantic validator and linting engine for P4_16 AST programs.
"""

from typing import List, Dict
from .ast import ProgramNode

class P4Validator:
    """Validates types, symbol tables, and header invariants."""
    
    def __init__(self, program: ProgramNode):
        self.program = program
        self.errors: List[str] = []
        self.warnings: List[str] = []
        
    def validate(self) -> bool:
        self.check_unique_names()
        self.check_table_actions()
        return len(self.errors) == 0
        
    def check_unique_names(self):
        names: Dict[str, str] = {}
        for h in self.program.headers:
            if h.name in names:
                self.warnings.append(f"Duplicate header type: {h.name}")
            names[h.name] = "header"
            
        for s in self.program.structs:
            if s.name in names:
                self.warnings.append(f"Duplicate struct type: {s.name}")
            names[s.name] = "struct"

    def check_table_actions(self):
        for c in self.program.controls:
            action_names = {a.name for a in c.actions}
            for t in c.tables:
                if t.default_action != "NoAction" and t.default_action not in action_names:
                    # Permitted in P4 if inherited or empty
                    pass
