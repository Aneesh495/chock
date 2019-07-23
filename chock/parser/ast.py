"""
Abstract Syntax Tree (AST) node hierarchy for P4_16 specifications.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class ASTNode:
    line: int = 0
    column: int = 0

@dataclass
class TypeNode(ASTNode):
    name: str = ""
    width: Optional[int] = None

@dataclass
class FieldNode(ASTNode):
    name: str = ""
    type_node: Optional[TypeNode] = None

@dataclass
class HeaderNode(ASTNode):
    name: str = ""
    fields: List[FieldNode] = field(default_factory=list)

@dataclass
class StructNode(ASTNode):
    name: str = ""
    fields: List[FieldNode] = field(default_factory=list)

@dataclass
class TypedefNode(ASTNode):
    name: str = ""
    target_type: Optional[TypeNode] = None

@dataclass
class EnumNode(ASTNode):
    name: str = ""
    members: List[str] = field(default_factory=list)

@dataclass
class ErrorNode(ASTNode):
    errors: List[str] = field(default_factory=list)

@dataclass
class ActionNode(ASTNode):
    name: str = ""
    parameters: List[FieldNode] = field(default_factory=list)
    body: List[str] = field(default_factory=list)

@dataclass
class KeyElementNode(ASTNode):
    expression: str = ""
    match_type: str = "exact"

@dataclass
class TableNode(ASTNode):
    name: str = ""
    keys: List[KeyElementNode] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    size: int = 1024
    default_action: str = "NoAction"

@dataclass
class ParserStateNode(ASTNode):
    name: str = ""
    statements: List[str] = field(default_factory=list)
    transition: str = ""

@dataclass
class ParserNode(ASTNode):
    name: str = ""
    parameters: List[FieldNode] = field(default_factory=list)
    states: List[ParserStateNode] = field(default_factory=list)

@dataclass
class ControlNode(ASTNode):
    name: str = ""
    parameters: List[FieldNode] = field(default_factory=list)
    locals: List[ASTNode] = field(default_factory=list)
    actions: List[ActionNode] = field(default_factory=list)
    tables: List[TableNode] = field(default_factory=list)
    apply_statements: List[str] = field(default_factory=list)

@dataclass
class ExternNode(ASTNode):
    name: str = ""
    type_params: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)

@dataclass
class PackageNode(ASTNode):
    name: str = ""
    type_params: List[str] = field(default_factory=list)
    args: List[str] = field(default_factory=list)

@dataclass
class ProgramNode(ASTNode):
    headers: List[HeaderNode] = field(default_factory=list)
    structs: List[StructNode] = field(default_factory=list)
    typedefs: List[TypedefNode] = field(default_factory=list)
    enums: List[EnumNode] = field(default_factory=list)
    errors: List[ErrorNode] = field(default_factory=list)
    parsers: List[ParserNode] = field(default_factory=list)
    controls: List[ControlNode] = field(default_factory=list)
    externs: List[ExternNode] = field(default_factory=list)
    packages: List[PackageNode] = field(default_factory=list)
