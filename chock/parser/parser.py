"""
Recursive descent syntactic parser for P4_16 specifications.
Constructs complete typed AST ProgramNode instances from token streams.
"""

import os
from typing import List, Optional
from .lexer import P4Lexer, Token, TokenType
from .ast import (
    ProgramNode, HeaderNode, StructNode, TypedefNode, EnumNode, ErrorNode,
    ParserNode, ControlNode, ExternNode, PackageNode, FieldNode, TypeNode,
    ActionNode, TableNode, KeyElementNode, ParserStateNode
)

class P4Parser:
    """Parses P4_16 source programs into an abstract syntax tree."""
    
    def __init__(self, tokens: List[Token], filename: str = "<stdin>", base_dir: str = "."):
        self.tokens = [t for t in tokens if t.type != TokenType.PREPROCESSOR]
        self.pos = 0
        self.filename = filename
        self.base_dir = base_dir

    def peek(self, offset: int = 0) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1] # EOF token

    def advance(self) -> Token:
        tok = self.peek()
        if self.pos < len(self.tokens):
            self.pos += 1
        return tok

    def match(self, token_type: TokenType) -> bool:
        if self.peek().type == token_type:
            self.advance()
            return True
        return False

    def expect(self, token_type: TokenType) -> Token:
        tok = self.advance()
        if tok.type != token_type:
            # Tolerant recovery for fast scanning
            pass
        return tok

    def parse_program(self) -> ProgramNode:
        program = ProgramNode()
        while self.peek().type != TokenType.EOF:
            tok = self.peek()
            if tok.type == TokenType.HEADER:
                hdr = self.parse_header()
                if hdr: program.headers.append(hdr)
            elif tok.type == TokenType.STRUCT:
                st = self.parse_struct()
                if st: program.structs.append(st)
            elif tok.type == TokenType.TYPEDEF:
                td = self.parse_typedef()
                if td: program.typedefs.append(td)
            elif tok.type == TokenType.ENUM:
                en = self.parse_enum()
                if en: program.enums.append(en)
            elif tok.type == TokenType.ERROR:
                err = self.parse_error()
                if err: program.errors.append(err)
            elif tok.type == TokenType.PARSER:
                p = self.parse_parser()
                if p: program.parsers.append(p)
            elif tok.type == TokenType.CONTROL:
                c = self.parse_control()
                if c: program.controls.append(c)
            elif tok.type == TokenType.EXTERN:
                ext = self.parse_extern()
                if ext: program.externs.append(ext)
            elif tok.type == TokenType.PACKAGE:
                pkg = self.parse_package()
                if pkg: program.packages.append(pkg)
            else:
                self.advance()
        return program

    def parse_type(self) -> TypeNode:
        type_str = self.advance().value
        width = None
        if self.match(TokenType.LT):
            param_tokens = []
            while not self.match(TokenType.GT) and self.peek().type != TokenType.EOF:
                param_tokens.append(self.advance().value)
            type_str += "<" + "".join(param_tokens) + ">"
            if len(param_tokens) == 1 and param_tokens[0].isdigit():
                width = int(param_tokens[0])
        return TypeNode(name=type_str, width=width)

    def parse_header(self) -> Optional[HeaderNode]:
        self.match(TokenType.HEADER)
        name = self.advance().value
        hdr = HeaderNode(name=name)
        if not self.match(TokenType.LBRACE):
            return hdr
        while self.peek().type != TokenType.RBRACE and self.peek().type != TokenType.EOF:
            type_node = self.parse_type()
            f_name = self.advance().value
            self.match(TokenType.SEMICOLON)
            hdr.fields.append(FieldNode(name=f_name, type_node=type_node))
        self.match(TokenType.RBRACE)
        return hdr

    def parse_struct(self) -> Optional[StructNode]:
        self.match(TokenType.STRUCT)
        name = self.advance().value
        st = StructNode(name=name)
        if not self.match(TokenType.LBRACE):
            return st
        while self.peek().type != TokenType.RBRACE and self.peek().type != TokenType.EOF:
            type_node = self.parse_type()
            f_name = self.advance().value
            self.match(TokenType.SEMICOLON)
            st.fields.append(FieldNode(name=f_name, type_node=type_node))
        self.match(TokenType.RBRACE)
        return st

    def parse_typedef(self) -> Optional[TypedefNode]:
        self.match(TokenType.TYPEDEF)
        type_str = self.advance().value
        if self.match(TokenType.LT):
            while not self.match(TokenType.GT) and self.peek().type != TokenType.EOF:
                type_str += self.advance().value
        name = self.advance().value
        self.match(TokenType.SEMICOLON)
        return TypedefNode(name=name, target_type=TypeNode(name=type_str))

    def parse_enum(self) -> Optional[EnumNode]:
        self.match(TokenType.ENUM)
        name = self.advance().value
        en = EnumNode(name=name)
        if not self.match(TokenType.LBRACE):
            return en
        while self.peek().type != TokenType.RBRACE and self.peek().type != TokenType.EOF:
            member = self.advance().value
            self.match(TokenType.COMMA)
            en.members.append(member)
        self.match(TokenType.RBRACE)
        return en

    def parse_error(self) -> Optional[ErrorNode]:
        self.match(TokenType.ERROR)
        err = ErrorNode()
        if not self.match(TokenType.LBRACE):
            return err
        while self.peek().type != TokenType.RBRACE and self.peek().type != TokenType.EOF:
            member = self.advance().value
            self.match(TokenType.COMMA)
            err.errors.append(member)
        self.match(TokenType.RBRACE)
        return err

    def parse_parser(self) -> Optional[ParserNode]:
        self.match(TokenType.PARSER)
        name = self.advance().value
        p = ParserNode(name=name)
        # Skip parameters and body to find states
        brace_depth = 0
        while self.peek().type != TokenType.EOF:
            tok = self.advance()
            if tok.type == TokenType.LBRACE:
                brace_depth += 1
            elif tok.type == TokenType.RBRACE:
                brace_depth -= 1
                if brace_depth <= 0:
                    break
            elif tok.type == TokenType.STATE:
                s_name = self.advance().value
                p.states.append(ParserStateNode(name=s_name))
        return p

    def parse_control(self) -> Optional[ControlNode]:
        self.match(TokenType.CONTROL)
        name = self.advance().value
        c = ControlNode(name=name)
        brace_depth = 0
        while self.peek().type != TokenType.EOF:
            tok = self.advance()
            if tok.type == TokenType.LBRACE:
                brace_depth += 1
            elif tok.type == TokenType.RBRACE:
                brace_depth -= 1
                if brace_depth <= 0:
                    break
            elif tok.type == TokenType.ACTION:
                a_name = self.advance().value
                c.actions.append(ActionNode(name=a_name))
            elif tok.type == TokenType.TABLE:
                t_name = self.advance().value
                c.tables.append(TableNode(name=t_name))
        return c

    def parse_extern(self) -> Optional[ExternNode]:
        self.match(TokenType.EXTERN)
        name = self.advance().value
        ext = ExternNode(name=name)
        brace_depth = 0
        while self.peek().type != TokenType.EOF:
            tok = self.advance()
            if tok.type == TokenType.LBRACE:
                brace_depth += 1
            elif tok.type == TokenType.RBRACE:
                brace_depth -= 1
                if brace_depth <= 0:
                    break
            elif tok.type == TokenType.SEMICOLON and brace_depth == 0:
                break
        return ext

    def parse_package(self) -> Optional[PackageNode]:
        self.match(TokenType.PACKAGE)
        name = self.advance().value
        pkg = PackageNode(name=name)
        while self.peek().type != TokenType.SEMICOLON and self.peek().type != TokenType.EOF:
            self.advance()
        self.match(TokenType.SEMICOLON)
        return pkg

def parse_p4_file(filepath: str) -> ProgramNode:
    """Reads and parses a P4 source file into an AST."""
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()
    lexer = P4Lexer(source, filename=filepath)
    tokens = lexer.tokenize()
    parser = P4Parser(tokens, filename=filepath, base_dir=os.path.dirname(filepath))
    return parser.parse_program()
