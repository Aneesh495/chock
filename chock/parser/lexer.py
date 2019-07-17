"""
P4_16 Lexical Analyzer and Tokenizer.

Scans raw P4_16 source text into strongly-typed token streams, handling
preprocessor directives, bit literals (width#value), identifiers, operators,
and comments without external dependencies.
"""

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional

class TokenType(Enum):
    # Keywords
    HEADER = auto()
    STRUCT = auto()
    TYPEDEF = auto()
    ENUM = auto()
    ERROR = auto()
    PARSER = auto()
    CONTROL = auto()
    PACKAGE = auto()
    ACTION = auto()
    TABLE = auto()
    KEY = auto()
    ACTIONS = auto()
    DEFAULT_ACTION = auto()
    SIZE = auto()
    STATE = auto()
    TRANSITION = auto()
    SELECT = auto()
    APPLY = auto()
    EXTERN = auto()
    IN = auto()
    OUT = auto()
    INOUT = auto()
    BIT = auto()
    VARBIT = auto()
    INT = auto()
    EXACT = auto()
    TERNARY = auto()
    LPM = auto()
    RANGE = auto()
    IF = auto()
    ELSE = auto()
    RETURN = auto()
    DEFAULT = auto()
    TRUE = auto()
    FALSE = auto()
    VOID = auto()
    
    # Literals & Identifiers
    IDENTIFIER = auto()
    BIT_LITERAL = auto()
    INT_LITERAL = auto()
    HEX_LITERAL = auto()
    STRING_LITERAL = auto()
    
    # Punctuation & Operators
    LBRACE = auto()
    RBRACE = auto()
    LPAREN = auto()
    RPAREN = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    SEMICOLON = auto()
    COLON = auto()
    COMMA = auto()
    DOT = auto()
    ASSIGN = auto()
    EQUALS = auto()
    NOT_EQUALS = auto()
    LT = auto()
    GT = auto()
    LE = auto()
    GE = auto()
    PLUS = auto()
    MINUS = auto()
    BAND = auto()
    BOR = auto()
    BXOR = auto()
    BNOT = auto()
    LSHIFT = auto()
    RSHIFT = auto()
    NOT = auto()
    LAND = auto()
    LOR = auto()
    
    # Special
    PREPROCESSOR = auto()
    EOF = auto()

KEYWORDS = {
    "header": TokenType.HEADER,
    "struct": TokenType.STRUCT,
    "typedef": TokenType.TYPEDEF,
    "enum": TokenType.ENUM,
    "error": TokenType.ERROR,
    "parser": TokenType.PARSER,
    "control": TokenType.CONTROL,
    "package": TokenType.PACKAGE,
    "action": TokenType.ACTION,
    "table": TokenType.TABLE,
    "key": TokenType.KEY,
    "actions": TokenType.ACTIONS,
    "default_action": TokenType.DEFAULT_ACTION,
    "size": TokenType.SIZE,
    "state": TokenType.STATE,
    "transition": TokenType.TRANSITION,
    "select": TokenType.SELECT,
    "apply": TokenType.APPLY,
    "extern": TokenType.EXTERN,
    "in": TokenType.IN,
    "out": TokenType.OUT,
    "inout": TokenType.INOUT,
    "bit": TokenType.BIT,
    "varbit": TokenType.VARBIT,
    "int": TokenType.INT,
    "exact": TokenType.EXACT,
    "ternary": TokenType.TERNARY,
    "lpm": TokenType.LPM,
    "range": TokenType.RANGE,
    "if": TokenType.IF,
    "else": TokenType.ELSE,
    "return": TokenType.RETURN,
    "default": TokenType.DEFAULT,
    "true": TokenType.TRUE,
    "false": TokenType.FALSE,
    "void": TokenType.VOID,
}

@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int
    width: Optional[int] = None
    numeric_value: Optional[int] = None

class P4Lexer:
    """Scans and tokenizes P4_16 source programs."""
    
    def __init__(self, source: str, filename: str = "<stdin>"):
        self.source = source
        self.filename = filename
        self.pos = 0
        self.line = 1
        self.column = 1
        self.length = len(source)
        
    def peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        if idx < self.length:
            return self.source[idx]
        return ""
        
    def advance(self) -> str:
        if self.pos < self.length:
            char = self.source[self.pos]
            self.pos += 1
            if char == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            return char
        return ""

    def skip_whitespace_and_comments(self):
        while self.pos < self.length:
            c = self.peek()
            if c in (" ", "\t", "\r", "\n"):
                self.advance()
            elif c == "/" and self.peek(1) == "/":
                # Line comment
                while self.pos < self.length and self.peek() != "\n":
                    self.advance()
            elif c == "/" and self.peek(1) == "*":
                # Block comment
                self.advance()
                self.advance()
                while self.pos < self.length:
                    if self.peek() == "*" and self.peek(1) == "/":
                        self.advance()
                        self.advance()
                        break
                    self.advance()
            elif c == "#":
                # Preprocessor line
                start_line = self.line
                start_col = self.column
                prep_str = ""
                while self.pos < self.length and self.peek() != "\n":
                    prep_str += self.advance()
                return Token(TokenType.PREPROCESSOR, prep_str.strip(), start_line, start_col)
            else:
                break
        return None

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []
        while self.pos < self.length:
            prep = self.skip_whitespace_and_comments()
            if prep:
                tokens.append(prep)
                continue
            if self.pos >= self.length:
                break
                
            start_line = self.line
            start_col = self.column
            c = self.peek()
            
            # Punctuation & operators
            if c == "{":
                tokens.append(Token(TokenType.LBRACE, self.advance(), start_line, start_col))
            elif c == "}":
                tokens.append(Token(TokenType.RBRACE, self.advance(), start_line, start_col))
            elif c == "(":
                tokens.append(Token(TokenType.LPAREN, self.advance(), start_line, start_col))
            elif c == ")":
                tokens.append(Token(TokenType.RPAREN, self.advance(), start_line, start_col))
            elif c == "[":
                tokens.append(Token(TokenType.LBRACKET, self.advance(), start_line, start_col))
            elif c == "]":
                tokens.append(Token(TokenType.RBRACKET, self.advance(), start_line, start_col))
            elif c == ";":
                tokens.append(Token(TokenType.SEMICOLON, self.advance(), start_line, start_col))
            elif c == ":":
                tokens.append(Token(TokenType.COLON, self.advance(), start_line, start_col))
            elif c == ",":
                tokens.append(Token(TokenType.COMMA, self.advance(), start_line, start_col))
            elif c == ".":
                tokens.append(Token(TokenType.DOT, self.advance(), start_line, start_col))
            elif c == "=":
                self.advance()
                if self.peek() == "=":
                    self.advance()
                    tokens.append(Token(TokenType.EQUALS, "==", start_line, start_col))
                else:
                    tokens.append(Token(TokenType.ASSIGN, "=", start_line, start_col))
            elif c == "!":
                self.advance()
                if self.peek() == "=":
                    self.advance()
                    tokens.append(Token(TokenType.NOT_EQUALS, "!=", start_line, start_col))
                else:
                    tokens.append(Token(TokenType.NOT, "!", start_line, start_col))
            elif c == "<":
                self.advance()
                if self.peek() == "<":
                    self.advance()
                    tokens.append(Token(TokenType.LSHIFT, "<<", start_line, start_col))
                elif self.peek() == "=":
                    self.advance()
                    tokens.append(Token(TokenType.LE, "<=", start_line, start_col))
                else:
                    tokens.append(Token(TokenType.LT, "<", start_line, start_col))
            elif c == ">":
                self.advance()
                if self.peek() == ">":
                    self.advance()
                    tokens.append(Token(TokenType.RSHIFT, ">>", start_line, start_col))
                elif self.peek() == "=":
                    self.advance()
                    tokens.append(Token(TokenType.GE, ">=", start_line, start_col))
                else:
                    tokens.append(Token(TokenType.GT, ">", start_line, start_col))
            elif c == "+":
                tokens.append(Token(TokenType.PLUS, self.advance(), start_line, start_col))
            elif c == "-":
                tokens.append(Token(TokenType.MINUS, self.advance(), start_line, start_col))
            elif c == "&":
                self.advance()
                if self.peek() == "&":
                    self.advance()
                    tokens.append(Token(TokenType.LAND, "&&", start_line, start_col))
                else:
                    tokens.append(Token(TokenType.BAND, "&", start_line, start_col))
            elif c == "|":
                self.advance()
                if self.peek() == "|":
                    self.advance()
                    tokens.append(Token(TokenType.LOR, "||", start_line, start_col))
                else:
                    tokens.append(Token(TokenType.BOR, "|", start_line, start_col))
            elif c == "^":
                tokens.append(Token(TokenType.BXOR, self.advance(), start_line, start_col))
            elif c == "~":
                tokens.append(Token(TokenType.BNOT, self.advance(), start_line, start_col))
                
            # Numbers and bit literals (e.g. 16#0800, 48#0, 32#1)
            elif c.isdigit():
                num_str = ""
                while self.pos < self.length and (self.peek().isalnum() or self.peek() == "#"):
                    num_str += self.advance()
                    
                if "#" in num_str:
                    parts = num_str.split("#")
                    w = int(parts[0])
                    v_str = parts[1]
                    val = int(v_str, 16) if any(h in v_str.lower() for h in "abcdef") else int(v_str, 10)
                    tokens.append(Token(TokenType.BIT_LITERAL, num_str, start_line, start_col, width=w, numeric_value=val))
                elif num_str.startswith("0x") or num_str.startswith("0X"):
                    tokens.append(Token(TokenType.HEX_LITERAL, num_str, start_line, start_col, numeric_value=int(num_str, 16)))
                else:
                    tokens.append(Token(TokenType.INT_LITERAL, num_str, start_line, start_col, numeric_value=int(num_str, 10)))
                    
            # Identifiers and keywords
            elif c.isalpha() or c == "_":
                ident_str = ""
                while self.pos < self.length and (self.peek().isalnum() or self.peek() == "_"):
                    ident_str += self.advance()
                    
                tt = KEYWORDS.get(ident_str, TokenType.IDENTIFIER)
                tokens.append(Token(tt, ident_str, start_line, start_col))
            else:
                self.advance()
                
        tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return tokens
