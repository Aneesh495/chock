"""
Unit tests for P4_16 Lexer, Parser, and AST generation.
"""

import unittest
import os
import glob
from chock.parser import P4Lexer, TokenType, P4Parser, parse_p4_file

class TestP4LexerParser(unittest.TestCase):
    def test_bit_literal_tokenization(self):
        source = "const bit<16> ETHERTYPE_IPV4 = 16#0800; bit<48> mac = 48#0;"
        lexer = P4Lexer(source)
        tokens = lexer.tokenize()
        bit_toks = [t for t in tokens if t.type == TokenType.BIT_LITERAL]
        self.assertEqual(len(bit_toks), 2)
        self.assertEqual(bit_toks[0].width, 16)
        self.assertEqual(bit_toks[0].numeric_value, 0x0800)
        self.assertEqual(bit_toks[1].width, 48)
        self.assertEqual(bit_toks[1].numeric_value, 0)

    def test_header_parsing(self):
        source = """
        header test_hdr_t {
            bit<48> dst;
            bit<48> src;
            bit<16> type;
        }
        """
        lexer = P4Lexer(source)
        parser = P4Parser(lexer.tokenize())
        prog = parser.parse_program()
        self.assertEqual(len(prog.headers), 1)
        self.assertEqual(prog.headers[0].name, "test_hdr_t")
        self.assertEqual(len(prog.headers[0].fields), 3)

    def test_all_p4_files_parseable(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p4_dir = os.path.join(repo_root, "p4")
        p4_files = glob.glob(os.path.join(p4_dir, "**/*.p4"), recursive=True)
        self.assertGreater(len(p4_files), 50)
        
        for f in p4_files:
            prog = parse_p4_file(f)
            self.assertIsNotNone(prog)

if __name__ == "__main__":
    unittest.main()
