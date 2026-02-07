"""Tests for QEMU trace parser."""

import pytest
import tempfile
from pathlib import Path

from inst_db.parsers.qemu_trace import QEMUTraceParser, TraceImporter
from inst_db.api import InstructionDB


class TestQEMUTraceParser:
    """Test QEMU trace parser functionality."""

    def test_parse_pc(self):
        """Test PC address parsing."""
        parser = QEMUTraceParser.__new__(QEMUTraceParser)
        
        assert parser._parse_pc("0x004000d4:") == 0x4000d4
        assert parser._parse_pc("0x0000000000400078:") == 0x400078
        assert parser._parse_pc("invalid") is None

    def test_parse_instructions(self):
        """Test instruction parsing."""
        parser = QEMUTraceParser.__new__(QEMUTraceParser)
        
        # Test with known QEMU output
        hex_data = "a00080d2410180d20200018b"
        instructions = list(parser._parse_instructions(hex_data))
        
        assert len(instructions) == 3
        assert instructions[0].hex() == "a00080d2"  # mov x0, #5
        assert instructions[1].hex() == "410180d2"  # mov x1, #10
        assert instructions[2].hex() == "0200018b"  # add x2, x0, x1

    def test_parse_incomplete_instruction(self):
        """Test handling of incomplete instructions."""
        parser = QEMUTraceParser.__new__(QEMUTraceParser)
        
        # Incomplete instruction (< 8 chars)
        hex_data = "a00080d2410180"
        instructions = list(parser._parse_instructions(hex_data))
        
        assert len(instructions) == 1  # Only first complete instruction

    def test_parse_file(self):
        """Test parsing a complete trace file."""
        # Create a temporary trace file
        trace_content = """----------------
IN: 
0x004000d4:  
OBJD-T: a00080d2410180d20200018b
OBJD-T: ff4300d1e20300f9
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(trace_content)
            trace_file = f.name
        
        try:
            parser = QEMUTraceParser(trace_file)
            results = list(parser.parse())
            
            assert len(results) == 5
            
            # Check PC addresses
            assert results[0][0] == 0x4000d4
            assert results[1][0] == 0x4000d8  # PC + 4
            assert results[2][0] == 0x4000dc  # PC + 8
            assert results[3][0] == 0x4000e0  # PC + 12
            assert results[4][0] == 0x4000e4  # PC + 16
            
            # Check instruction bytes
            assert results[0][1].hex() == "a00080d2"
            assert results[1][1].hex() == "410180d2"
            assert results[2][1].hex() == "0200018b"
        
        finally:
            Path(trace_file).unlink()

    def test_parse_multiple_translation_blocks(self):
        """Test parsing multiple translation blocks."""
        trace_content = """----------------
IN: 
0x004000d4:  
OBJD-T: a00080d2

----------------
IN: 
0x004000d8:  
OBJD-T: 410180d2
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(trace_content)
            trace_file = f.name
        
        try:
            parser = QEMUTraceParser(trace_file)
            results = list(parser.parse())
            
            assert len(results) == 2
            assert results[0][0] == 0x4000d4
            assert results[1][0] == 0x4000d8
        
        finally:
            Path(trace_file).unlink()


class TestTraceImporter:
    """Test trace importer functionality."""

    def test_import_trace(self):
        """Test importing trace into database."""
        # Create a simple trace file
        trace_content = """----------------
IN: 
0x004000d4:  
OBJD-T: a00080d2410180d20200018b
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(trace_content)
            trace_file = f.name
        
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_file = f.name
        
        try:
            # Import trace
            importer = TraceImporter(trace_file, db_file)
            count = importer.import_trace()
            
            assert count == 3
            
            # Verify database contents
            db = InstructionDB(f"sqlite:///{db_file}")
            instructions = db.get_instruction_trace()
            
            assert len(instructions) == 3
            assert instructions[0].pc == 0x4000d4
            assert instructions[1].pc == 0x4000d8
            assert instructions[2].pc == 0x4000dc
            
            # Check disassembly
            assert "mov" in instructions[0].disassembly
            assert "x0" in instructions[0].disassembly
            
            # Check register dependencies
            deps = db.get_register_dependencies(instructions[0].sequence_id)
            writes = [d.register_name for d in deps if d.is_dst]
            assert "x0" in writes
        
        finally:
            Path(trace_file).unlink()
            Path(db_file).unlink()

    def test_import_with_limit(self):
        """Test importing with max_instructions limit."""
        trace_content = """----------------
IN: 
0x004000d4:  
OBJD-T: a00080d2410180d20200018bff4300d1
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(trace_content)
            trace_file = f.name
        
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_file = f.name
        
        try:
            importer = TraceImporter(trace_file, db_file)
            count = importer.import_trace(max_instructions=2)
            
            assert count == 2
            
            db = InstructionDB(f"sqlite:///{db_file}")
            instructions = db.get_instruction_trace()
            assert len(instructions) == 2
        
        finally:
            Path(trace_file).unlink()
            Path(db_file).unlink()
