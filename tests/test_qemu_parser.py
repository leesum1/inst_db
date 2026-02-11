"""Tests for QEMU execlog parser and importer."""

import tempfile
from pathlib import Path

from inst_db.api import InstructionDB
from inst_db.parsers.qemu_trace import QEMUTraceParser, TraceImporter


class TestQEMUExeclogParser:
    """Test QEMU execlog parser functionality."""

    def test_parse_arm64_execlog_file(self):
        trace_content = """0, 0x400580, 0xd28000a0, \"mov x0, #5\"
0, 0x400584, 0xd2800141, \"mov x1, #10\"
0, 0x400588, 0x8b010002, \"add x2, x0, x1\"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(trace_content)
            trace_file = f.name

        try:
            parser = QEMUTraceParser(trace_file, architecture="arm64")
            results = list(parser.parse())

            assert len(results) == 3
            assert results[0][0] == 0x400580
            assert results[1][0] == 0x400584
            assert results[2][0] == 0x400588

            assert results[0][1].hex() == "a00080d2"
            assert results[1][1].hex() == "410180d2"
            assert results[2][1].hex() == "0200018b"
        finally:
            Path(trace_file).unlink()

    def test_parse_riscv_execlog_file(self):
        trace_content = """0, 0x1038c, 0x24000ef, \"jal ra,36\"
0, 0x10390, 0x87aa, \"mv a5,a0\"
0, 0x10392, 0x517, \"auipc a0,0\"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(trace_content)
            trace_file = f.name

        try:
            parser = QEMUTraceParser(trace_file, architecture="riscv64")
            results = list(parser.parse())

            assert len(results) == 3
            assert results[0][0] == 0x1038C
            assert results[1][0] == 0x10390
            assert results[2][0] == 0x10392

            assert results[0][1].hex() == "ef004002"
            assert results[1][1].hex() == "aa87"
            assert results[2][1].hex() == "17050000"
        finally:
            Path(trace_file).unlink()

    def test_skip_non_execlog_lines(self):
        trace_content = """noise line
0, 0x400580, 0xd503201f, \"nop\"
malformed, line
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(trace_content)
            trace_file = f.name

        try:
            parser = QEMUTraceParser(trace_file, architecture="arm64")
            results = list(parser.parse())

            assert len(results) == 1
            assert results[0][0] == 0x400580
            assert results[0][1].hex() == "1f2003d5"
        finally:
            Path(trace_file).unlink()

    def test_parse_with_registers_returns_none_state(self):
        trace_content = '0, 0x400580, 0xd503201f, "nop"\n'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(trace_content)
            trace_file = f.name

        try:
            parser = QEMUTraceParser(trace_file, architecture="arm64")
            results = list(parser.parse_with_registers())
            assert len(results) == 1
            assert results[0][2] is None
        finally:
            Path(trace_file).unlink()


class TestTraceImporter:
    """Test execlog importer functionality."""

    def test_import_arm64_trace(self):
        trace_content = """0, 0x400580, 0xd28000a0, \"mov x0, #5\"
0, 0x400584, 0xd2800141, \"mov x1, #10\"
0, 0x400588, 0x8b010002, \"add x2, x0, x1\"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(trace_content)
            trace_file = f.name

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_file = f.name

        try:
            importer = TraceImporter(trace_file, db_file, architecture="arm64")
            count = importer.import_trace()

            assert count == 3

            db = InstructionDB(f"sqlite:///{db_file}", architecture="arm64")
            instructions = db.get_instruction_trace()

            assert len(instructions) == 3
            assert instructions[0].pc == "0x0000000000400580"
            assert instructions[1].pc == "0x0000000000400584"
            assert instructions[2].pc == "0x0000000000400588"
            assert "mov" in instructions[0].disassembly
        finally:
            Path(trace_file).unlink()
            Path(db_file).unlink()

    def test_import_riscv_trace(self):
        trace_content = """0, 0x1038c, 0x24000ef, \"jal ra,36\"
0, 0x10390, 0x87aa, \"mv a5,a0\"
0, 0x10392, 0x517, \"auipc a0,0\"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(trace_content)
            trace_file = f.name

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_file = f.name

        try:
            importer = TraceImporter(trace_file, db_file, architecture="riscv64")
            count = importer.import_trace()

            assert count == 3

            db = InstructionDB(f"sqlite:///{db_file}", architecture="riscv64")
            instructions = db.get_instruction_trace()
            assert len(instructions) == 3
            assert instructions[0].pc == "0x000000000001038c"
            assert instructions[1].pc == "0x0000000000010390"
        finally:
            Path(trace_file).unlink()
            Path(db_file).unlink()

    def test_import_with_limit(self):
        trace_content = """0, 0x400580, 0xd28000a0, \"mov x0, #5\"
0, 0x400584, 0xd2800141, \"mov x1, #10\"
0, 0x400588, 0x8b010002, \"add x2, x0, x1\"
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(trace_content)
            trace_file = f.name

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_file = f.name

        try:
            importer = TraceImporter(trace_file, db_file, architecture="arm64")
            count = importer.import_trace(max_instructions=2)

            assert count == 2

            db = InstructionDB(f"sqlite:///{db_file}", architecture="arm64")
            instructions = db.get_instruction_trace()
            assert len(instructions) == 2
        finally:
            Path(trace_file).unlink()
            Path(db_file).unlink()
