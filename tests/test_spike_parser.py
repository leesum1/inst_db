"""Tests for Spike commit log parser and importer."""

import tempfile
from pathlib import Path

from inst_db.parsers.spike_trace import SpikeCommitLogParser, SpikeTraceImporter
from inst_db.api import InstructionDB


class TestSpikeCommitLogParser:
    def test_parse_variant_with_core_prefix(self):
        content = (
            "core   0: 0x0000000080000000 (0x00000513) addi a0, zero, 0\n"
            "core   0: 0x0000000080000004 (0x00100593) addi a1, zero, 1\n"
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(content)
            trace_path = f.name

        try:
            parser = SpikeCommitLogParser(trace_path)
            parsed = list(parser.parse())
            assert len(parsed) == 2
            assert parsed[0][0] == 0x80000000
            assert parsed[0][1].hex() == "13050000"
            assert parsed[1][0] == 0x80000004
            assert parsed[1][1].hex() == "93051000"
        finally:
            Path(trace_path).unlink()

    def test_parse_variant_without_core_prefix(self):
        content = "0x0000000080000010 (0x0001) c.nop\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(content)
            trace_path = f.name

        try:
            parser = SpikeCommitLogParser(trace_path)
            parsed = list(parser.parse())
            assert len(parsed) == 1
            assert parsed[0][0] == 0x80000010
            assert parsed[0][1].hex() == "0100"
        finally:
            Path(trace_path).unlink()

    def test_parse_register_writeback(self):
        content = (
            "core   0: 0x0000000080000000 (0x00000513) addi a0, zero, 0\n"
            "core   0: 3 0x0000000000000000\n"
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(content)
            trace_path = f.name

        try:
            parser = SpikeCommitLogParser(trace_path)
            parsed = list(parser.parse())
            assert len(parsed) == 1
            _, _, _, reg_state = parsed[0]
            assert reg_state is not None
            assert reg_state["x3"] == 0
        finally:
            Path(trace_path).unlink()

    def test_parse_extracts_core_id(self):
        content = "core   9: 0x0000000080000000 (0x00000513) addi a0, zero, 0\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(content)
            trace_path = f.name

        try:
            parser = SpikeCommitLogParser(trace_path)
            parsed = list(parser.parse())
            assert len(parsed) == 1
            assert parsed[0][2] == 9
        finally:
            Path(trace_path).unlink()


class TestSpikeTraceImporter:
    def test_import_spike_trace(self):
        content = (
            "core   0: 0x0000000080000000 (0x00000513) addi a0, zero, 0\n"
            "core   1: 0x0000000080000004 (0x00100593) addi a1, zero, 1\n"
            "core   2: 0x0000000080000008 (0x0001) c.nop\n"
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(content)
            trace_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            importer = SpikeTraceImporter(trace_path, db_path)
            count = importer.import_trace()
            assert count == 3

            db = InstructionDB(f"sqlite:///{db_path}", architecture="riscv64")
            instructions = db.get_instruction_trace()
            assert len(instructions) == 3
            assert instructions[0].pc == "0x0000000080000000"
            assert instructions[1].pc == "0x0000000080000004"
            assert instructions[0].core_id == 0
            assert instructions[1].core_id == 1
            assert instructions[2].core_id == 2
            assert ("addi" in instructions[0].disassembly) or (
                "mv" in instructions[0].disassembly
            )
        finally:
            Path(trace_path).unlink()
            Path(db_path).unlink()

    def test_import_with_limit(self):
        content = (
            "core   0: 0x0000000080000000 (0x00000513) addi a0, zero, 0\n"
            "core   0: 0x0000000080000004 (0x00100593) addi a1, zero, 1\n"
            "core   0: 0x0000000080000008 (0x0001) c.nop\n"
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(content)
            trace_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            importer = SpikeTraceImporter(trace_path, db_path)
            count = importer.import_trace(max_instructions=2)
            assert count == 2

            db = InstructionDB(f"sqlite:///{db_path}", architecture="riscv64")
            instructions = db.get_instruction_trace()
            assert len(instructions) == 2
        finally:
            Path(trace_path).unlink()
            Path(db_path).unlink()
