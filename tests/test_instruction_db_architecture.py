"""Tests for InstructionDB architecture selection."""

import pytest

from inst_db.api import InstructionDB
from inst_db.disassembler import ARM64Disassembler, RISCVDisassembler


def test_instruction_db_defaults_to_arm64():
    db = InstructionDB("sqlite:///:memory:")
    assert isinstance(db.disassembler, ARM64Disassembler)


def test_instruction_db_supports_riscv64():
    db = InstructionDB("sqlite:///:memory:", architecture="riscv64")
    assert isinstance(db.disassembler, RISCVDisassembler)


def test_instruction_db_rejects_unknown_architecture():
    with pytest.raises(ValueError):
        InstructionDB("sqlite:///:memory:", architecture="mips")


def test_instruction_db_uses_file_sqlite_database(tmp_path):
    db_path = tmp_path / "persist.db"
    db1 = InstructionDB(f"sqlite:///{db_path}")
    db1.add_instruction(
        pc=0x1000, instruction_code=bytes.fromhex("13050000"), sequence_id=1
    )

    db2 = InstructionDB(f"sqlite:///{db_path}")
    trace = db2.get_instruction_trace()
    assert len(trace) == 1
    assert trace[0].pc == "0x0000000000001000"
