"""Tests for RISC-V disassembler support."""

from inst_db.disassembler import RISCVDisassembler


class TestRISCVDisassembler:
    """Test cases for RISC-V disassembly behavior."""

    def test_disassemble_rv64_instruction(self):
        """Should decode a 32-bit RV64 instruction."""
        disassembler = RISCVDisassembler()

        result = disassembler.disassemble(bytes.fromhex("93001000"), 0x1000)

        assert result is not None
        assert result.address == 0x1000
        assert result.mnemonic == "addi"
        assert "ra" in result.operands or "x1" in result.operands

    def test_disassemble_compressed_instruction(self):
        """Should decode a 16-bit compressed instruction."""
        disassembler = RISCVDisassembler()

        result = disassembler.disassemble(bytes.fromhex("0100"), 0x1000)

        assert result is not None
        assert result.mnemonic == "c.nop"

    def test_extract_register_dependencies(self):
        """Should extract read/write register sets for simple ALU ops."""
        disassembler = RISCVDisassembler()

        result = disassembler.disassemble(bytes.fromhex("b3003100"), 0x1000)

        assert result is not None
        assert any(reg in result.regs_write for reg in ("ra", "x1"))
        assert any(reg in result.regs_read for reg in ("sp", "x2"))
        assert any(reg in result.regs_read for reg in ("gp", "x3"))
