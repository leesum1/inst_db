"""RISC-V disassembler using Capstone with semantic analysis."""

from typing import List, Optional, Set

from inst_db.disassembler.arm64 import DisassemblyResult

try:
    from capstone import (  # type: ignore[import-untyped]
        Cs,
        CS_ARCH_RISCV,
        CS_MODE_RISCV64,
        CS_MODE_RISCVC,
        CS_OP_REG,
    )
except ImportError as exc:
    raise ImportError(
        "Capstone is required for disassembly. Install it with: pip install capstone"
    ) from exc


_RISCV_ABI_TO_X = {
    "zero": "x0",
    "ra": "x1",
    "sp": "x2",
    "gp": "x3",
    "tp": "x4",
    "t0": "x5",
    "t1": "x6",
    "t2": "x7",
    "s0": "x8",
    "fp": "x8",
    "s1": "x9",
    "a0": "x10",
    "a1": "x11",
    "a2": "x12",
    "a3": "x13",
    "a4": "x14",
    "a5": "x15",
    "a6": "x16",
    "a7": "x17",
    "s2": "x18",
    "s3": "x19",
    "s4": "x20",
    "s5": "x21",
    "s6": "x22",
    "s7": "x23",
    "s8": "x24",
    "s9": "x25",
    "s10": "x26",
    "s11": "x27",
    "t3": "x28",
    "t4": "x29",
    "t5": "x30",
    "t6": "x31",
}


class RISCVDisassembler:
    """RISC-V instruction disassembler with register read/write extraction."""

    def __init__(self):
        self.cs = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
        self.cs.detail = True
        self.cs.skipdata = False

    @staticmethod
    def _normalize_reg_name(reg_name: str) -> str:
        name = reg_name.strip().lower()
        if not name:
            return name
        if name.startswith("x") and name[1:].isdigit():
            return name
        if name.startswith("f") and name[1:].isdigit():
            return name
        if name == "pc":
            return name
        return _RISCV_ABI_TO_X.get(name, name)

    def _extract_regs(self, instr) -> tuple[Set[str], Set[str]]:
        regs_read: Set[str] = set()
        regs_write: Set[str] = set()

        reg_operands = []
        for operand in instr.operands:
            if operand.type == CS_OP_REG:
                reg_name = self._normalize_reg_name(self.cs.reg_name(operand.reg))
                if reg_name:
                    reg_operands.append(reg_name)

        if reg_operands:
            regs_write.add(reg_operands[0])
            for reg_name in reg_operands[1:]:
                regs_read.add(reg_name)

        return regs_read, regs_write

    def disassemble(
        self, instruction_bytes: bytes, address: int = 0
    ) -> Optional[DisassemblyResult]:
        try:
            results = list(self.cs.disasm(instruction_bytes, address))
            if not results:
                return None

            instr = results[0]
            full_text = f"{instr.mnemonic} {instr.op_str}".strip()
            regs_read, regs_write = self._extract_regs(instr)

            return DisassemblyResult(
                address=instr.address,
                instruction_bytes=instruction_bytes,
                mnemonic=instr.mnemonic,
                operands=instr.op_str,
                full_text=full_text,
                regs_read=regs_read,
                regs_write=regs_write,
            )
        except Exception as exc:
            print(f"Error disassembling {instruction_bytes.hex()}: {exc}")
            return None

    def disassemble_many(
        self, instruction_bytes: bytes, start_address: int = 0
    ) -> List[DisassemblyResult]:
        results: List[DisassemblyResult] = []

        try:
            for instr in self.cs.disasm(instruction_bytes, start_address):
                full_text = f"{instr.mnemonic} {instr.op_str}".strip()
                regs_read, regs_write = self._extract_regs(instr)
                offset_start = instr.address - start_address
                offset_end = offset_start + instr.size

                results.append(
                    DisassemblyResult(
                        address=instr.address,
                        instruction_bytes=instruction_bytes[offset_start:offset_end],
                        mnemonic=instr.mnemonic,
                        operands=instr.op_str,
                        full_text=full_text,
                        regs_read=regs_read,
                        regs_write=regs_write,
                    )
                )
        except Exception as exc:
            print(f"Error disassembling multiple instructions: {exc}")

        return results
