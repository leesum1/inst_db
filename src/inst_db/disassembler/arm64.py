"""ARM64 disassembler using Capstone with semantic analysis."""

from typing import Tuple, List, Optional, Set
from dataclasses import dataclass

from inst_db.utils import normalize_reg_name

try:
    from capstone import (
        Cs,
        CS_ARCH_ARM64,
        CS_MODE_ARM,
        CS_OP_REG,
        CS_OP_FP,
        CS_AC_READ,
        CS_AC_WRITE,
    )
except ImportError:
    raise ImportError(
        "Capstone is required for disassembly. Install it with: pip install capstone"
    )


@dataclass
class DisassemblyResult:
    """Result of disassembling an instruction."""

    address: int
    instruction_bytes: bytes
    mnemonic: str
    operands: str
    full_text: str  # "mnemonic operands"
    regs_read: Set[str]  # 隐式和显式读取的寄存器
    regs_write: Set[str]  # 隐式和显式写入的寄存器





class ARM64Disassembler:
    """ARM64 instruction disassembler using Capstone with semantic information."""

    def __init__(self):
        """Initialize the ARM64 disassembler with detail mode enabled."""
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        # 启用详细模式以获取隐式寄存器读写信息
        self.cs.detail = True
        # Don't skip data
        self.cs.skipdata = False

    def disassemble(
        self, instruction_bytes: bytes, address: int = 0
    ) -> Optional[DisassemblyResult]:
        """
        Disassemble a single instruction with semantic analysis.

        Uses Capstone to extract register read/write semantics by analyzing operand access flags.

        Args:
            instruction_bytes: Raw instruction bytes (usually 4 bytes for ARM64)
            address: Address of the instruction (optional, for context)

        Returns:
            DisassemblyResult object with register dependencies, or None if disassembly fails
        """
        try:
            # Disassemble the bytes
            results = list(self.cs.disasm(instruction_bytes, address))

            if not results:
                return None

            instr = results[0]
            full_text = f"{instr.mnemonic} {instr.op_str}".strip()

            # 通过分析操作数来提取寄存器依赖
            regs_read = set()
            regs_write = set()

            for operand in instr.operands:
                # 处理寄存器操作数（整数寄存器和浮点寄存器）
                if operand.type == CS_OP_REG or operand.type == CS_OP_FP:
                    reg_name = normalize_reg_name(self.cs.reg_name(operand.reg))
                    if not reg_name:
                        continue

                    # 根据访问标志（CS_AC_READ, CS_AC_WRITE）分类
                    access = operand.access
                    if access & CS_AC_READ:
                        regs_read.add(reg_name)
                    if access & CS_AC_WRITE:
                        regs_write.add(reg_name)

            return DisassemblyResult(
                address=instr.address,
                instruction_bytes=instruction_bytes,
                mnemonic=instr.mnemonic,
                operands=instr.op_str,
                full_text=full_text,
                regs_read=regs_read,
                regs_write=regs_write,
            )
        except Exception as e:
            print(f"Error disassembling {instruction_bytes.hex()}: {e}")
            return None

    def disassemble_many(
        self, instruction_bytes: bytes, start_address: int = 0
    ) -> List[DisassemblyResult]:
        """
        Disassemble multiple consecutive instructions with semantic analysis.

        Args:
            instruction_bytes: Raw bytes containing multiple instructions
            start_address: Starting address

        Returns:
            List of DisassemblyResult objects with register dependencies
        """
        results = []
        try:
            for instr in self.cs.disasm(instruction_bytes, start_address):
                full_text = f"{instr.mnemonic} {instr.op_str}".strip()

                # 通过分析操作数来提取寄存器依赖
                regs_read = set()
                regs_write = set()

                for operand in instr.operands:
                    # 处理寄存器操作数（整数寄存器和浮点寄存器）
                    if operand.type == CS_OP_REG or operand.type == CS_OP_FP:
                        reg_name = normalize_reg_name(self.cs.reg_name(operand.reg))
                        if not reg_name:
                            continue

                        access = operand.access
                        if access & CS_AC_READ:
                            regs_read.add(reg_name)
                        if access & CS_AC_WRITE:
                            regs_write.add(reg_name)

                results.append(
                    DisassemblyResult(
                        address=instr.address,
                        instruction_bytes=instruction_bytes[
                            instr.address - start_address : instr.address
                            - start_address
                            + instr.size
                        ],
                        mnemonic=instr.mnemonic,
                        operands=instr.op_str,
                        full_text=full_text,
                        regs_read=regs_read,
                        regs_write=regs_write,
                    )
                )
        except Exception as e:
            print(f"Error disassembling multiple instructions: {e}")

        return results



    @staticmethod
    def bytes_to_hex(data: bytes) -> str:
        """Convert bytes to hex string."""
        return data.hex()

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert hex string to bytes."""
        return bytes.fromhex(hex_str)
