"""ARM64 disassembler using Capstone."""

from typing import Tuple, List, Optional
from dataclasses import dataclass

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
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


class ARM64Disassembler:
    """ARM64 instruction disassembler using Capstone."""

    def __init__(self):
        """Initialize the ARM64 disassembler."""
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        # Don't skip data
        self.cs.skipdata = False

    def disassemble(
        self, instruction_bytes: bytes, address: int = 0
    ) -> Optional[DisassemblyResult]:
        """
        Disassemble a single instruction.

        Args:
            instruction_bytes: Raw instruction bytes (usually 4 bytes for ARM64)
            address: Address of the instruction (optional, for context)

        Returns:
            DisassemblyResult object, or None if disassembly fails
        """
        try:
            # Disassemble the bytes
            results = list(self.cs.disasm(instruction_bytes, address))

            if not results:
                return None

            instr = results[0]
            full_text = f"{instr.mnemonic} {instr.op_str}".strip()

            return DisassemblyResult(
                address=instr.address,
                instruction_bytes=instruction_bytes,
                mnemonic=instr.mnemonic,
                operands=instr.op_str,
                full_text=full_text,
            )
        except Exception as e:
            print(f"Error disassembling {instruction_bytes.hex()}: {e}")
            return None

    def disassemble_many(
        self, instruction_bytes: bytes, start_address: int = 0
    ) -> List[DisassemblyResult]:
        """
        Disassemble multiple consecutive instructions.

        Args:
            instruction_bytes: Raw bytes containing multiple instructions
            start_address: Starting address

        Returns:
            List of DisassemblyResult objects
        """
        results = []
        try:
            for instr in self.cs.disasm(instruction_bytes, start_address):
                full_text = f"{instr.mnemonic} {instr.op_str}".strip()
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
