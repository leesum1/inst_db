"""QEMU instruction trace parser for execlog plugin output."""

import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple


class QEMUTraceParser:
    """Parse QEMU execlog plugin trace output.

    Expected format:
        0, 0x400580, 0xd503201f, "nop "
        0, 0x1038c, 0x24000ef, "jal ra,36 # 0x103b0"

    The first 3 comma-separated fields are:
      - CPU ID (ignored)
      - Program counter (hex)
      - Instruction word (hex, possibly without leading zeros)

    Architecture controls instruction width conversion:
      - arm64: always 4-byte fixed-width instructions
      - riscv64: infer 2-byte vs 4-byte by instruction low bits
    """

    _MEMORY_PATTERN = re.compile(
        r"m=(?P<kind>[LS])(?P<size>\d+),\s*"
        r"v=0x(?P<value>[0-9a-fA-F?]+),\s*"
        r"va=0x(?P<va>[0-9a-fA-F]+)"
        r"(?:,\s*pa=0x(?P<pa>[0-9a-fA-F]+))?"
        r"(?:,\s*dev=[^,]+)?"
    )

    def __init__(self, trace_file: str, architecture: str = "arm64"):
        """Initialize parser.

        Args:
            trace_file: Path to QEMU trace file
            architecture: "arm64" or "riscv64"
        """
        self.trace_file = Path(trace_file)
        if not self.trace_file.exists():
            raise FileNotFoundError(f"Trace file not found: {trace_file}")

        normalized_arch = architecture.strip().lower()
        if normalized_arch not in {"arm64", "riscv64"}:
            raise ValueError(
                f"Unsupported architecture: {architecture}. Supported: arm64, riscv64"
            )
        self.architecture = normalized_arch

    def parse(self) -> Iterator[Tuple[int, bytes]]:
        """Parse trace file and yield (pc, instruction_bytes) tuples.

        Yields:
            (pc, instruction_bytes): PC address and instruction bytes in correct byte order
        """
        for pc, instruction_bytes, _, _ in self.parse_with_details():
            yield (pc, instruction_bytes)

    def parse_with_details(
        self,
    ) -> Iterator[Tuple[int, bytes, Optional[Dict[str, int]], List[dict]]]:
        """Parse trace file and include memory operations from execlog fields."""
        with open(self.trace_file, "r") as file_obj:
            for line in file_obj:
                parsed = self._parse_execlog_line(line)
                if parsed is None:
                    continue
                pc, instruction_bytes, memory_operations = parsed
                yield (pc, instruction_bytes, None, memory_operations)

    def parse_with_registers(
        self,
    ) -> Iterator[Tuple[int, bytes, Optional[Dict[str, int]]]]:
        """Yield register-state tuples for interface compatibility.

        execlog does not include architectural register dumps in this project,
        so register_state is always None.
        """
        for pc, instruction_bytes, register_state, _ in self.parse_with_details():
            yield (pc, instruction_bytes, register_state)

    def _parse_execlog_line(self, line: str) -> Optional[Tuple[int, bytes, List[dict]]]:
        text = line.strip()
        if not text:
            return None

        fields = text.split(",", 3)
        if len(fields) < 3:
            return None

        pc_text = fields[1].strip()
        insn_text = fields[2].strip()

        try:
            pc = int(pc_text, 16)
        except ValueError:
            return None

        instruction_bytes = self._instruction_hex_to_bytes(insn_text)
        if instruction_bytes is None:
            return None

        memory_operations = self._parse_memory_operations(text)
        return pc, instruction_bytes, memory_operations

    def _parse_memory_operations(self, text: str) -> List[dict]:
        memory_operations: List[dict] = []

        for matched in self._MEMORY_PATTERN.finditer(text):
            kind = matched.group("kind")
            size_text = matched.group("size")
            value_text = matched.group("value")
            va_text = matched.group("va")
            pa_text = matched.group("pa")

            try:
                data_length = int(size_text)
                virtual_address = int(va_text, 16)
                physical_address = int(pa_text, 16) if pa_text else virtual_address
            except ValueError:
                continue

            memory_operations.append(
                {
                    "operation_type": "READ" if kind == "L" else "WRITE",
                    "virtual_address": virtual_address,
                    "physical_address": physical_address,
                    "data_length": data_length,
                    "memory_value": f"0x{value_text.lower()}",
                }
            )

        return memory_operations

    def _instruction_hex_to_bytes(self, instruction_hex: str) -> Optional[bytes]:
        text = instruction_hex.strip().lower()
        if text.startswith("0x"):
            text = text[2:]

        if not text:
            return None

        try:
            instruction_value = int(text, 16)
        except ValueError:
            return None

        try:
            if self.architecture == "arm64":
                return instruction_value.to_bytes(4, byteorder="little", signed=False)

            # RISC-V instruction length is encoded in low bits:
            #   - low2 != 0b11 -> 16-bit compressed
            #   - low2 == 0b11 -> 32-bit standard
            # execlog may omit leading zeros, so width cannot be inferred
            # from hex text length.
            byte_width = 2 if (instruction_value & 0b11) != 0b11 else 4
            if instruction_value > 0xFFFFFFFF:
                return None

            return instruction_value.to_bytes(
                byte_width, byteorder="little", signed=False
            )
        except OverflowError:
            return None


class TraceImporter:
    """Import QEMU trace into instruction database."""

    def __init__(self, trace_file: str, db_path: str, architecture: str = "arm64"):
        """Initialize importer.

        Args:
            trace_file: Path to QEMU trace file
            db_path: Path to SQLite database (will be created if doesn't exist)
            architecture: "arm64" or "riscv64"
        """
        self.parser = QEMUTraceParser(trace_file, architecture=architecture)
        self.db_path = db_path
        self.architecture = architecture

    def import_trace(self, max_instructions: Optional[int] = None) -> int:
        """Import trace into database.

        Args:
            max_instructions: Maximum number of instructions to import (None for all)

        Returns:
            Number of instructions imported
        """
        from inst_db.api import InstructionDB

        # Convert file path to SQLite URL if needed
        db_url = self.db_path
        if not db_url.startswith("sqlite:"):
            db_url = f"sqlite:///{self.db_path}"

        db = InstructionDB(db_url, architecture=self.architecture)

        count = 0
        sequence_id = 1

        with db.db_manager.get_session() as session:
            for (
                pc,
                instruction_bytes,
                register_state,
                memory_operations,
            ) in self.parser.parse_with_details():
                if max_instructions is not None and count >= max_instructions:
                    break

                try:
                    db.add_instruction(
                        pc=pc,
                        instruction_code=instruction_bytes,
                        sequence_id=sequence_id,
                        register_state=register_state,
                        memory_operations=memory_operations,
                        session=session,
                        flush=False,
                    )
                    count += 1
                    sequence_id += 1

                    if count % 1000 == 0:
                        session.flush()
                        print(f"Imported {count} instructions...")

                except Exception as exc:
                    print(f"Warning: Failed to import instruction at PC={pc:#x}: {exc}")
                    continue

        if db.db_manager.use_in_memory:
            db.db_manager.save_to_file(self.db_path)

        print(f"Successfully imported {count} instructions")
        return count
