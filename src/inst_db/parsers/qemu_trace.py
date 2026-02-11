"""QEMU instruction trace parser for -d in_asm output."""

import re
from typing import Iterator, Tuple, Optional, Dict
from pathlib import Path


class QEMUTraceParser:
    """Parse QEMU -d in_asm trace output.

    Expected format:
        ----------------
        IN: [function_name]
        0x004000d4:
        OBJD-T: a00080d2410180d20200018b...
        OBJD-T: ...continuation...

    The OBJD-T lines contain instruction bytes in little-endian format.
    Each 8 hex characters (4 bytes) represents one ARM64 instruction.
    """

    def __init__(self, trace_file: str):
        """Initialize parser.

        Args:
            trace_file: Path to QEMU trace file
        """
        self.trace_file = Path(trace_file)
        if not self.trace_file.exists():
            raise FileNotFoundError(f"Trace file not found: {trace_file}")

    def parse(self) -> Iterator[Tuple[int, bytes]]:
        """Parse trace file and yield (pc, instruction_bytes) tuples.

        Yields:
            (pc, instruction_bytes): PC address and instruction bytes in correct byte order
        """
        with open(self.trace_file, "r") as f:
            lines = f.readlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Look for PC address line: "0x004000d4:"
            if line.startswith("0x") and line.endswith(":"):
                pc = self._parse_pc(line)
                if pc is None:
                    i += 1
                    continue

                # Collect all OBJD-T lines
                i += 1
                hex_data = ""
                while i < len(lines) and lines[i].strip().startswith("OBJD-T:"):
                    hex_data += lines[i].strip()[7:].strip()  # Remove "OBJD-T:" prefix
                    i += 1

                # Parse instructions from collected hex data
                if hex_data:
                    for instruction_bytes in self._parse_instructions(hex_data):
                        yield (pc, instruction_bytes)
                        pc += 4  # ARM64 instructions are 4 bytes
                continue

            i += 1

    def parse_with_registers(
        self,
    ) -> Iterator[Tuple[int, bytes, Optional[Dict[str, int]]]]:
        """Parse trace file and yield (pc, instruction_bytes, register_state) tuples.

        register_state is only available when the trace is generated with:
            -d in_asm,exec,cpu,nochain -one-insn-per-tb
        """
        with open(self.trace_file, "r") as f:
            lines = f.readlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("0x") and line.endswith(":"):
                pc = self._parse_pc(line)
                if pc is None:
                    i += 1
                    continue

                i += 1
                hex_data = ""
                while i < len(lines) and lines[i].strip().startswith("OBJD-T:"):
                    hex_data += lines[i].strip()[7:].strip()
                    i += 1

                registers, i = self._parse_register_dump(lines, i)

                if hex_data:
                    for instruction_bytes in self._parse_instructions(hex_data):
                        yield (pc, instruction_bytes, registers)
                        pc += 4
                continue

            i += 1

    def _parse_pc(self, line: str) -> Optional[int]:
        """Parse PC address from line like '0x004000d4:'.

        Args:
            line: Line containing PC address

        Returns:
            PC address as integer, or None if parsing fails
        """
        try:
            # Remove trailing colon and parse hex
            pc_str = line.rstrip(":")
            return int(pc_str, 16)
        except ValueError:
            return None

    def _parse_instructions(self, hex_data: str) -> Iterator[bytes]:
        """Parse instruction bytes from hex data.

        QEMU outputs instructions in little-endian format (ARM64 native byte order).
        We can use them directly without any conversion.

        Args:
            hex_data: Concatenated hex string from OBJD-T lines

        Yields:
            Instruction bytes ready for Capstone
        """
        # Split into 8-character chunks (4 bytes per instruction)
        for i in range(0, len(hex_data), 8):
            if i + 8 > len(hex_data):
                # Incomplete instruction, skip
                break

            instruction_hex = hex_data[i : i + 8]

            try:
                # No conversion needed - QEMU output is already correct
                instruction_bytes = bytes.fromhex(instruction_hex)
                yield instruction_bytes
            except ValueError:
                # Invalid hex data, skip
                continue

    def _parse_register_dump(
        self, lines: list, start_index: int
    ) -> Tuple[Optional[Dict[str, int]], int]:
        i = start_index
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("Trace "):
                i += 1
                registers: Dict[str, int] = {}
                while i < len(lines):
                    reg_line = lines[i].strip()
                    if reg_line.startswith("PSTATE="):
                        i += 1
                        break
                    for reg_name, value in self._reg_pairs(reg_line):
                        registers[reg_name] = int(value, 16)
                    i += 1
                return registers, i

            if line.startswith("----------------"):
                break
            if line.startswith("0x") and line.endswith(":"):
                break
            i += 1

        return None, i

    @staticmethod
    def _reg_pairs(line: str) -> Iterator[Tuple[str, str]]:
        for match in re.findall(r"(X\d{2}|SP|PC)=([0-9A-Fa-f]+)", line):
            name, value = match
            yield QEMUTraceParser._normalize_reg_name(name), value

    @staticmethod
    def _normalize_reg_name(name: str) -> str:
        if name == "SP":
            return "sp"
        if name == "PC":
            return "pc"
        if name.startswith("X"):
            return f"x{int(name[1:])}"
        return name.lower()


class TraceImporter:
    """Import QEMU trace into instruction database."""

    def __init__(self, trace_file: str, db_path: str):
        """Initialize importer.

        Args:
            trace_file: Path to QEMU trace file
            db_path: Path to SQLite database (will be created if doesn't exist)
        """
        self.parser = QEMUTraceParser(trace_file)
        self.db_path = db_path

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

        db = InstructionDB(db_url)

        count = 0
        sequence_id = 1

        with db.db_manager.get_session() as session:
            for (
                pc,
                instruction_bytes,
                register_state,
            ) in self.parser.parse_with_registers():
                if max_instructions and count >= max_instructions:
                    break

                try:
                    db.add_instruction(
                        pc=pc,
                        instruction_code=instruction_bytes,
                        sequence_id=sequence_id,
                        register_state=register_state,
                        session=session,
                        flush=False,
                    )
                    count += 1
                    sequence_id += 1

                    if count % 1000 == 0:
                        session.flush()
                        print(f"Imported {count} instructions...")

                except Exception as e:
                    print(f"Warning: Failed to import instruction at PC={pc:#x}: {e}")
                    continue

        if db.db_manager.use_in_memory:
            db.db_manager.save_to_file(self.db_path)

        print(f"Successfully imported {count} instructions")
        return count
