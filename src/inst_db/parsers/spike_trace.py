"""Spike commit log parser and importer for RISC-V traces."""

import re
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple


class SpikeCommitLogParser:
    """Parse Spike `--log-commits` text output."""

    _INSTRUCTION_PATTERNS = (
        re.compile(
            r"^\s*core\s+(\d+):\s*0x([0-9a-fA-F]+)\s*\(0x([0-9a-fA-F]+)\)"
        ),
        re.compile(r"^\s*0x([0-9a-fA-F]+)\s*\(0x([0-9a-fA-F]+)\)"),
    )

    _REG_WRITE_PATTERN = re.compile(r"^\s*core\s+\d+:\s*(\d+)\s*0x([0-9a-fA-F]+)\s*$")

    def __init__(self, trace_file: str):
        self.trace_file = Path(trace_file)
        if not self.trace_file.exists():
            raise FileNotFoundError(f"Trace file not found: {trace_file}")

    @staticmethod
    def _to_instruction_bytes(instruction_hex: str) -> Optional[bytes]:
        text = instruction_hex.lower().strip()
        if text.startswith("0x"):
            text = text[2:]

        try:
            value = int(text, 16)
        except ValueError:
            return None

        if len(text) <= 4:
            return value.to_bytes(2, byteorder="little", signed=False)

        return value.to_bytes(4, byteorder="little", signed=False)

    @staticmethod
    def _normalize_reg_name(index: int) -> str:
        return f"x{index}"

    def parse(self) -> Iterator[Tuple[int, bytes, int, Optional[Dict[str, int]]]]:
        with open(self.trace_file, "r") as f:
            lines = f.readlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()
            matched = None
            for pattern in self._INSTRUCTION_PATTERNS:
                matched = pattern.match(line)
                if matched:
                    break

            if not matched:
                i += 1
                continue

            if line.startswith("core"):
                core_id = int(matched.group(1))
                pc = int(matched.group(2), 16)
                instruction_bytes = self._to_instruction_bytes(matched.group(3))
            else:
                core_id = 0
                pc = int(matched.group(1), 16)
                instruction_bytes = self._to_instruction_bytes(matched.group(2))
            i += 1

            if instruction_bytes is None:
                continue

            registers: Dict[str, int] = {}
            while i < len(lines):
                reg_line = lines[i].strip()
                reg_match = self._REG_WRITE_PATTERN.match(reg_line)
                if not reg_match:
                    break
                reg_index = int(reg_match.group(1))
                reg_value = int(reg_match.group(2), 16)
                registers[self._normalize_reg_name(reg_index)] = reg_value
                i += 1

            reg_state = registers if registers else None
            yield (pc, instruction_bytes, core_id, reg_state)


class SpikeTraceImporter:
    """Import Spike commit traces into the instruction database."""

    def __init__(self, trace_file: str, db_path: str):
        self.parser = SpikeCommitLogParser(trace_file)
        self.db_path = db_path

    def import_trace(self, max_instructions: Optional[int] = None) -> int:
        from inst_db.api import InstructionDB

        db_url = self.db_path
        if not db_url.startswith("sqlite:"):
            db_url = f"sqlite:///{self.db_path}"

        db = InstructionDB(db_url, architecture="riscv64")

        count = 0
        sequence_id = 1

        with db.db_manager.get_session() as session:
            for pc, instruction_bytes, core_id, register_state in self.parser.parse():
                if max_instructions is not None and count >= max_instructions:
                    break

                try:
                    db.add_instruction(
                        virtual_pc=pc,
                        physical_pc=pc,
                        instruction_code=instruction_bytes,
                        sequence_id=sequence_id,
                        core_id=core_id,
                        register_state=register_state,
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

        if db.db_manager.use_in_memory:
            db.db_manager.save_to_file(self.db_path)
        print(f"Successfully imported {count} instructions")
        return count
