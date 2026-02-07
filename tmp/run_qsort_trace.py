#!/usr/bin/env python3
"""Build quicksort demo, run QEMU trace, and import into the database."""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP_DIR = ROOT / "tmp"
SRC_FILE = TMP_DIR / "qsort_demo.c"
BIN_FILE = TMP_DIR / "qsort_demo"
TRACE_FILE = TMP_DIR / "qsort_trace.log"
DB_FILE = TMP_DIR / "quicksort_trace.db"

sys.path.insert(0, str(ROOT / "src"))

from inst_db.parsers import TraceImporter
from inst_db.api import InstructionDB


def check_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required tool not found: {name}")


def build_binary() -> None:
    cmd = [
        "aarch64-linux-gnu-gcc",
        "-static",
        "-O0",
        str(SRC_FILE),
        "-o",
        str(BIN_FILE),
    ]
    subprocess.run(cmd, check=True)


def run_qemu_trace() -> None:
    cmd = [
        "qemu-aarch64-static",
        "-one-insn-per-tb",
        "-d",
        "in_asm,exec,cpu,nochain",
        "-D",
        str(TRACE_FILE),
        str(BIN_FILE),
    ]
    subprocess.run(cmd, check=True)


def import_trace() -> int:
    importer = TraceImporter(str(TRACE_FILE), str(DB_FILE))
    return importer.import_trace()


def print_stats() -> None:
    db = InstructionDB(f"sqlite:///{DB_FILE}")
    instructions = db.get_instruction_trace()

    print("\n=== Trace Statistics ===")
    print(f"Total instructions: {len(instructions)}")

    if instructions:
        pcs = [instr.pc for instr in instructions]
        print(f"PC range: {min(pcs):#x} - {max(pcs):#x}")
        unique_pcs = len(set(pcs))
        print(f"Unique PCs: {unique_pcs}")
        print(f"Avg executions per PC: {len(instructions) / unique_pcs:.2f}")

        print("\nFirst 10 instructions:")
        for instr in instructions[:10]:
            print(f"[{instr.sequence_id:4d}] {instr.pc:#018x}: {instr.disassembly}")


def main() -> int:
    check_tool("aarch64-linux-gnu-gcc")
    check_tool("qemu-aarch64-static")

    print("Building quicksort demo...")
    build_binary()

    print("Running QEMU trace...")
    run_qemu_trace()

    print("Importing trace into database...")
    if DB_FILE.exists():
        DB_FILE.unlink()
    count = import_trace()
    print(f"Imported {count} instructions.")

    print_stats()
    return 0


if __name__ == "__main__":
    sys.exit(main())
