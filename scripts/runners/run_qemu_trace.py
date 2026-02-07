#!/usr/bin/env python3
"""Build and run QEMU trace for ARM64 demos, then import into the database."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any

ROOT = Path(__file__).resolve().parents[2]
TMP_DIR = ROOT / "tmp"
SRC_DIR = Path(__file__).resolve().parent / "source"

sys.path.insert(0, str(ROOT / "src"))


# Demo configurations
DEMOS = {
    "qsort": {
        "name": "Quicksort",
        "src_file": "qsort_demo.c",
        "bin_file": "qsort_demo",
        "trace_file": "qsort_trace.log",
        "db_file": "quicksort_trace.db",
        "compile_flags": [],
        "qemu_flags": [],
    },
    "sve": {
        "name": "SVE",
        "src_file": "sve_demo.c",
        "bin_file": "sve_demo",
        "trace_file": "sve_trace.log",
        "db_file": "sve_trace.db",
        "compile_flags": ["-march=armv8.2-a+sve"],
        "qemu_flags": ["-cpu", "max,sve=on"],
    },
}


def pc_to_int(pc_value: str | int) -> int:
    """Convert PC value to integer."""
    if isinstance(pc_value, int):
        return pc_value
    text = pc_value.strip().lower()
    if text.startswith("0x"):
        return int(text, 16)
    return int(text, 16)


def check_tool(name: str) -> None:
    """Check if a tool is available."""
    if shutil.which(name) is None:
        raise RuntimeError(f"Required tool not found: {name}")


def build_binary(config: Dict[str, Any]) -> None:
    """Build the binary from source."""
    src_file = SRC_DIR / config["src_file"]
    bin_file = TMP_DIR / config["bin_file"]

    if not src_file.exists():
        raise FileNotFoundError(f"Source file not found: {src_file}")

    cmd = [
        "aarch64-linux-gnu-gcc",
        "-static",
        "-O0",
    ]
    
    # Add demo-specific compile flags
    cmd.extend(config["compile_flags"])
    
    cmd.extend([
        str(src_file),
        "-o",
        str(bin_file),
    ])
    
    subprocess.run(cmd, check=True)


def run_qemu_trace(config: Dict[str, Any]) -> None:
    """Run QEMU trace on the binary."""
    bin_file = TMP_DIR / config["bin_file"]
    trace_file = TMP_DIR / config["trace_file"]

    cmd = ["qemu-aarch64-static"]
    
    # Add demo-specific QEMU flags
    cmd.extend(config["qemu_flags"])
    
    cmd.extend([
        "-one-insn-per-tb",
        "-d",
        "in_asm,exec,cpu,nochain",
        "-D",
        str(trace_file),
        str(bin_file),
    ])
    
    subprocess.run(cmd, check=True)


def import_trace(config: Dict[str, Any]) -> int:
    """Import the trace into the database."""
    from inst_db.parsers import TraceImporter
    
    trace_file = TMP_DIR / config["trace_file"]
    db_file = TMP_DIR / config["db_file"]

    importer = TraceImporter(str(trace_file), str(db_file))
    return importer.import_trace()


def print_stats(config: Dict[str, Any]) -> None:
    """Print trace statistics."""
    from inst_db.api import InstructionDB
    
    db_file = TMP_DIR / config["db_file"]
    db = InstructionDB(f"sqlite:///{db_file}")
    instructions = db.get_instruction_trace()

    print("\n=== Trace Statistics ===")
    print(f"Total instructions: {len(instructions)}")

    if instructions:
        pcs = [pc_to_int(instr.pc) for instr in instructions]
        print(f"PC range: {min(pcs):#x} - {max(pcs):#x}")
        unique_pcs = len(set(pcs))
        print(f"Unique PCs: {unique_pcs}")
        print(f"Avg executions per PC: {len(instructions) / unique_pcs:.2f}")

        print("\nFirst 10 instructions:")
        for instr in instructions[:10]:
            pc_int = pc_to_int(instr.pc)
            print(f"[{instr.sequence_id:4d}] {pc_int:#018x}: {instr.disassembly}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Build and run QEMU trace for ARM64 demos."
    )
    parser.add_argument(
        "demo",
        choices=list(DEMOS.keys()),
        help=f"Demo to run ({', '.join(DEMOS.keys())})",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip building the binary",
    )
    parser.add_argument(
        "--no-trace",
        action="store_true",
        help="Skip running QEMU trace",
    )
    parser.add_argument(
        "--no-import",
        action="store_true",
        help="Skip importing trace into database",
    )
    parser.add_argument(
        "--no-stats",
        action="store_true",
        help="Skip printing statistics",
    )

    args = parser.parse_args()
    config = DEMOS[args.demo]

    try:
        check_tool("aarch64-linux-gnu-gcc")
        check_tool("qemu-aarch64-static")

        if not args.no_build:
            print(f"Building {config['name']} demo...")
            build_binary(config)

        if not args.no_trace:
            print("Running QEMU trace...")
            run_qemu_trace(config)

        if not args.no_import:
            print("Importing trace into database...")
            db_file = TMP_DIR / config["db_file"]
            if db_file.exists():
                db_file.unlink()
            count = import_trace(config)
            print(f"Imported {count} instructions.")

        if not args.no_stats:
            print_stats(config)

        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
