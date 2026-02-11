#!/usr/bin/env python3
"""Build and run QEMU execlog traces, then import into the database."""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[2]
TMP_DIR = ROOT / "tmp"
SRC_DIR = Path(__file__).resolve().parent / "source"
QEMU_LOG_DIR = ROOT / "qemu_log"
QEMU_PLUGIN = QEMU_LOG_DIR / "libexeclog.so"

QEMU_BINS = {
    "arm64": QEMU_LOG_DIR / "qemu-aarch64",
    "riscv64": QEMU_LOG_DIR / "qemu-riscv64",
}

sys.path.insert(0, str(ROOT / "src"))


# Demo configurations
DEMOS = {
    "qsort": {
        "name": "Quicksort",
        "architecture": "arm64",
        "src_file": "qsort_demo.c",
        "bin_file": "qsort_demo",
        "trace_file": "qsort_execlog.log",
        "db_file": "quicksort_trace.db",
        "compiler": "aarch64-linux-gnu-gcc",
        "compile_flags": [],
        "qemu_flags": [],
    },
    "sve": {
        "name": "SVE",
        "architecture": "arm64",
        "src_file": "sve_demo.c",
        "bin_file": "sve_demo",
        "trace_file": "sve_execlog.log",
        "db_file": "sve_trace.db",
        "compiler": "aarch64-linux-gnu-gcc",
        "compile_flags": ["-march=armv8.2-a+sve"],
        "qemu_flags": ["-cpu", "max,sve=on"],
    },
    "riscv_min": {
        "name": "RISC-V Minimal",
        "architecture": "riscv64",
        "src_file": "riscv_min_demo.c",
        "bin_file": "riscv_min_demo",
        "trace_file": "riscv_min_execlog.log",
        "db_file": "riscv_min_trace.db",
        "compiler": "riscv64-linux-gnu-gcc",
        "compile_flags": ["-march=rv64gc", "-mabi=lp64d"],
        "qemu_flags": [],
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


def check_executable(path: Path) -> None:
    """Check if a local executable file exists and is runnable."""
    if not path.exists():
        raise FileNotFoundError(f"Required executable not found: {path}")
    if not os.access(path, os.X_OK):
        raise RuntimeError(f"File is not executable: {path}")


def build_binary(config: Dict[str, Any]) -> None:
    """Build the binary from source."""
    src_file = SRC_DIR / config["src_file"]
    bin_file = TMP_DIR / config["bin_file"]

    if not src_file.exists():
        raise FileNotFoundError(f"Source file not found: {src_file}")

    cmd = [
        config["compiler"],
        "-static",
        "-O0",
    ]

    # Add demo-specific compile flags
    cmd.extend(config["compile_flags"])

    cmd.extend(
        [
            str(src_file),
            "-o",
            str(bin_file),
        ]
    )

    subprocess.run(cmd, check=True)


def run_qemu_trace(config: Dict[str, Any]) -> None:
    """Run QEMU execlog trace on the binary."""
    bin_file = TMP_DIR / config["bin_file"]
    trace_file = TMP_DIR / config["trace_file"]
    qemu_bin = QEMU_BINS[config["architecture"]]

    cmd = [str(qemu_bin)]

    # Add demo-specific QEMU flags
    cmd.extend(config["qemu_flags"])

    cmd.extend(
        [
            "-d",
            "plugin",
            "-D",
            str(trace_file),
            "-plugin",
            str(QEMU_PLUGIN),
            str(bin_file),
        ]
    )

    subprocess.run(cmd, check=True)


def import_trace(config: Dict[str, Any]) -> int:
    """Import the trace into the database."""
    from inst_db.parsers import TraceImporter

    trace_file = TMP_DIR / config["trace_file"]
    db_file = TMP_DIR / config["db_file"]

    importer = TraceImporter(
        str(trace_file),
        str(db_file),
        architecture=config["architecture"],
    )
    return importer.import_trace()


def print_stats(config: Dict[str, Any]) -> None:
    """Print trace statistics."""
    from inst_db.api import InstructionDB

    db_file = TMP_DIR / config["db_file"]
    db = InstructionDB(f"sqlite:///{db_file}", architecture=config["architecture"])
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
        description="Build and run QEMU execlog traces for ARM64/RISC-V demos."
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
    TMP_DIR.mkdir(parents=True, exist_ok=True)

    try:
        if not args.no_build:
            check_tool(config["compiler"])
            print(f"Building {config['name']} demo...")
            build_binary(config)

        if not args.no_trace:
            check_executable(QEMU_BINS[config["architecture"]])
            if not QEMU_PLUGIN.exists():
                raise FileNotFoundError(f"QEMU plugin not found: {QEMU_PLUGIN}")

            print("Running QEMU execlog trace...")
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
