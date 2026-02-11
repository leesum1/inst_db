#!/usr/bin/env python3
"""Build and run Spike trace for a no-pk RISC-V demo, then import into DB."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[2]
TMP_DIR = ROOT / "tmp"
SRC_DIR = Path(__file__).resolve().parent / "source"

sys.path.insert(0, str(ROOT / "src"))

DEMO: Dict[str, Any] = {
    "name": "RISC-V (no-pk)",
    "src_file": "riscv_demo_nopk.S",
    "bin_file": "riscv_demo_nopk.elf",
    "trace_file": "riscv_trace.log",
    "db_file": "riscv_trace.db",
    "compile_flags": ["-march=rv64gc", "-mabi=lp64d"],
    "linker_flags": ["-Wl,-Ttext=0x80000000"],
    "memory_map": "0x00010000:0x10000,0x80000000:0x100000",
    "isa": "RV64GC",
}


def pc_to_int(pc_value: str | int) -> int:
    if isinstance(pc_value, int):
        return pc_value
    text = pc_value.strip().lower()
    if text.startswith("0x"):
        return int(text, 16)
    return int(text, 16)


def check_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required tool not found: {name}")


def build_binary(config: Dict[str, Any]) -> None:
    src_file = SRC_DIR / config["src_file"]
    bin_file = TMP_DIR / config["bin_file"]

    if not src_file.exists():
        raise FileNotFoundError(f"Source file not found: {src_file}")

    cmd = [
        "riscv64-linux-gnu-gcc",
        "-nostdlib",
        "-nostartfiles",
        "-static",
        "-O0",
        *config["compile_flags"],
        *config["linker_flags"],
        str(src_file),
        "-o",
        str(bin_file),
    ]
    subprocess.run(cmd, check=True)


def run_spike_trace(config: Dict[str, Any], run_seconds: Optional[float]) -> None:
    bin_file = TMP_DIR / config["bin_file"]
    trace_file = TMP_DIR / config["trace_file"]

    cmd = [
        "spike",
        f"--isa={config['isa']}",
        f"-m{config['memory_map']}",
        "-l",
        f"--log={trace_file}",
        str(bin_file),
    ]

    if run_seconds is not None and run_seconds <= 0:
        run_seconds = None

    try:
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=run_seconds,
        )
    except subprocess.TimeoutExpired:
        seconds_text = f"{run_seconds:g}s" if run_seconds is not None else "timeout"
        print(
            f"Spike stopped by timeout after {seconds_text} (expected for loop demo)."
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        if stderr:
            print(stderr)
        raise


def import_trace(config: Dict[str, Any], max_instructions: Optional[int]) -> int:
    from inst_db.parsers import SpikeTraceImporter

    trace_file = TMP_DIR / config["trace_file"]
    db_file = TMP_DIR / config["db_file"]

    importer = SpikeTraceImporter(str(trace_file), str(db_file))
    return importer.import_trace(max_instructions=max_instructions)


def print_stats(config: Dict[str, Any]) -> None:
    from inst_db.api import InstructionDB

    db_file = TMP_DIR / config["db_file"]
    db = InstructionDB(f"sqlite:///{db_file}", architecture="riscv64")
    instructions = db.get_instruction_trace()

    print("\n=== Spike Trace Statistics ===")
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
    parser = argparse.ArgumentParser(
        description="Build and run Spike trace for a no-pk RISC-V demo."
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip building the ELF binary",
    )
    parser.add_argument(
        "--no-trace",
        action="store_true",
        help="Skip running Spike trace",
    )
    parser.add_argument(
        "--run-seconds",
        type=float,
        default=1.0,
        help="Spike run duration in seconds (<=0 means no timeout)",
    )
    parser.add_argument(
        "--no-import",
        action="store_true",
        help="Skip importing trace into database",
    )
    parser.add_argument(
        "--import-limit",
        type=int,
        default=50000,
        help="Maximum instructions imported from log (<=0 means no limit)",
    )
    parser.add_argument(
        "--no-stats",
        action="store_true",
        help="Skip printing statistics",
    )

    args = parser.parse_args()
    config = DEMO
    TMP_DIR.mkdir(parents=True, exist_ok=True)

    import_limit: Optional[int] = args.import_limit
    if import_limit is not None and import_limit <= 0:
        import_limit = None

    try:
        if not args.no_build:
            check_tool("riscv64-linux-gnu-gcc")
            print(f"Building {config['name']} demo...")
            build_binary(config)

        if not args.no_trace:
            check_tool("spike")
            print("Running Spike trace (no pk mode)...")
            run_spike_trace(config, run_seconds=args.run_seconds)

        if not args.no_import:
            print("Importing trace into database...")
            db_file = TMP_DIR / config["db_file"]
            if db_file.exists():
                db_file.unlink()
            count = import_trace(config, max_instructions=import_limit)
            print(f"Imported {count} instructions.")

        if not args.no_stats:
            print_stats(config)

        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
