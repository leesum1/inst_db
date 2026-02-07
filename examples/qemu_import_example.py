#!/usr/bin/env python3
"""Example of importing QEMU trace into instruction database."""

import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from inst_db.parsers import TraceImporter
from inst_db.api import InstructionDB


def main():
    """Import QEMU trace and display results."""
    
    # Example trace file path
    trace_file = "trace.log"
    db_file = "qemu_trace.db"
    
    # Check if trace file exists
    if not Path(trace_file).exists():
        print(f"Error: Trace file '{trace_file}' not found")
        print("\nTo generate a trace file, run:")
        print("  qemu-aarch64-static -d in_asm -D trace.log ./your_program")
        return 1
    
    print(f"Importing trace from: {trace_file}")
    print(f"Database: {db_file}\n")
    
    # Import trace
    importer = TraceImporter(trace_file, db_file)
    count = importer.import_trace()
    
    print(f"\n{'='*60}")
    print("Import completed!")
    print(f"{'='*60}\n")
    
    # Display first 20 instructions
    print("First 20 instructions:\n")
    db = InstructionDB(db_file)
    
    for instr in db.get_instruction_trace(limit=20):
        print(f"[{instr.sequence_id:4d}] {instr.pc:#018x}: {instr.disassembly}")
        
        # Show register dependencies
        deps = db.get_register_dependencies(instr.id)
        reads = [d.register_name for d in deps if d.is_src]
        writes = [d.register_name for d in deps if d.is_dst]
        
        if reads:
            print(f"       └─ Reads:  {', '.join(reads)}")
        if writes:
            print(f"       └─ Writes: {', '.join(writes)}")
        print()
    
    # Statistics
    print(f"\n{'='*60}")
    print("Statistics:")
    print(f"{'='*60}")
    
    all_instrs = db.get_instruction_trace()
    print(f"Total instructions: {len(all_instrs)}")
    
    if all_instrs:
        print(f"PC range: {all_instrs[0].pc:#x} - {all_instrs[-1].pc:#x}")
        
        # Count unique PCs
        unique_pcs = len(set(i.pc for i in all_instrs))
        print(f"Unique PCs: {unique_pcs}")
        print(f"Average executions per PC: {len(all_instrs) / unique_pcs:.2f}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
